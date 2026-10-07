import copy
import hashlib
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from eval_receipts import core
from eval_receipts.cli import verify_local
from eval_receipts.timestamp import deserialize, serialize, verify_timestamp
from eval_receipts.transport import registry_url


class Commitments(unittest.TestCase):
    def setUp(self):
        self.items = [core.item_record({'id':str(i),'input':f'public-{i}','output':str(i),'score':v},i)
                      for i,v in enumerate(['0.1','0.2','0.3','0.4','0.5'])]
        self.salts = ['00'*31+f'{i:02x}' for i in range(len(self.items))]
        self.levels = core.tree([core.leaf(v,s,i) for i,(v,s) in enumerate(zip(self.items,self.salts))])
    def test_every_position_with_odd_tree_and_single_leaf(self):
        for n in (1,2,3,4,5):
            items=self.items[:n]; salts=self.salts[:n]
            levels=core.tree([core.leaf(v,s,i) for i,(v,s) in enumerate(zip(items,salts))])
            for i in range(n):
                core.verify_inclusion(items[i],salts[i],i,n,core.inclusion(levels,i),levels[-1][0].hex())
    def test_tampered_content_score_salt_position_and_proof(self):
        i=4; root=self.levels[-1][0].hex(); proof=core.inclusion(self.levels,i)
        for field,value in [('input','tampered'),('output','tampered'),('score','0.9'),('id','other')]:
            bad=dict(self.items[i],**{field:value})
            with self.assertRaises(core.InvalidReceipt): core.verify_inclusion(bad,self.salts[i],i,5,proof,root)
        for salt,pos,steps in [('ff'*32,i,proof),(self.salts[i],3,proof),(self.salts[i],i,proof[:-1]),
                              (self.salts[i],i,proof+[proof[0]])]:
            with self.assertRaises(core.InvalidReceipt): core.verify_inclusion(self.items[i],salt,pos,5,steps,root)
        bad=copy.deepcopy(proof);bad[0]['side']='left'
        with self.assertRaises(core.InvalidReceipt):core.verify_inclusion(self.items[i],self.salts[i],i,5,bad,root)
        bad=copy.deepcopy(proof);bad[0]['hash']='ff'*32
        with self.assertRaises(core.InvalidReceipt):core.verify_inclusion(self.items[i],self.salts[i],i,5,bad,root)
    def test_random_salts_change_root(self):
        alternate=core.tree([core.leaf(v,'ff'*32,i) for i,v in enumerate(self.items)])
        self.assertNotEqual(self.levels[-1][0],alternate[-1][0])
    def test_decimal_aggregate_and_opt_in_cost(self):
        s=core.summary(self.items[:2]);self.assertEqual(s['score_sum'],'0.3');self.assertEqual(s['aggregate_score'],'0.15')
        items=[dict(self.items[0],cost='0.1'),dict(self.items[1],cost='0.2')]
        self.assertIsNone(core.summary(items)['cost_total_usd'])
        self.assertEqual(core.summary(items,share_cost=True)['cost_total_usd'],'0.3')
    def test_unsafe_numbers_duplicate_json_and_unknown_fields_rejected(self):
        for v in [True,'NaN','Infinity','-Infinity','1e-13','1e19']:
            with self.assertRaises(core.InvalidReceipt):core.decimal_text(v)
        for data in ['{"score":1,"score":2}', '{"a":NaN}']:
            with self.assertRaises(core.InvalidReceipt):core.strict_json(data)
        with self.assertRaises(core.InvalidReceipt):core.item_record(dict(self.items[0],customer_data='secret'),0)
        with self.assertRaises(core.InvalidReceipt):core.tree([])
    def test_suite_binds_order_inputs_and_ids(self):
        a=core.suite_hash(self.items,'00'*32)
        self.assertEqual(a,core.suite_hash([dict(v,output='new',score='1') for v in self.items],'00'*32))
        self.assertNotEqual(a,core.suite_hash(list(reversed(self.items)),'00'*32))
        self.assertNotEqual(a,core.suite_hash(self.items,'01'*32))
    def test_names_cannot_contradict_overrides(self):
        with self.assertRaises(core.InvalidReceipt):core.summary([dict(self.items[0],model='one')],model='two')
    def test_transport_refuses_remote_http_credentials_and_query(self):
        for value in ['http://example.com','https://u:p@example.com','https://example.com?token=secret','https://example.com/other']:
            with self.assertRaises(core.InvalidReceipt):registry_url(value)
        self.assertEqual(registry_url('http://127.0.0.1:4318'),'http://127.0.0.1:4318')
        self.assertEqual(registry_url('https://example.com/eval/'),'https://example.com/eval')


class LocalCLI(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.root=Path(self.tmp.name)
        self.file=self.root/'results.jsonl'
        self.rows=[{'id':'x','input':'LOCAL_ONLY_INPUT_CANARY','output':'LOCAL_ONLY_OUTPUT_CANARY','score':1,'model':'demo','grader':'exact','cost':'0.25'},
                   {'id':'y','input':'other','output':'other','score':0,'model':'demo','grader':'exact','cost':'0.5'}]
        self.file.write_text(''.join(json.dumps(v)+'\n' for v in self.rows))
    def tearDown(self):self.tmp.cleanup()
    def cli(self,*args):
        return subprocess.run([sys.executable,'-m','eval_receipts','--state-dir',str(self.root/'state'),*args],
                              text=True,capture_output=True,env={k:v for k,v in os.environ.items() if not k.startswith('RECEIPT_')})
    def build(self):
        p=self.cli('eval',str(self.file),'--offline','--demo','--out',str(self.root/'receipt'))
        self.assertEqual(p.returncode,0,p.stderr)
        return self.root/'receipt/receipt.json'
    def test_roundtrip_and_single_revealed_item(self):
        receipt=self.build()
        p=self.cli('verify',str(receipt),'--offline');self.assertEqual(p.returncode,0,p.stderr)
        self.assertEqual(json.loads(p.stdout)['ledger'],'unchecked')
        p=self.cli('reveal',str(receipt),'--item','x','--out',str(self.root/'item.json'));self.assertEqual(p.returncode,0,p.stderr)
        p=self.cli('verify-item',str(self.root/'item.json'),'--receipt',str(receipt));self.assertEqual(p.returncode,0,p.stderr)
        r=json.loads((self.root/'item.json').read_text());r['item']['score']='0'
        (self.root/'item.json').write_text(json.dumps(r))
        self.assertEqual(self.cli('verify-item',str(self.root/'item.json'),'--receipt',str(receipt)).returncode,1)
    def test_summary_score_tamper_and_private_item_tamper(self):
        receipt=self.build();value=json.loads(receipt.read_text());original=copy.deepcopy(value)
        value['payload']['summary']['score_sum']='0.8';value['payload']['summary']['aggregate_score']='0.4'
        receipt.write_text(json.dumps(value))
        self.assertEqual(self.cli('verify',str(receipt),'--offline').returncode,1)
        receipt.write_text(json.dumps(original))
        records=[json.loads(l) for l in (receipt.parent/'items.jsonl').read_text().splitlines()]
        records[0]['item']['score']='0'
        (receipt.parent/'items.jsonl').write_text(''.join(json.dumps(v)+'\n' for v in records))
        self.assertEqual(self.cli('verify',str(receipt),'--offline').returncode,1)
    def test_proof_tamper_rejected(self):
        receipt=self.build();p=receipt.parent/'proofs.jsonl';r=[json.loads(l) for l in p.read_text().splitlines()]
        r[0]['siblings'][0]['hash']='ff'*32;p.write_text(''.join(json.dumps(v)+'\n' for v in r))
        self.assertEqual(self.cli('verify',str(receipt),'--offline').returncode,1)
    def test_payload_dump_has_no_content_identifiers_salts_or_default_cost(self):
        receipt=self.build();value=json.loads(receipt.read_text());payload=(receipt.parent/'payload.json').read_text()
        self.assertNotIn('LOCAL_ONLY_',payload);self.assertNotIn('"id"',payload);self.assertNotIn('salt',payload)
        for record in (receipt.parent/'items.jsonl').read_text().splitlines():
            self.assertNotIn(json.loads(record)['salt'],payload)
        self.assertIsNone(value['payload']['summary']['cost_total_usd'])
        self.assertEqual((receipt.parent/'items.jsonl').stat().st_mode&0o777,0o600)
    def test_csv_roundtrip_and_duplicate_headers_rejected(self):
        p=self.root/'results.csv';p.write_text('item_id,input,output,score\na,public,ok,0.1\nb,public,ok,0.2\n')
        response=self.cli('eval',str(p),'--offline','--demo','--out',str(self.root/'csv-out'))
        self.assertEqual(response.returncode,0,response.stderr)
        self.assertEqual(self.cli('verify',str(self.root/'csv-out/receipt.json'),'--offline').returncode,0)
        p.write_text('id,input,output,score,score\na,x,y,1,0\n')
        self.assertEqual(self.cli('eval',str(p),'--offline').returncode,1)
    def test_existing_output_preserved_and_duplicate_ids_rejected(self):
        receipt=self.build();original=receipt.read_bytes()
        self.assertEqual(self.cli('eval',str(self.file),'--offline','--out',str(receipt.parent)).returncode,1)
        self.assertEqual(original,receipt.read_bytes())
        self.file.write_text(''.join(json.dumps(self.rows[0])+'\n' for _ in range(2)))
        self.assertEqual(self.cli('eval',str(self.file),'--offline').returncode,1)
    def test_path_traversal_and_symlink_refused(self):
        receipt=self.build();value=json.loads(receipt.read_text());value['local']['items_file']='../results.jsonl'
        with self.assertRaises(core.InvalidReceipt):verify_local(receipt,value)
        value=json.loads(receipt.read_text());p=receipt.parent/'items.jsonl';p.unlink();p.symlink_to(self.file)
        with self.assertRaises(core.InvalidReceipt):verify_local(receipt,value)
    def test_unregistered_online_and_offline_confirmed_cannot_pass(self):
        receipt=self.build()
        self.assertEqual(self.cli('verify',str(receipt)).returncode,1)
        self.assertEqual(self.cli('verify',str(receipt),'--offline','--require-confirmed').returncode,1)


class TimestampBinding(unittest.TestCase):
    def proof(self):
        import io
        from opentimestamps.core.op import OpSHA256
        from opentimestamps.core.timestamp import DetachedTimestampFile
        from opentimestamps.core.notary import PendingAttestation
        root='ab'*32
        proof=DetachedTimestampFile.from_fd(OpSHA256(),io.BytesIO(bytes.fromhex(root)))
        proof.timestamp.attestations.add(PendingAttestation('https://a.pool.opentimestamps.org'))
        return root,proof
    def test_pending_never_claims_bitcoin_confirmation(self):
        root,p=self.proof();r=verify_timestamp(serialize(p),root,False)
        self.assertEqual(r['status'],'pending');self.assertFalse(r['bitcoin_verified'])
    def test_official_pool_response_calendar_aliases(self):
        from opentimestamps.core.notary import PendingAttestation
        root,p=self.proof();p.timestamp.attestations.clear()
        p.timestamp.attestations.add(PendingAttestation('https://alice.btc.calendar.opentimestamps.org'))
        p.timestamp.attestations.add(PendingAttestation('https://bob.btc.calendar.opentimestamps.org'))
        self.assertEqual(verify_timestamp(serialize(p),root,False)['status'],'pending')
    def test_changed_root_and_trailing_proof_rejected(self):
        root,p=self.proof()
        with self.assertRaises(core.InvalidReceipt):deserialize(serialize(p),'cd'*32)
        with self.assertRaises(core.InvalidReceipt):deserialize(serialize(p)+b'evil',root)
    def test_forged_bitcoin_attestation_is_not_confirmation(self):
        from opentimestamps.core.notary import BitcoinBlockHeaderAttestation
        root,p=self.proof();p.timestamp.attestations.add(BitcoinBlockHeaderAttestation(1))
        with patch('eval_receipts.timestamp.request',return_value=b'00'*32):
            with self.assertRaises(core.InvalidReceipt):verify_timestamp(serialize(p),root)


if __name__=='__main__':unittest.main()
