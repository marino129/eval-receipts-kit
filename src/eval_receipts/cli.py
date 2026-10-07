"""receipt eval, seed, publish, verify and local single-item disclosure."""
import argparse
import base64
import getpass
import json
import os
import secrets
import sys
import time
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from . import __version__
from .core import (SCHEMA, InvalidReceipt, canonical, hash_hex, inclusion, item_record,
                   leaf, name, now, read_items, read_suite, replace_private, require,
                   save_json, sha, strict_json, suite_hash, summary, tree,
                   validate_payload, verify_chain, verify_inclusion, write_private, MAX_ITEMS)
from .transport import api, registry_url


def state_dir(args):
    return Path(args.state_dir or os.environ.get("RECEIPT_STATE_DIR", str(Path.home() / ".config/eval-receipts")))


def settings(args):
    p = state_dir(args) / "connection.json"
    result = strict_json(p.read_bytes()) if p.exists() else {}
    base = args.registry or os.environ.get("RECEIPT_REGISTRY") or result.get("registry")
    token = os.environ.get("RECEIPT_TOKEN") or result.get("token")
    return (registry_url(base) if base else None), token


def suite_salt(args):
    directory = state_dir(args)
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    p = directory / "suite-salt"
    try:
        write_private(p, secrets.token_hex(32).encode())
    except FileExistsError:
        pass
    return hash_hex(p.read_text())


def local_child(receipt_path, filename):
    require(isinstance(filename, str) and Path(filename).name == filename and filename not in ("", ".", ".."),
            "Local artifact path must be a filename beside receipt.json")
    p = receipt_path.parent / filename
    require(not p.is_symlink(), "Local artifacts cannot be symlinks")
    return p


def output_dir(args, prefix):
    p = Path(args.out or (prefix + "-" + uuid.uuid4().hex[:12]))
    p.mkdir(parents=True, exist_ok=False, mode=0o700)
    return p


def login(args):
    base = registry_url(args.url)
    token = os.environ.get("RECEIPT_TOKEN") or getpass.getpass("Private registry key (hidden): ")
    response = api(base, "/api/health", token=token)
    require(response.get("segment") == "eval-receipts-v1", "Unexpected registry")
    p = state_dir(args) / "connection.json"
    p.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    replace_private(p, canonical({"registry": base, "token": token}) + b"\n")
    print("Private registry connected. Ready: receipt eval results.jsonl")


def config_commit(args, salt=None):
    salt = salt or secrets.token_hex(32)
    config = strict_json(Path(args.config).read_bytes()) if args.config else {}
    digest = sha(b"creationloop.eval.config.v1\0" + bytes.fromhex(hash_hex(salt)) + canonical(config))
    return digest, salt


def fingerprints(args):
    result = {}
    for value in getattr(args, "weights_fingerprint", None) or []:
        model, separator, digest = value.rpartition("=")
        require(separator and model and model not in result, "Use one MODEL=SHA256 fingerprint per model")
        result[name(model)] = hash_hex(digest)
    return dict(sorted(result.items()))


def metadata(args):
    result = {"created_at": now(), "demo": args.demo, "tool_version": __version__,
              "benchmark_hash": hash_hex(args.benchmark_hash) if args.benchmark_hash else None}
    values = fingerprints(args)
    if values: result["model_fingerprints"] = values
    return result


def seed(args):
    base, token = settings(args)
    require(base, "Connect first: receipt login PRIVATE_REGISTRY_URL")
    s = suite_salt(args)
    config_hash, config_salt = config_commit(args)
    run_id = uuid.uuid4().hex
    payload = {"schema": SCHEMA, "kind": "seed", "run_id": run_id,
               "suite_hash": suite_hash(read_suite(args.suite), s), "models": [name(args.model)],
               "graders": [name(args.grader)], "config_hash": config_hash,
               "run_metadata": metadata(args),
               "expires_at": (datetime.now(timezone.utc) + timedelta(hours=args.expires_hours)).isoformat(timespec="seconds")}
    validate_payload(payload, "seed")
    out = output_dir(args, "seed")
    value = {"schema": SCHEMA, "payload": payload, "suite_salt": s,
             "config_salt": config_salt, "registry": base, "registration": None}
    save_json(out / "payload.json", payload)
    save_json(out / "seed.json", value)
    # Seed artifacts survive a timeout; retry this exact payload, never allocate a new id.
    response = api(base, "/api/seed", data=payload, token=token)
    value["registration"] = response
    replace_private(out / "seed.json", canonical(value) + b"\n")
    print(json.dumps({"seed_file": str(out / "seed.json"), "receipt_url": response["receipt_url"],
                      "run_number": response["run_number"], "status": "seeded"}))


def seed_retry(args):
    p = Path(args.seed_file)
    value = strict_json(p.read_bytes())
    base, token = settings(args)
    require(base == value["registry"], "Select the same private registry used for the seed")
    validate_payload(value["payload"], "seed")
    response = api(base, "/api/seed", data=value["payload"], token=token)
    value["registration"] = response
    replace_private(p, canonical(value) + b"\n")
    print(json.dumps(response))


def build(args):
    started = time.perf_counter()
    base, token = settings(args)
    require(args.offline or base, "Connect first: receipt login PRIVATE_REGISTRY_URL (or choose --offline)")
    items, seen = [], set()
    for item in read_items(args.results):
        require(item["id"] not in seen, "Duplicate item id")
        seen.add(item["id"])
        items.append(item)
        require(len(items) <= MAX_ITEMS, "Run exceeds one million items")
    require(items, "Results file is empty")
    total = summary(items, args.model, args.grader, args.share_cost)
    salted_suite = suite_salt(args)
    config_hash, config_salt = config_commit(args)
    run_id, seed_id = uuid.uuid4().hex, None
    if args.seed_file:
        seeded = strict_json(Path(args.seed_file).read_bytes())
        validate_payload(seeded["payload"], "seed")
        seed_payload = seeded["payload"]
        require(base == seeded["registry"], "Seed and run must use the same private registry")
        salted_suite = seeded["suite_salt"]
        config_hash, config_salt = config_commit(args, seeded["config_salt"])
        require(config_hash == seed_payload["config_hash"], "Configuration differs from seed")
        require(total["models"] == seed_payload["models"] and total["graders"] == seed_payload["graders"],
                "Model or grader differs from seed")
        require(args.demo == seed_payload["run_metadata"]["demo"] and
                (args.benchmark_hash or None) == seed_payload["run_metadata"]["benchmark_hash"], "Run labeling differs from seed")
        require(fingerprints(args) == seed_payload["run_metadata"].get("model_fingerprints", {}),
                "Model weights fingerprint differs from seed")
        run_id = seed_id = seed_payload["run_id"]
    suite = suite_hash(items, salted_suite)
    if args.seed_file:
        require(suite == seed_payload["suite_hash"], "Suite differs from seed")
    salts = [secrets.token_hex(32) for _ in items]
    levels = tree([leaf(item, salt, i) for i, (item, salt) in enumerate(zip(items, salts))])
    root = levels[-1][0].hex()
    run_metadata = metadata(args)
    if args.seed_file:
        run_metadata["tool_version"] = seed_payload["run_metadata"]["tool_version"]
    payload = {"schema": SCHEMA, "kind": "settle", "run_id": run_id, "suite_hash": suite,
               "config_hash": config_hash, "models": total["models"], "graders": total["graders"],
               "run_metadata": run_metadata, "root": root, "summary": total, "seed_id": seed_id}
    validate_payload(payload)
    out = output_dir(args, "receipt")
    with (out / "items.jsonl").open("xb") as f, (out / "proofs.jsonl").open("xb") as g:
        os.chmod(f.name, 0o600)
        os.chmod(g.name, 0o600)
        for i, (item, salt) in enumerate(zip(items, salts)):
            f.write(canonical({"index": i, "item": item, "salt": salt}) + b"\n")
            g.write(canonical({"index": i, "siblings": inclusion(levels, i)}) + b"\n")
        f.flush(); g.flush(); os.fsync(f.fileno()); os.fsync(g.fileno())
    save_json(out / "payload.json", payload)
    write_private(out / "root.bin", bytes.fromhex(root))
    value = {"schema": SCHEMA, "payload": payload, "registry": base, "registration": None,
             "local": {"items_file": "items.jsonl", "proofs_file": "proofs.jsonl", "suite_salt": salted_suite,
                       "config_salt": config_salt, "model_override": args.model, "grader_override": args.grader}}
    if fingerprints(args): value["local"]["model_fingerprints"] = fingerprints(args)
    path = out / "receipt.json"
    save_json(path, value)
    processing_seconds = time.perf_counter() - started
    if not args.offline:
        submit(path, value, base, token)
    print(json.dumps({"receipt_file": str(path), "receipt_url": (value["registration"] or {}).get("receipt_url"),
                      "root": root, "item_count": len(items), "processing_seconds": round(processing_seconds, 3),
                      "anchor_status": (value["registration"] or {}).get("anchor", {}).get("status", "not_submitted"),
                      "demo": args.demo}))


def submit(path, value, base, token):
    validate_payload(value["payload"])
    require(base and base == value["registry"], "Choose the same registry as receipt.json")
    response = api(base, "/api/settle", data=value["payload"], token=token)
    value["registration"] = response
    replace_private(path, canonical(value) + b"\n")
    cache_proof(path, response)
    return response


def cache_proof(path, response):
    data = response.get("anchor", {}).get("proof_base64")
    if data:
        proof = base64.b64decode(data, validate=True)
        from .timestamp import deserialize
        deserialize(proof, response["root"])
        replace_private(path.parent / "root.bin.ots", proof)


def publish(args):
    path = Path(args.receipt)
    value = strict_json(path.read_bytes())
    verify_local(path, value)
    base, token = settings(args)
    # Offline packets may opt into this explicitly chosen registry on first publication.
    if value["registry"] is None:
        value["registry"] = base
        replace_private(path, canonical(value) + b"\n")
    response = submit(path, value, base, token)
    print(json.dumps({"receipt_url": response["receipt_url"], "anchor_status": response["anchor"]["status"]}))


def verify_local(path, value):
    require(value["schema"] == SCHEMA, "Unsupported receipt")
    p, loc = value["payload"], value["local"]
    validate_payload(p)
    require(loc.get("model_fingerprints", {}) == p["run_metadata"].get("model_fingerprints", {}),
            "Local model weights fingerprint differs from receipt")
    items, hashes, ids = [], [], set()
    with local_child(path, loc["items_file"]).open() as f:
        for index, line in enumerate(f):
            record = strict_json(line)
            require(set(record) == {"index", "item", "salt"} and type(record["index"]) is int and record["index"] == index,
                    "Local item sequence mismatch")
            item = item_record(record["item"], index)
            require(item["id"] not in ids, "Duplicate local item id")
            ids.add(item["id"])
            items.append(item)
            hashes.append(leaf(item, record["salt"], index))
            require(len(items) <= MAX_ITEMS, "Local bundle exceeds item bound")
    require(len(items) == p["summary"]["item_count"], "Item count mismatch")
    levels = tree(hashes)
    require(levels[-1][0].hex() == p["root"], "Recomputed Merkle root mismatch (item or score tampered)")
    require(summary(items, loc["model_override"], loc["grader_override"], p["summary"]["cost_total_usd"] is not None) == p["summary"],
            "Recomputed aggregate, model, grader or cost mismatch")
    require(suite_hash(items, loc["suite_salt"]) == p["suite_hash"], "Suite commitment mismatch")
    proofs = 0
    with local_child(path, loc["proofs_file"]).open() as f:
        for index, line in enumerate(f):
            proof = strict_json(line)
            require(set(proof) == {"index", "siblings"} and type(proof["index"]) is int and proof["index"] == index and index < len(items),
                    "Proof sequence mismatch")
            require(proof["siblings"] == inclusion(levels, index), "Inclusion proof differs from committed item tree")
            proofs += 1
    require(proofs == len(items), "Inclusion proof count mismatch")
    return {"root": "pass", "aggregate": "pass", "item_count": len(items)}


def verify(args):
    path = Path(args.receipt)
    value = strict_json(path.read_bytes())
    report = verify_local(path, value)
    report.update({"demo": value["payload"]["run_metadata"]["demo"], "ledger": "unchecked", "timestamp": "unchecked"})
    if not args.offline:
        base, token = settings(args)
        require(base and base == value["registry"], "Connect to the receipt's private registry before online verification")
        reg = value["registration"]
        require(reg and reg.get("entry_hash"), "Receipt has no ledger registration; receipt publish first")
        current = api(base, "/api/runs/" + value["payload"]["run_id"], token=token)
        chain = api(base, "/api/ledger/" + current["entry_hash"], token=token)
        entry = verify_chain(chain["entries"], reg["entry_hash"])
        require(entry["event"] == "settle" and entry["payload"] == value["payload"], "Ledger payload differs from receipt")
        from .core import series_id
        require(entry["run_id"] == value["payload"]["run_id"] and entry["series_id"] == series_id(value["payload"]) and
                entry["run_number"] == reg["run_number"] and reg["series_id"] == entry["series_id"], "Ledger run identity mismatch")
        if value["payload"]["seed_id"]:
            seeds = [e for e in chain["entries"] if e["run_id"] == entry["run_id"] and e["event"] == "seed"]
            require(len(seeds) == 1 and seeds[0]["sequence"] < entry["sequence"], "Missing or unordered pre-registration")
            seed_payload = seeds[0]["payload"]
            validate_payload(seed_payload, "seed")
            require(all(seed_payload[k] == value["payload"][k] for k in ("suite_hash", "models", "graders", "config_hash")),
                    "Pre-registration differs from settled run")
            require(seed_payload["run_metadata"].get("model_fingerprints", {}) ==
                    value["payload"]["run_metadata"].get("model_fingerprints", {}),
                    "Pre-registration model weights fingerprint differs from settled run")
        require(current["entry_hash"] == reg["entry_hash"] and current["root"] == value["payload"]["root"] and
                current["run_number"] == reg["run_number"] and current["series_id"] == reg["series_id"], "Registry identity mismatch")
        report["ledger"] = "pass"
        if value["payload"]["run_metadata"].get("model_fingerprints"):
            report["model_fingerprints"] = value["payload"]["run_metadata"]["model_fingerprints"]
        from .timestamp import verify_timestamp
        data = current["anchor"].get("proof_base64")
        require(data, "No timestamp proof yet; retry verification later")
        report["timestamp"] = verify_timestamp(base64.b64decode(data, validate=True), value["payload"]["root"])
        require(current["anchor"]["status"] == report["timestamp"]["status"], "Registry timestamp status differs from verification")
        if args.require_confirmed:
            require(report["timestamp"]["bitcoin_verified"], "Bitcoin anchor is pending")
        cache_proof(path, current)
        report["run"] = f"run {current['run_number']} of {current['series_total']}"
    else:
        require(not args.require_confirmed, "--require-confirmed requires online verification")
        report["scope"] = "local only; ledger and timestamp unchecked"
    print(json.dumps({"verified": True, **report}))


def reveal(args):
    path = Path(args.receipt)
    value = strict_json(path.read_bytes())
    verify_local(path, value)
    found, index = None, None
    with local_child(path, value["local"]["items_file"]).open() as f:
        for line in f:
            record = strict_json(line)
            if str(record["item"]["id"]) == args.item:
                found, index = record, record["index"]
                break
    require(found is not None, "Item id not found")
    with local_child(path, value["local"]["proofs_file"]).open() as f:
        for line in f:
            proof = strict_json(line)
            if proof["index"] == index:
                break
    result = {"schema": SCHEMA, "root": value["payload"]["root"], "item_count": value["payload"]["summary"]["item_count"],
              **found, "siblings": proof["siblings"], "demo": value["payload"]["run_metadata"]["demo"]}
    save_json(args.out, result)
    print("Local revealed-item file written. It contains this item's salt. Keep it on this machine.")


def verify_item(args):
    revealed = strict_json(Path(args.revealed).read_bytes())
    receipt = strict_json(Path(args.receipt).read_bytes())
    validate_payload(receipt["payload"])
    require(revealed["root"] == receipt["payload"]["root"] and revealed["item_count"] == receipt["payload"]["summary"]["item_count"],
            "Revealed item belongs to a different receipt")
    verify_inclusion(revealed["item"], revealed["salt"], revealed["index"], revealed["item_count"], revealed["siblings"], revealed["root"])
    print(json.dumps({"verified": True, "scope": "single item inclusion; aggregate, ledger and timestamp need receipt verify", "demo": revealed["demo"]}))


def parser():
    p = argparse.ArgumentParser(prog="receipt", description="Salt and hash eval output locally. Send only a root and chosen summaries.")
    p.add_argument("--state-dir", help="Local private settings directory")
    p.add_argument("--registry", help="HTTPS private registry origin, optionally /eval")
    sub = p.add_subparsers(dest="command", required=True)
    s = sub.add_parser("login"); s.add_argument("url"); s.set_defaults(func=login)
    def opts(s):
        s.add_argument("--model"); s.add_argument("--grader"); s.add_argument("--config", help="Local JSON config, salted before commitment")
        s.add_argument("--weights-fingerprint", action="append", metavar="MODEL=SHA256",
                       help="Opt in to sharing a model weights fingerprint; repeat for each model")
        s.add_argument("--demo", action="store_true"); s.add_argument("--benchmark-hash"); s.add_argument("--out")
    s = sub.add_parser("eval"); s.add_argument("results"); opts(s)
    s.add_argument("--share-cost", action="store_true", help="Explicitly send USD cost total (per-item costs stay local)")
    s.add_argument("--seed-file"); s.add_argument("--offline", action="store_true"); s.set_defaults(func=build)
    s = sub.add_parser("seed"); s.add_argument("--suite", required=True); opts(s)
    for option in s._actions:
        if option.dest in ("model", "grader"):
            option.required = True
    s.add_argument("--expires-hours", type=int, choices=range(1, 169), default=24); s.set_defaults(func=seed)
    s = sub.add_parser("seed-retry"); s.add_argument("seed_file"); s.set_defaults(func=seed_retry)
    s = sub.add_parser("publish"); s.add_argument("receipt"); s.set_defaults(func=publish)
    s = sub.add_parser("verify"); s.add_argument("receipt"); s.add_argument("--offline", action="store_true")
    s.add_argument("--require-confirmed", action="store_true"); s.set_defaults(func=verify)
    s = sub.add_parser("reveal"); s.add_argument("receipt"); s.add_argument("--item", required=True); s.add_argument("--out", required=True); s.set_defaults(func=reveal)
    s = sub.add_parser("verify-item"); s.add_argument("revealed"); s.add_argument("--receipt", required=True); s.set_defaults(func=verify_item)
    return p


def main():
    try:
        args = parser().parse_args()
        args.func(args)
        return 0
    except (InvalidReceipt, ValueError, OSError, KeyError, TypeError, ZeroDivisionError):
        # Never dump raw rows, input/output or secrets in parser/network errors.
        exc = sys.exc_info()[1]
        print("Verification failed: " + str(exc) if isinstance(exc, InvalidReceipt) else
              "Receipt failed: invalid or unreadable artifact; local files retained", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
