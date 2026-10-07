# creationloop eval receipts

Turn an existing JSONL or CSV eval file into a salted Merkle commitment and a private receipt link. All items and salts stay local. Only a root, a salted suite/config commitment, count, aggregate, model/grader names, optional USD total and fixed run metadata leave the machine.

[One-page quickstart](QUICKSTART.md) · [Protocol](PROTOCOL.md) · [Privacy and verification limits](SECURITY.md)

```sh
receipt login PRIVATE_REGISTRY_URL
receipt eval results.jsonl
receipt verify receipt-XXXXXXXXXXXX/receipt.json
```

Optional commands: `receipt seed`, `receipt seed-retry`, `receipt publish`, `receipt reveal`, and `receipt verify-item`. Use `receipt --help` or `receipt COMMAND --help` for options. A missing registry fails before registration; `--offline` explicitly creates a local commitment without a link.

For an open-weights model, opt in to recording its SHA256 weights fingerprint with `--weights-fingerprint MODEL=SHA256` on both `seed` and `eval`. The fingerprint stays bound to that model's seed and immutable ledger entry. Online verification rejects a changed fingerprint. See the [protocol](PROTOCOL.md) for the distinction between a committed fingerprint and proof of which weights executed.

The tool and verifier are Apache 2.0. Registry code, ledger storage, receipt pages, credentials and operational evidence are a separate private project. This package has no imports or runtime dependency on LeadReceipts v1 or Builder A.

## Local example

```sh
receipt eval examples/demo-results.jsonl --offline --demo --out demo-local
receipt verify demo-local/receipt.json --offline
receipt reveal demo-local/receipt.json --item public-example-1 --out revealed-item.json
receipt verify-item revealed-item.json --receipt demo-local/receipt.json
```

The revealed-item file remains local and contains the item's salt. No command uploads it. A single-item proof confirms inclusion only; full aggregate, registry and timestamp verification uses the complete local receipt bundle.

## Development

```sh
python3 -m venv .venv
.venv/bin/python -m pip install -e .
.venv/bin/python -m unittest discover -s tests -v
```

Supported platforms: Python 3.10+ on Linux and macOS. The Windows console works through `python -m eval_receipts`; private-file permissions must be enforced by the user's Windows account/ACL configuration. See the [v0.1.1 release](https://github.com/marino129/eval-receipts-kit/releases/tag/v0.1.1) for the installable wheel and source archive. The 0.1.1 verifier also accepts unchanged 0.1.0 receipts.
