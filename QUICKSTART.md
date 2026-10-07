# Eval receipts in one sitting

Use Python 3.10 or newer. Get the private registry URL and key from your eval team's operator first. The registry is private; your machine must already have access to its private network. Keep your existing JSONL or CSV results file on your machine.

**1. Install and connect once**

```sh
python3 -m venv .receipt-env
.receipt-env/bin/python -m pip install "https://github.com/marino129/eval-receipts-kit/releases/download/v0.1.0/creationloop_eval_receipts-0.1.0-py3-none-any.whl"
.receipt-env/bin/receipt login PRIVATE_REGISTRY_URL
```

Enter the key at the hidden prompt. For automation, set `RECEIPT_REGISTRY` and `RECEIPT_TOKEN` through your secret manager. Credentials are stored locally with private file permissions and never appear in receipt links.

**2. Turn the results you already have into a receipt**

```sh
.receipt-env/bin/receipt eval results.jsonl
```

Each row needs `id` (or `item_id`), `input`, `output`, and a numeric `score`. Optional fields are `model`, `grader`, and per-item USD `cost`. CSV needs the same header. Add `--model NAME --grader NAME` when the file does not name them. Add `--share-cost` only if you want the cost total sent. Add `--demo` for demonstrations.

The command prints a private receipt link and a directory containing `receipt.json`, `items.jsonl`, `proofs.jsonl`, and the exact `payload.json` sent. Open the link, enter the same registry key, and see the run number, count, score, model, grader, cost and anchor status. Keep the whole directory local: it contains item content and secret salts. Only the allowlisted hash and summaries are uploaded. Item processing is local; Bitcoin confirmation arrives later.

**3. Verify**

```sh
.receipt-env/bin/receipt verify receipt-XXXXXXXXXXXX/receipt.json
.receipt-env/bin/receipt verify receipt-XXXXXXXXXXXX/receipt.json --require-confirmed
```

The first command checks the local root and aggregate, the private ledger entry and timestamp binding. It clearly reports a pending anchor. The second succeeds only after independent Bitcoin verification. A changed item or score fails with a nonzero exit code. Network failures preserve the artifacts: retry with `receipt publish PATH/receipt.json`; it uses the same run id.

Optional pre-registration: `receipt seed --suite suite.jsonl --model NAME --grader NAME --out seed-1`, then `receipt eval results.jsonl --seed-file seed-1/seed.json --model NAME --grader NAME`. Suites need only id and input. Pass the same local JSON `--config FILE` to both commands. Unsettled seeds expire after 24 hours and remain visible as abandoned. Repeated suite/model runs from this installation retain a stable salted suite commitment and receive increasing run numbers.

Install the wheel above without Git, or use the source at tag `v0.1.0`. Release files and checksums are on the [v0.1.0 release](https://github.com/marino129/eval-receipts-kit/releases/tag/v0.1.0). The private network and registry key are prerequisites, supplied by your eval team's operator.
