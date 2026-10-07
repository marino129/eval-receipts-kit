"""Versioned canonicalization, salted Merkle commitments, and wire allowlists.

Item content, item identifiers, and salts belong to local artifacts only.
All numeric inputs are normalized decimal strings, never binary-float sums.
"""
import csv
import hashlib
import json
import os
import re
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation, localcontext
from pathlib import Path

SCHEMA = "creationloop.eval.v1"
HEX = re.compile(r"[0-9a-f]{64}\Z")
UUID = re.compile(r"[0-9a-f]{32}\Z")
ITEM_KEYS = {"id", "input", "output", "score", "model", "grader", "cost"}
MAX_ITEMS = 1_000_000


class InvalidReceipt(ValueError):
    pass


def require(ok, message):
    if not ok:
        raise InvalidReceipt(message)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False).encode("utf-8")


def strict_json(data):
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, "Duplicate JSON key")
            result[key] = value
        return result
    return json.loads(data, object_pairs_hook=pairs,
                      parse_constant=lambda _: require(False, "Nonfinite JSON number"))


def decimal_text(value, nonnegative=False):
    require(not isinstance(value, bool) and isinstance(value, (str, int, float, Decimal)),
            "Expected a decimal number")
    try:
        d = Decimal(str(value))
    except InvalidOperation:
        raise InvalidReceipt("Invalid decimal number") from None
    require(d.is_finite() and abs(d) <= Decimal("1e18") and d.as_tuple().exponent >= -12,
            "Number must be finite, <= 1e18, and have <= 12 decimal places")
    require(not nonnegative or d >= 0, "Cost must be nonnegative")
    if d == 0:
        return "0"
    return format(d, "f").rstrip("0").rstrip(".") if d.as_tuple().exponent < 0 else format(d, "f")


def name(value):
    require(isinstance(value, str) and 0 < len(value) <= 160 and
            all(c.isprintable() for c in value), "Invalid model or grader name")
    return value


def now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def parse_time(value):
    require(isinstance(value, str) and len(value) <= 40, "Invalid timestamp")
    try:
        d = datetime.fromisoformat(value.replace("Z", "+00:00"))
        require(d.tzinfo is not None, "Timestamp needs timezone")
        return d.astimezone(timezone.utc)
    except ValueError:
        raise InvalidReceipt("Invalid timestamp") from None


def sha(value):
    return hashlib.sha256(value).hexdigest()


def hash_hex(value):
    require(isinstance(value, str) and HEX.fullmatch(value), "Invalid SHA-256 digest")
    return value


def item_record(value, index):
    require(isinstance(value, dict), "Each item must be an object")
    value = dict(value)
    if "item_id" in value:
        require("id" not in value, "Use id or item_id, not both")
        value["id"] = value.pop("item_id")
    require(set(value) <= ITEM_KEYS and {"id", "input", "output", "score"} <= set(value),
            "Expected id, input, output, score and optional model, grader, cost")
    require(isinstance(value["id"], (str, int)) and not isinstance(value["id"], bool), "Invalid item id")
    value["id"] = str(value["id"])
    require(value["id"] and len(value["id"]) <= 1024, "Invalid item id")
    value["score"] = decimal_text(value["score"])
    for k in ("model", "grader"):
        if value.get(k) in (None, ""):
            value.pop(k, None)
        elif k in value:
            value[k] = name(value[k])
    if value.get("cost") in (None, ""):
        value.pop("cost", None)
    elif "cost" in value:
        value["cost"] = decimal_text(value["cost"], nonnegative=True)
    require(len(canonical(value)) <= 4_000_000, f"Item {index} exceeds 4MB")
    return value


def read_items(path):
    path = Path(path)
    with path.open(encoding="utf-8-sig", newline="") as f:
        if path.suffix.lower() == ".csv":
            reader = csv.DictReader(f)
            require(reader.fieldnames and len(set(reader.fieldnames)) == len(reader.fieldnames),
                    "CSV headers must be unique")
            for i, row in enumerate(reader):
                require(None not in row and all(v is not None for v in row.values()), "Malformed CSV row")
                yield item_record(row, i)
        elif path.suffix.lower() in (".jsonl", ".ndjson"):
            for i, line in enumerate(f):
                require(line.strip(), "Blank JSONL row")
                yield item_record(strict_json(line), i)
        else:
            raise InvalidReceipt("Use a .jsonl, .ndjson, or .csv results file")


def leaf(item, salt, index):
    hash_hex(salt)
    return hashlib.sha256(b"creationloop.eval.item.v1\0" + bytes.fromhex(salt) +
                          canonical({"index": index, "item": item})).digest()


def parent(left, right):
    return hashlib.sha256(b"creationloop.eval.node.v1\0" + left + right).digest()


def tree(leaves):
    require(leaves, "A run must contain at least one item")
    levels = [leaves]
    while len(levels[-1]) > 1:
        row = levels[-1]
        levels.append([parent(row[i], row[min(i + 1, len(row) - 1)])
                       for i in range(0, len(row), 2)])
    return levels


def inclusion(levels, index):
    proof = []
    for row in levels[:-1]:
        side = "left" if index % 2 else "right"
        proof.append({"side": side, "hash": row[min(index ^ 1, len(row) - 1)].hex()})
        index //= 2
    return proof


def verify_inclusion(item, salt, index, count, proof, root):
    require(type(index) is int and type(count) is int and 0 <= index < count <= MAX_ITEMS,
            "Invalid proof position")
    require(isinstance(proof, list), "Proof must be a list")
    h = leaf(item_record(item, index), salt, index)
    n, pos, depth = count, index, 0
    while n > 1:
        require(depth < len(proof), "Proof too short")
        p = proof[depth]
        require(isinstance(p, dict) and set(p) == {"side", "hash"}, "Invalid proof step")
        sibling = bytes.fromhex(hash_hex(p["hash"]))
        require(p["side"] == ("left" if pos % 2 else "right"), "Proof orientation mismatch")
        if pos % 2 == 0 and pos == n - 1:
            require(sibling == h, "Odd leaf must duplicate itself")
        h = parent(sibling, h) if pos % 2 else parent(h, sibling)
        pos, n, depth = pos // 2, (n + 1) // 2, depth + 1
    require(depth == len(proof) and h.hex() == hash_hex(root), "Item inclusion proof mismatch")


def suite_hash(items, salt):
    hash_hex(salt)
    h = hashlib.sha256(b"creationloop.eval.suite.v1\0" + bytes.fromhex(salt))
    for i, item in enumerate(items):
        part = canonical({"index": i, "id": item["id"], "input": item["input"]})
        h.update(len(part).to_bytes(8, "big"))
        h.update(part)
    return h.hexdigest()


def read_suite(path):
    """Before a run only id/item_id and input are required; extra columns ignored locally."""
    path = Path(path)
    with path.open(encoding="utf-8-sig", newline="") as f:
        if path.suffix.lower() == ".csv":
            reader = csv.DictReader(f)
            require(reader.fieldnames and len(set(reader.fieldnames)) == len(reader.fieldnames), "CSV headers must be unique")
        else:
            require(path.suffix.lower() in (".jsonl", ".ndjson"), "Suite must be JSONL or CSV")
            reader = (strict_json(line) for line in f)
        seen = set()
        for row in reader:
            require(isinstance(row, dict) and "input" in row, "Suite requires id and input")
            ident = row.get("id", row.get("item_id"))
            require(isinstance(ident, (str, int)) and not isinstance(ident, bool), "Invalid suite id")
            ident = str(ident)
            require(ident and ident not in seen, "Duplicate or empty suite id")
            seen.add(ident)
            require(len(seen) <= MAX_ITEMS, "Suite too large")
            yield {"id": ident, "input": row["input"]}
        require(seen, "Suite is empty")


def summary(items, model=None, grader=None, share_cost=False):
    names = {k: sorted({item[k] for item in items if k in item}) for k in ("model", "grader")}
    for key, override in (("model", model), ("grader", grader)):
        if override:
            name(override)
            require(not names[key] or names[key] == [override], f"{key} override contradicts item names")
            names[key] = [override]
        if not names[key]:
            names[key] = ["unspecified"]
    with localcontext() as ctx:
        ctx.prec = 64
        total = sum((Decimal(item["score"]) for item in items), Decimal(0))
        mean = (total / len(items)).quantize(Decimal("0.000000000001"))
        cost = sum((Decimal(item["cost"]) for item in items if "cost" in item), Decimal(0))
    def fmt(d):
        return format(d, "f").rstrip("0").rstrip(".") if "." in format(d, "f") else str(d)
    return {"item_count": len(items), "score_sum": fmt(total) or "0",
            "aggregate_score": fmt(mean) or "0", "models": names["model"],
            "graders": names["grader"], "cost_total_usd": (fmt(cost) or "0") if share_cost else None}


def validate_summary(s):
    require(isinstance(s, dict) and set(s) == {"item_count", "score_sum", "aggregate_score", "models", "graders", "cost_total_usd"},
            "Unknown or missing summary field")
    require(type(s["item_count"]) is int and 0 < s["item_count"] <= MAX_ITEMS, "Invalid item count")
    # Allow larger sums while bounding parsing and preserving the mean definition.
    for k in ("score_sum", "aggregate_score", "cost_total_usd"):
        if k == "cost_total_usd" and s[k] is None:
            continue
        require(isinstance(s[k], str) and len(s[k]) <= 48, "Summary numbers must be decimal strings")
        try:
            d = Decimal(s[k])
        except InvalidOperation:
            raise InvalidReceipt("Invalid summary number") from None
        require(d.is_finite() and abs(d) <= Decimal("1e24") and d.as_tuple().exponent >= -12,
                "Invalid summary number")
        require(k != "cost_total_usd" or d >= 0, "Negative cost")
    with localcontext() as ctx:
        ctx.prec = 64
        expected = (Decimal(s["score_sum"]) / s["item_count"]).quantize(Decimal("0.000000000001"))
    require(Decimal(s["aggregate_score"]) == expected, "Aggregate differs from score sum / count")
    for k in ("models", "graders"):
        require(isinstance(s[k], list) and 0 < len(s[k]) <= 64, "Invalid name list")
        for v in s[k]:
            name(v)
        require(s[k] == sorted(set(s[k])), "Names must be sorted and unique")
    return s


def validate_payload(p, kind="settle"):
    base = {"schema", "kind", "run_id", "suite_hash", "models", "graders", "config_hash", "run_metadata"}
    expected = base | ({"root", "summary", "seed_id"} if kind == "settle" else {"expires_at"})
    require(isinstance(p, dict) and set(p) == expected, "Unknown or missing registry field")
    require(p["schema"] == SCHEMA and p["kind"] == kind, "Unsupported payload schema")
    require(isinstance(p["run_id"], str) and UUID.fullmatch(p["run_id"]), "Invalid run id")
    for k in ("suite_hash", "config_hash"):
        hash_hex(p[k])
    for k in ("models", "graders"):
        require(isinstance(p[k], list) and 0 < len(p[k]) <= 64, "Invalid model or grader list")
        for v in p[k]: name(v)
        require(p[k] == sorted(set(p[k])), "Names must be unique and sorted")
    m = p["run_metadata"]
    require(isinstance(m, dict) and set(m) == {"created_at", "demo", "tool_version", "benchmark_hash"},
            "Run metadata accepts only timestamp, demo, tool version, benchmark hash")
    parse_time(m["created_at"])
    require(type(m["demo"]) is bool and m["tool_version"] == "0.1.0", "Invalid run metadata")
    if m["benchmark_hash"] is not None: hash_hex(m["benchmark_hash"])
    if kind == "settle":
        hash_hex(p["root"])
        validate_summary(p["summary"])
        require(p["models"] == p["summary"]["models"] and p["graders"] == p["summary"]["graders"],
                "Payload names differ from summary")
        require(p["seed_id"] is None or p["seed_id"] == p["run_id"], "Invalid seed id")
    else:
        parse_time(p["expires_at"])
    require(len(canonical(p)) <= 32_768, "Registry payload too large")
    return p


def series_id(p):
    # Suite and model define a series; grader/config changes remain visible in each entry.
    return sha(b"creationloop.eval.series.v1\0" + canonical({"suite_hash": p["suite_hash"], "models": p["models"]}))


def entry_hash(e):
    return sha(b"creationloop.eval.ledger.v1\0" + canonical(e))


def verify_chain(entries, expected_entry=None):
    previous = "0" * 64
    require(isinstance(entries, list) and entries, "Missing ledger segment")
    found = None
    for seq, entry in enumerate(entries, 1):
        require(isinstance(entry, dict) and set(entry) == {"segment", "sequence", "previous_hash", "at", "event", "run_id", "series_id", "run_number", "payload", "hash"},
                "Invalid ledger entry")
        e = {k: v for k, v in entry.items() if k != "hash"}
        require(e["segment"] == "eval-receipts-v1" and type(e["sequence"]) is int and e["sequence"] == seq and e["previous_hash"] == previous,
                "Ledger chain discontinuity")
        require(entry_hash(e) == hash_hex(entry["hash"]), "Ledger hash mismatch")
        parse_time(e["at"])
        require(e["event"] in ("seed", "settle", "abandoned", "anchor_confirmed"), "Invalid ledger event")
        require(type(e["run_number"]) is int and e["run_number"] > 0, "Invalid run number")
        if expected_entry and entry["hash"] == expected_entry:
            found = entry
        previous = entry["hash"]
    require(not expected_entry or found is not None, "Receipt entry not in ledger")
    return found


def write_private(path, data):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())


def save_json(path, value):
    write_private(path, canonical(value) + b"\n")


def replace_private(path, data):
    import secrets
    path = Path(path)
    temp = path.with_name(path.name + ".tmp-" + secrets.token_hex(8))
    write_private(temp, data)
    os.replace(temp, path)
