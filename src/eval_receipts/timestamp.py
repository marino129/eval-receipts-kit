"""Standard OpenTimestamps proofs for SHA256(the 32-byte Merkle root).

No item or salt is passed to a calendar. HTTPS explorer mode uses two independent
main-chain hash witnesses; operators can independently verify the .ots with
Bitcoin Core using the official ots client and the saved root.bin.
"""
import hashlib
import io
import struct
from .core import InvalidReceipt, hash_hex, require
from .transport import request

CALENDARS = ("https://a.pool.opentimestamps.org", "https://b.pool.opentimestamps.org")
ALLOWED_CALENDARS = CALENDARS + ("https://alice.btc.calendar.opentimestamps.org",
                                "https://bob.btc.calendar.opentimestamps.org")
WITNESSES = ("https://blockstream.info/api", "https://mempool.space/api")


def serialize(detached):
    from opentimestamps.core.serialize import StreamSerializationContext
    out = io.BytesIO()
    detached.serialize(StreamSerializationContext(out))
    return out.getvalue()


def deserialize(data, root):
    from opentimestamps.core.serialize import StreamDeserializationContext, DeserializationError
    from opentimestamps.core.timestamp import DetachedTimestampFile
    from opentimestamps.core.op import OpSHA256
    require(isinstance(data, bytes) and 0 < len(data) <= 1_000_000, "Invalid timestamp proof size")
    buf = io.BytesIO(data)
    try:
        proof = DetachedTimestampFile.deserialize(StreamDeserializationContext(buf))
    except (DeserializationError, ValueError, TypeError, OverflowError):
        raise InvalidReceipt("Invalid OpenTimestamps proof") from None
    require(not buf.read(1), "Trailing timestamp bytes")
    require(type(proof.file_hash_op) is OpSHA256 and
            proof.file_digest == hashlib.sha256(bytes.fromhex(hash_hex(root))).digest(),
            "Timestamp does not bind the Merkle root")
    return proof


def stamp_root(root):
    from opentimestamps.calendar import RemoteCalendar
    from opentimestamps.core.op import OpSHA256
    from opentimestamps.core.timestamp import DetachedTimestampFile
    proof = DetachedTimestampFile.from_fd(OpSHA256(), io.BytesIO(bytes.fromhex(hash_hex(root))))
    accepted = 0
    for uri in CALENDARS:
        try:
            proof.timestamp.merge(RemoteCalendar(uri).submit(proof.file_digest, timeout=10))
            accepted += 1
        except Exception:
            continue
    require(accepted, "No OpenTimestamps calendar accepted the root; retry is safe")
    return serialize(proof)


def upgrade_root(data, root):
    from opentimestamps.calendar import RemoteCalendar
    from opentimestamps.core.notary import PendingAttestation
    proof = deserialize(data, root)
    def walk(ts):
        yield ts
        for child in list(ts.ops.values()):
            yield from walk(child)
    for ts in list(walk(proof.timestamp)):
        for att in list(ts.attestations):
            if type(att) is PendingAttestation and att.uri in ALLOWED_CALENDARS:
                try:
                    ts.merge(RemoteCalendar(att.uri).get_timestamp(ts.msg, timeout=10))
                except Exception:
                    continue
    return serialize(proof)


def verify_timestamp(data, root, allow_network=True):
    from opentimestamps.core.notary import BitcoinBlockHeaderAttestation, PendingAttestation
    proof = deserialize(data, root)
    attestations = list(proof.timestamp.all_attestations())
    bitcoin = [(msg, att) for msg, att in attestations if type(att) is BitcoinBlockHeaderAttestation]
    if not bitcoin:
        require(any(type(att) is PendingAttestation and att.uri in ALLOWED_CALENDARS for _, att in attestations),
                "Timestamp has no recognized attestation")
        return {"status": "pending", "binding_verified": True, "bitcoin_verified": False}
    require(allow_network, "Bitcoin confirmation requires independent header verification; use online verify")
    for msg, att in bitcoin:
        try:
            hashes = [request(base + f"/block-height/{att.height}", limit=128).decode().strip()
                      for base in WITNESSES]
            require(len(set(hashes)) == 1, "Bitcoin witnesses disagree")
            block_hash = hash_hex(hashes[0])
            header = bytes.fromhex(request(WITNESSES[0] + f"/block/{block_hash}/header", limit=200).decode().strip())
            require(len(header) == 80, "Invalid Bitcoin header")
            digest = hashlib.sha256(hashlib.sha256(header).digest()).digest()
            require(digest[::-1].hex() == block_hash, "Bitcoin header hash mismatch")
            bits = struct.unpack("<I", header[72:76])[0]
            exponent, mantissa = bits >> 24, bits & 0x7fffff
            require(not bits & 0x800000 and 3 <= exponent <= 32, "Invalid proof of work target")
            target = mantissa << (8 * (exponent - 3))
            require(0 < target <= (0xffff << (8 * (0x1d - 3))) and
                    int.from_bytes(digest, "little") <= target, "Bitcoin proof of work mismatch")
            require(msg == header[36:68], "OTS Bitcoin Merkle root mismatch")
            return {"status": "confirmed", "binding_verified": True, "bitcoin_verified": True,
                    "height": att.height, "block_hash": block_hash,
                    "block_time": struct.unpack("<I", header[68:72])[0],
                    "verification": "header PoW and two independent HTTPS main-chain witnesses"}
        except (InvalidReceipt, ValueError):
            continue
    raise InvalidReceipt("Bitcoin timestamp verification failed")
