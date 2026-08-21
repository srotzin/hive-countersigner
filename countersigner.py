"""Hive countersigner.

A second signing party for pass records. It holds its own key, keeps its own
clock, and maintains an append-only hash-chained log with Merkle inclusion
proofs so a relying party can check that a record was logged without asking the
serving operator for anything.

HONESTY BOUNDARY, read this before quoting the service anywhere.
This process is operated by Hive today. It is a second key and a second clock,
not an independent third party. Independence is a deployment property, not a
code property, and this code does not create it. /health reports
independent: false and says so in words. Do not describe this as neutral,
independent, or third party until it runs somewhere Hive does not control.

Signature scheme here is Ed25519, not ML-DSA. The operator signer at
signer.thehiveryiq.com is ML-DSA-65. Those are different schemes and the
records say which is which. Never describe the countersignature as
post-quantum.
"""
import json, os, time, base64, threading
from flask import Flask, request, jsonify
from blake3 import blake3
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives import serialization

HERE = os.path.dirname(os.path.abspath(__file__))
KEY_PATH = os.environ.get("COUNTERSIGNER_KEY_PATH", os.path.join(HERE, "countersigner_key.pem"))
LOG_DIR  = os.environ.get("COUNTERSIGNER_LOG_DIR", HERE)
LOG_PATH = os.path.join(LOG_DIR, "countersign_log.jsonl")
# A persistent disk is what makes the log durable across restarts. When this is
# not set the process is running on ephemeral storage and the log does not
# survive a redeploy. /health reports that honestly rather than implying
# durability the host does not provide.
LOG_DURABLE = os.environ.get("COUNTERSIGNER_LOG_DURABLE", "").lower() == "true"
MIN_OPERATOR_SIG = 1000   # the operator signer emits 4400+ chars; refuse stubs

_lock = threading.Lock()

def _load_key():
    # A seed in the environment keeps the public key stable across redeploys on
    # hosts with no persistent disk. Without it the key is generated once and
    # lives only as long as the filesystem does.
    seed = os.environ.get("COUNTERSIGNER_SEED", "").strip()
    if seed:
        raw = base64.b64decode(seed)
        if len(raw) != 32:
            raise SystemExit("COUNTERSIGNER_SEED must be 32 bytes base64")
        return Ed25519PrivateKey.from_private_bytes(raw)
    if os.path.exists(KEY_PATH):
        with open(KEY_PATH, "rb") as f:
            return serialization.load_pem_private_key(f.read(), password=None)
    k = Ed25519PrivateKey.generate()
    with open(KEY_PATH, "wb") as f:
        f.write(k.private_bytes(serialization.Encoding.PEM,
                               serialization.PrivateFormat.PKCS8,
                               serialization.NoEncryption()))
    os.chmod(KEY_PATH, 0o600)
    return k

KEY = _load_key()
PUB_B64 = base64.b64encode(KEY.public_key().public_bytes(
    serialization.Encoding.Raw, serialization.PublicFormat.Raw)).decode()

def canon(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()

def h(b, tag):
    return blake3(tag.encode() + b"\x00" + b).hexdigest()

def read_log():
    if not os.path.exists(LOG_PATH):
        return []
    out = []
    with open(LOG_PATH) as f:
        for line in f:
            line = line.strip()
            if line:
                out.append(json.loads(line))
    return out

def merkle_root(leaves):
    """Root over leaf hashes. Odd node is promoted, not duplicated."""
    if not leaves:
        return h(b"", "empty")
    level = list(leaves)
    while len(level) > 1:
        nxt = []
        for i in range(0, len(level), 2):
            if i + 1 < len(level):
                nxt.append(h((level[i] + level[i+1]).encode(), "node"))
            else:
                nxt.append(level[i])
        level = nxt
    return level[0]

def merkle_path(leaves, index):
    """Audit path from leaf to root. Each step is [side, sibling_hash]."""
    path, level, idx = [], list(leaves), index
    while len(level) > 1:
        nxt = []
        for i in range(0, len(level), 2):
            if i + 1 < len(level):
                parent = h((level[i] + level[i+1]).encode(), "node")
                if i == idx:      path.append(["right", level[i+1]])
                elif i + 1 == idx: path.append(["left", level[i]])
            else:
                parent = level[i]
            nxt.append(parent)
        idx //= 2
        level = nxt
    return path

def apply_path(leaf, path):
    cur = leaf
    for side, sib in path:
        cur = h(((cur + sib) if side == "right" else (sib + cur)).encode(), "node")
    return cur

app = Flask(__name__)

INDEPENDENCE_NOTE = (
    "This countersigner is operated by Hive. It holds a separate key and keeps a "
    "separate clock and log from the serving operator, which removes self-dated "
    "records and undetected conflicting records. It does not make Hive an "
    "independent party, because Hive runs both sides today. Independence is a "
    "deployment property. Do not describe this service as independent, neutral or "
    "third party while this flag reads false."
)

@app.get("/health")
def health():
    log = read_log()
    return jsonify({
        "service": "hive-countersigner",
        "status": "live",
        "signature_scheme": "Ed25519",
        "post_quantum": False,
        "public_key_b64": PUB_B64,
        "log_entries": len(log),
        "log_durable": LOG_DURABLE,
        "log_durability_note": (
            "Log is on a persistent disk." if LOG_DURABLE else
            "Log is on ephemeral storage and does not survive a redeploy. Until a "
            "persistent disk is attached, treat the log as append-only within a "
            "process lifetime only, and do not describe it as a durable "
            "transparency log."),
        "log_root": merkle_root([e["leaf"] for e in log]),
        "independent": False,
        "independence_note": INDEPENDENCE_NOTE,
    })

@app.post("/countersign")
def countersign():
    body = request.get_json(force=True, silent=True) or {}
    record = body.get("record")
    op_sig = body.get("operator_signature") or ""
    op_scheme = body.get("operator_signature_scheme") or "unstated"
    if not isinstance(record, dict):
        return jsonify({"error": "record must be an object"}), 422
    if len(op_sig) < MIN_OPERATOR_SIG:
        return jsonify({"error": "operator signature absent or too short to be real",
                        "min_chars": MIN_OPERATOR_SIG, "got_chars": len(op_sig)}), 422

    record_digest = h(canon(record), "record")
    with _lock:
        log = read_log()
        seq = len(log) + 1
        prev = log[-1]["leaf"] if log else h(b"", "genesis")
        cs_time = time.time()
        leaf = h(canon({"seq": seq, "prev": prev, "record_digest": record_digest,
                        "countersigner_time": cs_time, "operator_signature_digest":
                        h(op_sig.encode(), "opsig")}), "leaf")
        signed_over = {
            "seq": seq,
            "record_digest": record_digest,
            "operator_signature_digest": h(op_sig.encode(), "opsig"),
            "operator_signature_scheme": op_scheme,
            "countersigner_time": cs_time,
            "prev_leaf": prev,
            "leaf": leaf,
        }
        cs_sig = base64.b64encode(KEY.sign(canon(signed_over))).decode()
        entry = dict(signed_over)
        entry["countersignature"] = cs_sig
        with open(LOG_PATH, "a") as f:
            f.write(json.dumps(entry, sort_keys=True) + "\n")
        log.append(entry)
        root = merkle_root([e["leaf"] for e in log])

    return jsonify({
        "countersigned": True,
        "seq": seq,
        "signed_over": signed_over,
        "signed_over_canonical": canon(signed_over).decode(),
        "countersignature": cs_sig,
        "countersignature_scheme": "Ed25519",
        "countersigner_public_key_b64": PUB_B64,
        "log_root_after": root,
        "independent": False,
        "note": "Second key and second clock. Not an independent party. See /health.",
    })

@app.get("/log/head")
def head():
    log = read_log()
    return jsonify({"entries": len(log),
                    "root": merkle_root([e["leaf"] for e in log]),
                    "latest_seq": log[-1]["seq"] if log else 0})

@app.get("/log/inclusion")
def inclusion():
    try:
        seq = int(request.args.get("seq", "0"))
    except ValueError:
        return jsonify({"error": "seq must be an integer"}), 422
    log = read_log()
    if seq < 1 or seq > len(log):
        return jsonify({"error": "no such seq", "entries": len(log)}), 404
    leaves = [e["leaf"] for e in log]
    entry = log[seq - 1]
    signed_over = {k: v for k, v in entry.items() if k != "countersignature"}
    return jsonify({"seq": seq,
                    "signed_over": signed_over,
                    "signed_over_canonical": canon(signed_over).decode(),
                    "countersigner_public_key_b64": PUB_B64,
                    "countersignature": entry["countersignature"],
                    "audit_path": merkle_path(leaves, seq - 1),
                    "root": merkle_root(leaves)})

@app.post("/verify")
def verify():
    """Check a countersignature and, if an audit path is supplied, inclusion.
    Verification uses only the countersigner public key and the supplied values,
    so a relying party can run this code itself rather than calling this host."""
    b = request.get_json(force=True, silent=True) or {}
    signed_over, sig = b.get("signed_over"), b.get("countersignature") or ""
    if not isinstance(signed_over, dict):
        return jsonify({"error": "signed_over must be an object"}), 422
    # the countersignature is never inside the bytes it signs; drop it if a
    # caller passes a whole log entry straight through
    signed_over = {k: v for k, v in signed_over.items() if k != "countersignature"}
    try:
        pk = Ed25519PublicKey.from_public_bytes(base64.b64decode(
            b.get("countersigner_public_key_b64") or PUB_B64))
        pk.verify(base64.b64decode(sig), canon(signed_over))
        sig_ok = True
    except Exception:
        sig_ok = False
    out = {"countersignature_valid": sig_ok}
    if b.get("audit_path") is not None and b.get("root"):
        out["inclusion_valid"] = (apply_path(signed_over.get("leaf", ""),
                                             b["audit_path"]) == b["root"])
    if b.get("record") is not None:
        out["record_digest_matches"] = (h(canon(b["record"]), "record")
                                        == signed_over.get("record_digest"))
    return jsonify(out)

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=int(os.environ.get("PORT", "8791")))
