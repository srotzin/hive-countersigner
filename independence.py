"""Issuer-relative independence.

THE RULE
Hive operates this countersigner, so it is never independent of Hive. It can be
independent of a receipt's issuer: for each receipt, independent_of_issuer is
true only when the issuer key is stated and is not a Hive-operated key. It is
false when the issuer is Hive (a Hive key, a did:hive identifier or a Hive host)
and false when no issuer key is stated, because independence from an unknown
party cannot be shown.

What the flag does not claim: it does not check that the stated issuer key
produced the operator signature. The fingerprint of the stated key is inside the
countersigned bytes, so a relying party compares it with the key that actually
verifies the receipt. A flag computed against a different key does not apply.
"""
import base64
import binascii
import hashlib
import json
import os
import re

OPERATOR = "hive"
HERE = os.path.dirname(os.path.abspath(__file__))
_REGISTRY_PATH = os.environ.get("HIVE_OPERATED_KEYS_FILE", os.path.join(HERE, "hive_operated_keys.json"))
_HIVE_HOST = re.compile(r"(^|[./@:])(thehiveryiq\.com|hivebound\.io)(?=$|[/:?#])", re.I)

RULE = (
    "Operated by Hive, so never independent of Hive. For each receipt, "
    "independent_of_issuer is true only when the issuer key is stated and is not "
    "a Hive-operated key. Hive-issued receipts and receipts with no stated issuer "
    "key read false. Describe this countersigner as independent of a named "
    "non-Hive issuer only for receipts where independent_of_issuer is true; do "
    "not describe it as neutral, a third party, or independent of Hive."
)


def key_bytes(key):
    """Raw public key bytes from 'ed25519:<b64url>', base64, base64url or hex."""
    if isinstance(key, (bytes, bytearray)):
        return bytes(key)
    if not isinstance(key, str) or not key.strip():
        return None
    s = key.strip()
    if ":" in s and not s.lower().startswith("sha256:"):
        s = s.split(":", 1)[1]
    if re.fullmatch(r"[0-9a-fA-F]+", s) and len(s) % 2 == 0 and len(s) >= 64:
        return bytes.fromhex(s)
    try:
        return base64.urlsafe_b64decode(s.replace("+", "-").replace("/", "_") + "=" * (-len(s) % 4))
    except (binascii.Error, ValueError):
        return None


def fingerprint(key):
    if isinstance(key, str) and key.lower().startswith("sha256:"):
        fp = key[7:].lower()
        return fp if re.fullmatch(r"[0-9a-f]{64}", fp) else None
    b = key_bytes(key)
    return hashlib.sha256(b).hexdigest() if b else None


def _load():
    fps = {}
    try:
        with open(_REGISTRY_PATH) as f:
            for k in json.load(f).get("keys", []):
                fps[k["sha256"]] = k.get("label", "hive key")
    except (OSError, ValueError, KeyError):
        pass
    for item in os.environ.get("HIVE_OPERATED_KEYS", "").split(","):
        fp = fingerprint(item.strip()) if item.strip() else None
        if fp:
            fps[fp] = "HIVE_OPERATED_KEYS"
    return fps


HIVE_KEY_FPS = _load()


def add_hive_key(key, label):
    fp = fingerprint(key)
    if fp:
        HIVE_KEY_FPS[fp] = label
    return fp


def is_hive_identity(issuer_id):
    if not isinstance(issuer_id, str) or not issuer_id:
        return False
    s = issuer_id.strip().lower()
    return s.startswith("did:hive:") or s.startswith("did:web:thehiveryiq.com") or bool(_HIVE_HOST.search(s))


def issuer_from(body, record):
    """The issuer key and id a caller stated, request fields first, then the record."""
    record = record if isinstance(record, dict) else {}
    key = body.get("issuer_public_key") or record.get("issuer_public_key") or record.get("public_key")
    iid = body.get("issuer") or record.get("issuer") or record.get("issuer_did") or record.get("iss")
    return key, iid if isinstance(iid, str) else None


def assess(issuer_key, issuer_id=None, *, hive_issued=False):
    """Per-receipt independence fields. All of them go into the countersigned bytes."""
    fp = fingerprint(issuer_key) if issuer_key else None
    if hive_issued:
        basis = "issuer is a Hive signer by construction"
        ind = False
    elif issuer_key and not fp:
        basis = "issuer key could not be parsed"
        ind = False
    elif not fp:
        basis = "no issuer key stated, so independence from the issuer cannot be shown"
        ind = False
    elif fp in HIVE_KEY_FPS:
        basis = "issuer key is Hive-operated (%s)" % HIVE_KEY_FPS[fp]
        ind = False
    elif is_hive_identity(issuer_id):
        basis = "stated issuer is a Hive identity"
        ind = False
    else:
        basis = "issuer key is not a Hive-operated key"
        ind = True
    return {
        "operator": OPERATOR,
        "issuer_key_sha256": fp,
        "independent_of_issuer": ind,
        "independence_basis": basis,
    }
