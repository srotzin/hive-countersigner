import base64, json, os, sys, tempfile, importlib
HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, HERE)
os.environ["COUNTERSIGNER_LOG_DIR"] = tempfile.mkdtemp()
os.environ["COUNTERSIGNER_KEY_PATH"] = os.path.join(os.environ["COUNTERSIGNER_LOG_DIR"], "k.pem")
os.environ["HIVE_OPERATED_KEYS"] = "sha256:" + "ab" * 32
import countersigner as cs
import independence as ind
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives import serialization

C = cs.app.test_client()
OPSIG = "x" * 1200
def b64u(b): return base64.urlsafe_b64encode(b).rstrip(b"=").decode()
def fresh_key():
    return b64u(Ed25519PrivateKey.generate().public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw))

def post(**kw):
    body = {"record": {"pass": 1}, "operator_signature": OPSIG, "operator_signature_scheme": "ed25519", **kw}
    r = C.post("/countersign", json=body)
    assert r.status_code == 200, r.get_json()
    return r.get_json()

def check_sig(out):
    pk = Ed25519PublicKey.from_public_bytes(base64.b64decode(out["countersigner_public_key_b64"]))
    pk.verify(base64.b64decode(out["countersignature"]), cs.canon(out["signed_over"]))

def test_health_operator_and_rule():
    h = C.get("/health").get_json()
    assert h["operator"] == "hive" and h["independent"] is False and h["independent_of_hive"] is False
    assert h["independence_scope"] == "issuer-relative"
    assert "Do not describe this service as independent" not in h["independence_note"]
    assert "independent_of_issuer" in h["independence_rule"] and h["hive_operated_key_count"] >= 30

def test_non_hive_issuer_is_independent_and_bound():
    k = fresh_key()
    out = post(issuer_public_key=k, issuer="did:web:example.org")
    so = out["signed_over"]
    assert out["independent_of_issuer"] is True and so["independent_of_issuer"] is True
    assert so["operator"] == "hive" and so["issuer_key_sha256"] == ind.fingerprint(k)
    assert out["independent"] is False and out["independent_of_hive"] is False
    check_sig(out)
    # tampering the flag breaks the countersignature
    so2 = dict(so, independent_of_issuer=False)
    r = C.post("/verify", json={"signed_over": so2, "countersignature": out["countersignature"]}).get_json()
    assert r["countersignature_valid"] is False
    r = C.post("/verify", json={"signed_over": so, "countersignature": out["countersignature"]}).get_json()
    assert r["countersignature_valid"] is True

def test_hive_keys_are_not_independent():
    for k in ["FCHk4lQ-PvNo2cxkUoL0VlGuKdU6DiK-vPraAR7gyHE",             # witness
              "ed25519:gWOCQWOMOfBL-R7IYJcjVfF1SlkXNqHtu55c7xbiO_8",     # typed-receipts-v2
              cs.PUB_B64,                                                # own key, std base64
              "sha256:" + "ab" * 32]:                                    # env-added
        out = post(issuer_public_key=k)
        assert out["independent_of_issuer"] is False, k
        assert "Hive-operated" in out["independence_basis"]

def test_hive_identity_absent_and_bad_key():
    assert post(issuer_public_key=fresh_key(), issuer="did:hive:someone")["independent_of_issuer"] is False
    assert post(issuer_public_key=fresh_key(), issuer="https://api.thehiveryiq.com/v1")["independent_of_issuer"] is False
    out = post()
    assert out["independent_of_issuer"] is False and "no issuer key" in out["independence_basis"]
    assert out["signed_over"]["issuer_key_sha256"] is None
    assert post(issuer_public_key="!!!")["independent_of_issuer"] is False

def test_issuer_read_from_record():
    k = fresh_key()
    r = C.post("/countersign", json={"record": {"issuer_public_key": k, "x": 1}, "operator_signature": OPSIG}).get_json()
    assert r["independent_of_issuer"] is True and r["signed_over"]["issuer_key_sha256"] == ind.fingerprint(k)

def test_hex_and_std_b64_same_fingerprint():
    raw = os.urandom(32)
    assert ind.fingerprint(raw.hex()) == ind.fingerprint(base64.b64encode(raw).decode()) == ind.fingerprint(b64u(raw))

def test_briefing_local_is_hive_issued():
    import briefing
    out = briefing._countersign_local({"a": 1}, OPSIG, "ml-dsa-65", fresh_key())
    assert out["independent_of_issuer"] is False and out["signed_over"]["independent_of_issuer"] is False
    assert out["operator"] == "hive"

def test_old_entries_still_verify():
    # an entry signed without the new fields (pre-change shape) still verifies
    so = {"seq": 1, "record_digest": "r", "operator_signature_digest": "o", "operator_signature_scheme": "s",
          "countersigner_time": 1.0, "prev_leaf": "p", "leaf": "l"}
    sig = base64.b64encode(cs.KEY.sign(cs.canon(so))).decode()
    assert C.post("/verify", json={"signed_over": so, "countersignature": sig}).get_json()["countersignature_valid"] is True

def test_inclusion_route_carries_flags():
    out = post(issuer_public_key=fresh_key())
    inc = C.get("/log/inclusion?seq=%d" % out["seq"]).get_json()
    assert inc["signed_over"]["independent_of_issuer"] is True
    assert C.post("/verify", json={"signed_over": inc["signed_over"], "countersignature": inc["countersignature"],
                                   "audit_path": inc["audit_path"], "root": inc["root"]}).get_json() == {"countersignature_valid": True, "inclusion_valid": True}
