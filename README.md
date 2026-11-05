# hive-countersigner

A second signing party for Hive pass records. It holds its own key, keeps its
own clock, and maintains a hash-chained log with Merkle inclusion proofs, so a
relying party can check that a record was logged without asking the serving
operator for anything.

## Honesty boundary

Read this before quoting the service anywhere.

* This process is operated by Hive (`operator: "hive"`). It is a second key and a
  second clock. It is never independent of Hive: `/health` reports
  `independent: false` and `independent_of_hive: false`.
* Independence is issuer-relative. Every countersigned entry carries
  `independent_of_issuer`, true only when the issuer key is stated and is not a
  Hive-operated key (`hive_operated_keys.json`, the countersigner's own key, and
  `HIVE_OPERATED_KEYS`). A stated `did:hive:` or Hive-host issuer, or no stated
  issuer key, reads false. Briefing records are Hive-signed and always read false.
* The SHA-256 of the stated issuer key is inside the countersigned bytes. The
  flag applies only if that key is the one that verifies the record; the
  countersigner does not itself verify the operator signature.
* Describe the countersigner as independent of a named non-Hive issuer only for
  receipts where `independent_of_issuer` is true. Do not describe it as
  neutral, a third party, or independent of Hive.
* The countersignature scheme is **Ed25519**. It is not post quantum. The
  operator signer at `signer.thehiveryiq.com` is ML-DSA-65 under NIST FIPS 204.
  Those are different schemes and every record states which signed which part.
* When no persistent disk is attached, `/health` reports `log_durable: false`.
  In that state the log does not survive a redeploy and must not be described as
  a durable transparency log.

## Endpoints

| Method | Path | Purpose |
|---|---|---|
| GET | `/health` | Scheme, public key, entry count, log root, honesty flags |
| POST | `/countersign` | Countersign a record that already carries a real operator signature |
| GET | `/log/head` | Entry count, latest sequence number, current Merkle root |
| GET | `/log/inclusion?seq=N` | The signed entry plus its audit path to the root |
| POST | `/verify` | Check a countersignature, an inclusion proof, and a record digest |

`/countersign` takes `record`, `operator_signature`, `operator_signature_scheme`,
and optionally `issuer_public_key` and `issuer` (otherwise read from the record's
`issuer_public_key`/`public_key` and `issuer`/`issuer_did`/`iss`).

`/countersign` refuses any request whose operator signature is under 1000
characters, because the production signer emits well over 4000. A stub
signature is rejected with 422 rather than logged.

## Verifying without trusting this host

`/verify` uses only the supplied values and the countersigner public key, so the
same check runs offline. Take the `signed_over` object, the
`countersignature`, the `audit_path` and the `root` from `/log/inclusion`, and
verify locally.

## Run it

```
pip install -r requirements.txt
COUNTERSIGNER_SEED=<32 bytes base64> gunicorn countersigner:app --bind 0.0.0.0:$PORT
```

Environment:

* `COUNTERSIGNER_SEED` keeps the public key stable across restarts.
* `COUNTERSIGNER_LOG_DIR` points the log at a persistent disk.
* `COUNTERSIGNER_LOG_DURABLE=true` only when that disk is real.
* `HIVE_OPERATED_KEYS` adds Hive-operated keys (comma-separated keys or `sha256:` fingerprints).

Patent pending.
