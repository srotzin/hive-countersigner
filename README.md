# hive-countersigner

A second signing party for Hive pass records. It holds its own key, keeps its
own clock, and maintains a hash-chained log with Merkle inclusion proofs, so a
relying party can check that a record was logged without asking the serving
operator for anything.

## Honesty boundary

Read this before quoting the service anywhere.

* This process is operated by Hive. It is a second key and a second clock, not
  an independent third party. `/health` reports `independent: false` and says so
  in words. Independence is a deployment property. It is not created by code.
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

Patent pending.
