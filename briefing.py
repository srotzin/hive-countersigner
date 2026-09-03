"""Briefing receipts: the durable public read side of the self serve proof page.

WHY THIS LIVES HERE AND NOT ON THE VERIFIER API
The verifier API at thehiveryiq.com/v1 mints and returns. It stores nothing and
it sends cache-control no-store on every response. That is the right shape for a
verifier, and it is the wrong shape for a page that promises a reader the record
will still resolve in three days. Resolution also should not live on the same
process that mints, or the page asks the reader to trust one box twice.

This process already holds a second key, a second clock, and an append only log
on a mounted persistent disk. It was missing exactly one thing: a public read
route. That is what this module adds.

HONESTY BOUNDARY, read before quoting any of this anywhere.
  * A second key and a second clock is not an independent third party. Hive runs
    both sides today. /health reports independent: false and this module never
    contradicts it.
  * The operator signature is ML-DSA-65. The countersignature is Ed25519. Never
    describe the countersignature as post quantum.
  * A digest comparison proves a record differs from what was anchored. It does
    not prove who changed it, why, or that anything was prevented.
"""
import base64
import io
import json
import os
import re
import secrets
import threading
import time
from collections import defaultdict, deque

import segno
from flask import Response, jsonify, render_template_string, request
from markupsafe import escape

# Reuse the countersigner's own primitives so a briefing record and a pass
# record land in the same log with the same leaf construction.
import countersigner as cs

SIGNER_URL = os.environ.get("HIVE_SIGNER_URL", "https://signer.thehiveryiq.com")
PUBLIC_BASE = os.environ.get("HIVE_PUBLIC_BASE", "https://thehiveryiq.com")
STORE_DIR = os.path.join(cs.LOG_DIR, "briefing")

RECEIPT_ID_RE = re.compile(r"^r_brf_[0-9]{10}_[0-9a-f]{16}$")
MAX_ACTION_CHARS = 400
ISSUE_PER_HOUR = 40
CHECK_PER_HOUR = 200

_rl_lock = threading.Lock()
_rl = defaultdict(deque)


def _client_ip():
    fwd = request.headers.get("X-Forwarded-For", "")
    return (fwd.split(",")[0].strip() if fwd else request.remote_addr) or "unknown"


def _rate_ok(bucket, limit):
    """Fixed one hour window per client per bucket. Held in memory on purpose.

    A restart forgives the window. That is an acceptable trade for a public
    read and write path that must not depend on a database, and it is stated
    here rather than implied.
    """
    key = (bucket, _client_ip())
    now = time.time()
    with _rl_lock:
        q = _rl[key]
        while q and now - q[0] > 3600:
            q.popleft()
        if len(q) >= limit:
            return False
        q.append(now)
        return True


def _sha256_hex(text):
    import hashlib
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _shard_path(receipt_id):
    return os.path.join(STORE_DIR, receipt_id[-2:], receipt_id + ".json")


def _store(receipt):
    p = _shard_path(receipt["receipt_id"])
    os.makedirs(os.path.dirname(p), exist_ok=True)
    tmp = p + ".tmp"
    with open(tmp, "w") as f:
        json.dump(receipt, f, sort_keys=True)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, p)


def _load(receipt_id):
    if not RECEIPT_ID_RE.match(receipt_id or ""):
        return None
    try:
        with open(_shard_path(receipt_id)) as f:
            return json.load(f)
    except (OSError, ValueError):
        return None


def _operator_sign(payload_text):
    """Ask the ML-DSA signer to sign. Returns (envelope, error_string)."""
    import urllib.error
    import urllib.request
    body = json.dumps({"text": payload_text}).encode()
    req = urllib.request.Request(
        SIGNER_URL + "/sign", data=body,
        headers={"Content-Type": "application/json"}, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            d = json.loads(r.read())
    except (urllib.error.URLError, ValueError, OSError) as e:
        return None, "operator signer unreachable: %s" % type(e).__name__
    env = d.get("envelope") or {}
    sig = env.get("envelope_signature") or ""
    if not d.get("ok") or len(sig) < cs.MIN_OPERATOR_SIG:
        return None, "operator signer returned no usable signature"
    return env, None


def _countersign_local(record, op_sig, op_scheme):
    """Append to the same log the /countersign route writes, in process.

    This does not loop back over HTTP. It takes the same lock and writes the
    same leaf shape, so a briefing record is a real entry in the same chain,
    not a parallel pretend one.
    """
    record_digest = cs.h(cs.canon(record), "record")
    with cs._lock:
        log = cs.read_log()
        seq = len(log) + 1
        prev = log[-1]["leaf"] if log else cs.h(b"", "genesis")
        cs_time = time.time()
        opsig_digest = cs.h(op_sig.encode(), "opsig")
        leaf = cs.h(cs.canon({
            "seq": seq, "prev": prev, "record_digest": record_digest,
            "countersigner_time": cs_time,
            "operator_signature_digest": opsig_digest}), "leaf")
        signed_over = {
            "seq": seq,
            "record_digest": record_digest,
            "operator_signature_digest": opsig_digest,
            "operator_signature_scheme": op_scheme,
            "countersigner_time": cs_time,
            "prev_leaf": prev,
            "leaf": leaf,
        }
        sig = base64.b64encode(cs.KEY.sign(cs.canon(signed_over))).decode()
        entry = dict(signed_over)
        entry["countersignature"] = sig
        with open(cs.LOG_PATH, "a") as f:
            f.write(json.dumps(entry, sort_keys=True) + "\n")
            f.flush()
            os.fsync(f.fileno())
        log.append(entry)
        root = cs.merkle_root([e["leaf"] for e in log])
    return {
        "signed_over": signed_over,
        "signed_over_canonical": cs.canon(signed_over).decode(),
        "countersignature": sig,
        "countersignature_scheme": "Ed25519",
        "countersigner_public_key_b64": cs.PUB_B64,
        "log_root_after": root,
        "independent": False,
    }


BOUNDARY = ("This record shows what an action said at the moment it was "
            "recorded, and whether a later copy differs from it. It does not "
            "show who made a change, why, or that any change was prevented.")


def register(app):
    # ---------------------------------------------------------------- issue
    def _do_issue(action):
        """Returns (http_status, dict). Shared by the JSON and form paths."""
        if not _rate_ok("issue", ISSUE_PER_HOUR):
            return 429, {"error": "Too many records from this address in the "
                                  "last hour. Try again later."}
        if not isinstance(action, str) or not action.strip():
            return 422, {"error": "Describe the action you want receipted."}
        action = action.strip()
        if len(action) > MAX_ACTION_CHARS:
            return 422, {"error": "That description is longer than %d "
                                  "characters." % MAX_ACTION_CHARS}

        digest = _sha256_hex(action)
        rid = "r_brf_%010d_%s" % (int(time.time()), secrets.token_hex(8))
        observed_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        signed_body = {
            "receipt_type": "briefing.action",
            "schema": "r1.0.0",
            "receipt_id": rid,
            "action_text": action,
            "action_digest_sha256": digest,
            "observed_at": observed_at,
            "boundary": BOUNDARY,
        }
        env, err = _operator_sign(cs.canon(signed_body).decode())
        if err:
            return 503, {"error": err}
        op_sig = env["envelope_signature"]
        countersig = _countersign_local(signed_body, op_sig, "ml-dsa-65")
        receipt = {
            "receipt_id": rid,
            "signed_body": signed_body,
            "signed_body_canonical": cs.canon(signed_body).decode(),
            "operator_signature": {
                "scheme": env.get("sig_scheme", "ml-dsa-65"),
                "spec": "NIST FIPS 204",
                "signature": op_sig,
                "public_key": env.get("public_key"),
                "issued_at": env.get("issued_at"),
                "post_quantum": True,
            },
            "countersignature": countersig,
            "verify_url": "%s/briefing/check?id=%s" % (PUBLIC_BASE, rid),
        }
        _store(receipt)
        return 200, receipt

    @app.post("/briefing/issue")
    def briefing_issue():
        # Two content types on one route, so a visitor whose browser blocks
        # scripts can still make a receipt by plain form post and gets a whole
        # HTML page back instead of raw JSON.
        form = request.form or {}
        wants_html = bool(form) or "text/html" in (request.headers.get("Accept") or "")
        if form:
            action = form.get("action_text") or ""
        else:
            b = request.get_json(force=True, silent=True) or {}
            action = b.get("action_text")
        status, out = _do_issue(action)
        if wants_html:
            return Response(_render_issued(out), status=status,
                            mimetype="text/html")
        return jsonify(out), status

    # ------------------------------------------------------------- read back
    @app.get("/briefing/receipt/<receipt_id>")
    def briefing_receipt(receipt_id):
        r = _load(receipt_id)
        if not r:
            return jsonify({"error": "No record with that identifier.",
                            "receipt_id": receipt_id}), 404
        return jsonify(r)

    # ---------------------------------------------------------------- check
    def _do_check(receipt_id, submitted):
        """Returns (http_status, dict). Digest comparison against the anchor."""
        if not _rate_ok("check", CHECK_PER_HOUR):
            return 429, {"error": "Too many checks from this address in the last "
                                  "hour. Try again later."}
        # Order matters for the reader. An empty box is a different mistake
        # from a wrong identifier, and telling someone who submitted nothing
        # that no such record exists sends them hunting for the wrong problem.
        if not receipt_id:
            return 422, {"error": "Paste a receipt identifier to check."}
        if not RECEIPT_ID_RE.match(receipt_id):
            return 422, {"error": "That is not a receipt identifier. They look "
                                  "like r_brf_ followed by numbers and letters."}
        r = _load(receipt_id)
        if not r:
            return 404, {"error": "No record with that identifier."}
        if not isinstance(submitted, str) or not submitted.strip():
            return 422, {"error": "Supply the text you want checked."}
        submitted = submitted.strip()
        if len(submitted) > MAX_ACTION_CHARS:
            return 422, {"error": "Submitted text is longer than %d characters."
                         % MAX_ACTION_CHARS}
        anchored = r["signed_body"]["action_digest_sha256"]
        got = _sha256_hex(submitted)
        match = (got == anchored)
        checked_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        outcome = "recorded_match" if match else "recorded_mismatch"
        check_body = {
            "receipt_type": "briefing.check",
            "schema": "r1.0.0",
            "target_receipt_id": receipt_id,
            "anchored_digest_sha256": anchored,
            "submitted_digest_sha256": got,
            "outcome": outcome,
            "checked_at": checked_at,
            "boundary": BOUNDARY,
        }
        env, err = _operator_sign(cs.canon(check_body).decode())
        if err:
            # The comparison itself is already decided and does not depend on
            # the signer. Say plainly that the check result is unsigned rather
            # than failing the reader's press or pretending it was signed.
            return 200, {
                "outcome": outcome,
                "match": match,
                "target_receipt_id": receipt_id,
                "anchored_digest_sha256": anchored,
                "submitted_digest_sha256": got,
                "checked_at": checked_at,
                "signed": False,
                "signing_note": err + ". The comparison above stands on its own. "
                                      "This check result is not countersigned.",
                "boundary": BOUNDARY,
            }
        countersig = _countersign_local(check_body, env["envelope_signature"],
                                        "ml-dsa-65")
        return 200, {
            "outcome": outcome,
            "match": match,
            "target_receipt_id": receipt_id,
            "anchored_digest_sha256": anchored,
            "submitted_digest_sha256": got,
            "checked_at": checked_at,
            "signed": True,
            "signed_body": check_body,
            "signed_body_canonical": cs.canon(check_body).decode(),
            "operator_signature": {
                "scheme": env.get("sig_scheme", "ml-dsa-65"),
                "signature": env["envelope_signature"],
                "public_key": env.get("public_key"),
                "post_quantum": True,
            },
            "countersignature": countersig,
            "boundary": BOUNDARY,
        }

    @app.post("/briefing/check")
    def briefing_check():
        # One route, two content types. A blocked script still reaches this by
        # form post and gets a whole HTML page back.
        form = request.form or {}
        wants_html = bool(form) or "text/html" in (request.headers.get("Accept") or "")
        if form:
            rid = (form.get("id") or "").strip()
            txt = form.get("text") or ""
        else:
            b = request.get_json(force=True, silent=True) or {}
            rid = (b.get("id") or "").strip()
            txt = b.get("text") or ""
        status, out = _do_check(rid, txt)
        if wants_html:
            return Response(_render_verifier(rid, txt, out), status=status,
                            mimetype="text/html")
        return jsonify(out), status

    @app.get("/briefing/check")
    def briefing_check_form():
        # Arriving here by link, by code, or by pasting an identifier into the
        # form on the briefing page. Say something either way. A reader who
        # pastes a wrong identifier and gets a silent form back learns nothing.
        rid = (request.args.get("id") or "").strip()
        prefill = ""
        out = None
        status = 200
        if rid:
            if not RECEIPT_ID_RE.match(rid):
                out = {"error": "That is not a receipt identifier. They look "
                                "like r_brf_ followed by numbers and letters."}
                status = 422
            else:
                r = _load(rid)
                if r is None:
                    out = {"error": "No record with that identifier. Check for a "
                                    "missing character and try again."}
                    status = 404
                else:
                    prefill = r["signed_body"]["action_text"]
                    out = {"found": r["signed_body"]["observed_at"]}
        return Response(_render_verifier(rid, prefill, out), status=status,
                        mimetype="text/html")

    # ------------------------------------------------------------------- qr
    @app.get("/briefing/qr")
    def briefing_qr():
        rid = (request.args.get("id") or "").strip()
        if not RECEIPT_ID_RE.match(rid):
            return jsonify({"error": "Supply a valid record identifier."}), 422
        url = "%s/briefing/check?id=%s" % (PUBLIC_BASE, rid)
        q = segno.make(url, error="m")
        buf = io.BytesIO()
        q.save(buf, kind="svg", scale=5, border=2, dark="#28251d", light="#ffffff",
               svgclass=None, lineclass=None)
        resp = Response(buf.getvalue(), mimetype="image/svg+xml")
        resp.headers["Cache-Control"] = "public, max-age=86400"
        return resp

    return app


# The verifier page is served by this process so that it works with scripts
# blocked. It is plain HTML, one form, system fonts, no external request of any
# kind. Styles are inline because a stylesheet would be a second request and
# this page has to survive a locked down browser on a government laptop.
_VERIFIER_HTML = """<!DOCTYPE html>
<html lang="en"><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex">
<title>Hive public record check</title>
<style>
 :root{color-scheme:light}
 *{box-sizing:border-box}
 body{margin:0;background:#f6f7f9;color:#14171b;
   font:16px/1.6 system-ui,-apple-system,"Segoe UI",Roboto,"Helvetica Neue",Arial,sans-serif;
   padding:32px 20px 64px;-webkit-text-size-adjust:100%}
 .w{max-width:640px;margin:0 auto}
 .mk{font:700 18px/1 inherit;letter-spacing:.02em;margin:0 0 18px}
 .mk s{text-decoration:none;color:#1f68d8}
 h1{font-size:22px;letter-spacing:-.015em;margin:0 0 6px}
 p.sub{color:#626d7d;margin:0 0 28px;font-size:15px}
 label{display:block;font-size:12px;letter-spacing:.09em;text-transform:uppercase;
   color:#626d7d;margin:0 0 7px}
 input,textarea{width:100%;font:15px/1.55 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;
   color:#14171b;background:#fff;border:1px solid #dfe4ec;border-radius:8px;padding:11px 13px}
 textarea{min-height:96px;resize:vertical}
 input:focus-visible,textarea:focus-visible,button:focus-visible{outline:3px solid #2f80ff;
   outline-offset:2px}
 .f{margin:0 0 18px}
 button{font:650 15px/1 inherit;color:#fff;background:#1f68d8;border:1px solid #1f68d8;
   border-radius:10px;padding:14px 22px;cursor:pointer;
   box-shadow:0 1px 2px rgba(20,23,27,.05),0 8px 24px -16px rgba(20,23,27,.18)}
 button:hover{background:#1a58bb}
 .r{border:1px solid #dfe4ec;border-radius:10px;padding:20px 22px;margin:0 0 26px;background:#fff}
 .r.m{background:#e6f6ee;border-color:#9bd9b9;border-left:4px solid #0b6b3f}
 .r.x{background:#fdedeb;border-color:#f0b3ad;border-left:4px solid #a81f18}
 .r.e{background:#fdedeb;border-color:#f0b3ad;border-left:4px solid #a81f18}
 .v{font:700 20px/1.25 inherit;letter-spacing:.01em;margin:0 0 8px}
 .r.m .v{color:#0b6b3f}.r.x .v{color:#a81f18}.r.e .v{color:#a81f18}
 .r p{margin:0 0 8px;font-size:15px;color:#3d4653}
 .r p.pu{font-weight:600;color:#14171b}
 dl{margin:14px 0 0;font-size:13px}
 dt{color:#626d7d;margin:10px 0 2px;letter-spacing:.05em;text-transform:uppercase;font-size:11px}
 dd{margin:0;font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;
   word-break:break-all;color:#14171b}
 .qr{background:#fff;border:1px solid #dfe4ec;border-radius:10px;padding:10px;
   display:inline-block;line-height:0;margin:14px 0 0}
 .qr img{width:132px;height:132px;display:block}
 .b{border-top:1px solid #dfe4ec;margin:34px 0 0;padding:18px 0 0;color:#626d7d;font-size:13.5px}
 a{color:#1f68d8}
</style></head><body><div class="w">
<p class="mk">Hiv<s>e</s></p>
<h1>Hive public record check</h1>
<p class="sub">Paste a record identifier and the text you want checked. This page
runs without scripts and stores nothing about you.</p>
{{ result|safe }}
<form method="post" action="/briefing/check">
 <div class="f"><label for="id">Record identifier</label>
  <input id="id" name="id" value="{{ rid }}" autocomplete="off" spellcheck="false"
    placeholder="r_brf_0000000000_0000000000000000"></div>
 <div class="f"><label for="text">Text to check</label>
  <textarea id="text" name="text" spellcheck="false">{{ txt }}</textarea></div>
 <button type="submit">Check this record</button>
</form>
<p class="b">A match means the text you submitted is byte for byte the text that
was recorded. A mismatch means it is not. Neither result shows who changed
anything, why, or that a change was stopped. Records are checkable here for as
long as this service runs.</p>
</div></body></html>"""


def _render_verifier(rid, txt, out):
    block = ""
    if out is not None:
        if "found" in out:
            block = (
                '<div class="r"><p class="v" style="font-size:16px">RECORD FOUND</p>'
                '<p>Recorded at %s. The text below is what was recorded. Submit '
                'it unchanged for a match, or change it to see the other answer.'
                '</p></div>' % escape(out["found"]))
        elif "error" in out:
            block = ('<div class="r e"><p class="v">CANNOT CHECK</p><p>%s</p></div>'
                     % escape(out["error"]))
        elif out["match"]:
            block = (
                '<div class="r m"><p class="v">MATCH</p>'
                '<p>The text you submitted is identical to the text recorded '
                'under this identifier.</p>'
                '<dl><dt>Recorded digest</dt><dd>%s</dd>'
                '<dt>Submitted digest</dt><dd>%s</dd>'
                '<dt>Checked at</dt><dd>%s</dd></dl></div>'
                % (escape(out["anchored_digest_sha256"]),
                   escape(out["submitted_digest_sha256"]),
                   escape(out["checked_at"])))
        else:
            block = (
                '<div class="r x"><p class="v">MISMATCH</p>'
                '<p>The text you submitted is not the text recorded under this '
                'identifier. The recorded version is unchanged.</p>'
                '<dl><dt>Recorded digest</dt><dd>%s</dd>'
                '<dt>Submitted digest</dt><dd>%s</dd>'
                '<dt>Checked at</dt><dd>%s</dd></dl></div>'
                % (escape(out["anchored_digest_sha256"]),
                   escape(out["submitted_digest_sha256"]),
                   escape(out["checked_at"])))
    return render_template_string(_VERIFIER_HTML, rid=escape(rid or ""),
                                  txt=escape(txt or ""), result=block)


# Served when a scripts-blocked browser posts the issue form. Same shell and
# palette as the verifier so the sequence looks like one product.
_ISSUED_HTML = """<!DOCTYPE html>
<html lang="en"><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex">
<title>Record issued</title>
<style>{{ css|safe }}</style></head><body><div class="w">
<p class="mk">Hiv<s>e</s></p>
{{ body|safe }}
<p class="b">Keep the identifier above. Anyone can check this record here, free,
with no account, for as long as this service runs. A check shows whether a copy
of the text differs from what was recorded. It does not show who changed
anything, why, or that a change was stopped.</p>
</div></body></html>"""


def _shell_css():
    m = re.search(r"<style>(.*?)</style>", _VERIFIER_HTML, re.S)
    return m.group(1) if m else ""


def _render_issued(out):
    if "error" in out:
        body = ('<h1>That did not go through</h1>'
                '<div class="r e"><p class="v">NOT RECORDED</p><p>%s</p></div>'
                '<p><a href="/briefing/">Back to the four presses</a></p>'
                % escape(out["error"]))
        return render_template_string(_ISSUED_HTML, css=_shell_css(), body=body)
    sb = out["signed_body"]
    rid = out["receipt_id"]
    url = "%s/briefing/check?id=%s" % (PUBLIC_BASE, rid)
    body = (
        '<h1>Recorded and countersigned</h1>'
        '<p class="sub">This record is anchored in an append only log. Change the '
        'text on the next screen and it will not match.</p>'
        '<div class="r m"><p class="v">ANCHORED</p>'
        '<p>%s</p>'
        '<dl><dt>Record identifier</dt><dd>%s</dd>'
        '<dt>Fingerprint</dt><dd>%s</dd>'
        '<dt>Recorded at</dt><dd>%s</dd>'
        '<dt>Log position</dt><dd>%s</dd></dl></div>'
        '<h1>Check it from any device</h1>'
        '<p class="sub">Open this on a phone that has never seen this site. Same '
        'record, same answer, no account.</p>'
        '<p><a href="%s">%s</a></p>'
        '<div class="qr"><img src="/briefing/qr?id=%s" width="132" height="132"'
        ' alt="Code linking to the public verifier, loaded with this record."></div>'
        % (escape(sb["action_text"]), escape(rid),
           escape(sb["action_digest_sha256"]), escape(sb["observed_at"]),
           escape(str(out["countersignature"]["signed_over"]["seq"])),
           escape(url), escape(url), escape(rid)))
    return render_template_string(_ISSUED_HTML, css=_shell_css(), body=body)
