"""Build copy-pasteable curl commands from captured requests.

Secrets: when redact=True, values of sensitive headers (Authorization, Cookie, *token*, ...),
sensitive query params and sensitive body fields - and anything already stored as [REDACTED] -
are replaced by shell variables ($AUTHORIZATION, $COOKIE, $SESSION_TOKEN ...). The caller gets the
list of variables so it can tell the user what to `export`.
"""
from __future__ import annotations

import re
import shlex
from urllib.parse import parse_qsl, quote, urlsplit, urlunsplit

from wnm_common import (
    HOP_HEADERS, REDACTED, is_sensitive_field, is_sensitive_header, redact_post_data,
)

# Rendered placeholder marker (never appears in real data); expanded to $VAR at render time.
_PH = "\x00PH:{}\x00"
_PH_RE = re.compile(r"\x00PH:([A-Z0-9_]+)\x00")
# Header names that curl manages or that break a replay
_SKIP = HOP_HEADERS | {"accept-encoding"}


def env_name(name: str) -> str:
    n = re.sub(r"[^A-Za-z0-9]+", "_", str(name)).strip("_").upper() or "SECRET"
    return ("V_" + n) if n[0].isdigit() else n


class _Vars:
    def __init__(self):
        self.vars: dict[str, str] = {}  # VAR -> description

    def ph(self, name: str, desc: str) -> str:
        var = env_name(name)
        base, i = var, 2
        while var in self.vars and self.vars[var] != desc:
            var = f"{base}_{i}"
            i += 1
        self.vars[var] = desc
        return _PH.format(var)


def _sh(s: str) -> str:
    """Shell-quote; strings with placeholders are double-quoted so $VAR expands."""
    if not _PH_RE.search(s):
        return shlex.quote(s)
    out = []
    for i, part in enumerate(_PH_RE.split(s)):
        if i % 2:  # variable name
            out.append("${" + part + "}")
        else:
            out.append(re.sub(r'([\\"`$])', r"\\\1", part))
    return '"' + "".join(out) + '"'


def _redact_url(url: str, v: _Vars, redact: bool) -> str:
    try:
        p = urlsplit(url)
    except ValueError:
        return url
    if not p.query:
        return url
    q = parse_qsl(p.query, keep_blank_values=True)
    if not any(val == REDACTED or (redact and is_sensitive_field(k)) for k, val in q):
        return url
    parts = []
    for k, val in q:
        if val == REDACTED or (redact and is_sensitive_field(k) and val):
            parts.append(f"{quote(k, safe='[]')}={v.ph(k, f'query param {k!r}')}")
        else:
            parts.append(f"{quote(k, safe='[]')}={quote(val, safe='[]:/,')}")
    return urlunsplit((p.scheme, p.netloc, p.path, "&".join(parts), p.fragment))


_BODY_KEY_RE = re.compile(r"""["']?([A-Za-z0-9_\-]{1,64})["']?\s*[:=]\s*["']?$""")


def _redact_body(body: str, content_type: str | None, v: _Vars, redact: bool) -> str:
    if redact:
        red = redact_post_data(body, content_type) or body
        if REDACTED in red and red != body:
            body = red  # only re-serialise when something was actually redacted
    if REDACTED not in body and "%5BREDACTED%5D" not in body:
        return body
    body = body.replace("%5BREDACTED%5D", REDACTED)
    out, pos = [], 0
    for m in re.finditer(re.escape(REDACTED), body):
        before = body[pos:m.start()]
        km = _BODY_KEY_RE.search(body[max(0, m.start() - 80):m.start()])
        key = km.group(1) if km else "BODY_SECRET"
        out.append(before + v.ph(key, f"request body field {key!r}"))
        pos = m.end()
    out.append(body[pos:])
    return "".join(out)


def build_curl(method: str, url: str, headers: dict | None, body: str | None, redact: bool = True,
               compressed: bool = True, max_body: int = 200_000) -> dict:
    """Return {"args": [...], "multiline": str, "oneline": str, "env": {VAR: desc}}."""
    v = _Vars()
    method = (method or "GET").upper()
    args = ["curl", "-sS", "-X", method]
    if compressed:
        args.append("--compressed")
    hdr_args = []
    ct = None
    for k, val in (headers or {}).items():
        kl = k.lower()
        if kl.startswith(":") or kl in _SKIP:
            continue
        val = "" if val is None else str(val)
        if kl == "content-type":
            ct = val
        if val == REDACTED or REDACTED in val or (redact and is_sensitive_header(kl) and val):
            val = v.ph(kl, f"value of the {k} header")
        hdr_args.append(f"{_canon(k)}: {val}")
    args.append(_redact_url(url, v, redact))
    for h in hdr_args:
        args += ["-H", h]
    raw_idx = set()  # arg indices emitted verbatim (not shell-quoted)
    if body:
        if len(body) > max_body:
            body = body[:max_body]
            args_note = f"# NOTE: body truncated to {max_body} bytes"
        else:
            args_note = None
        if _is_binary(body):
            # binary payload (gRPC-web / protobuf): shell args cannot carry NUL bytes, so feed the exact
            # bytes through process substitution (bash) instead of --data-raw
            args += ["--data-binary", _printf_subst(body)]
            raw_idx.add(len(args) - 1)
            args_note = ((args_note + "\n") if args_note else "") + "# NOTE: binary body (protobuf/gRPC) sent via --data-binary @<(printf ...) (bash)"
        else:
            args += ["--data-raw", _redact_body(body, ct, v, redact)]
    else:
        args_note = None
    q = [_sh(a) if i and i not in raw_idx else a for i, a in enumerate(args)]
    # multiline: "curl -sS -X M [--compressed]", then URL, then one "-H ..." / "--data-raw ..." per line
    n_head = 5 if compressed else 4
    lines = [" ".join(q[:n_head]), q[n_head]]
    rest = q[n_head + 1:]
    lines += [f"{rest[j]} {rest[j + 1]}" for j in range(0, len(rest), 2)]
    multiline = " \\\n  ".join(lines)
    if args_note:
        multiline = args_note + "\n" + multiline
    return {"args": [(_PH_RE.sub(lambda m: "$" + m.group(1), a)) for a in args],
            "multiline": multiline, "oneline": " ".join(q), "env": v.vars}


def _is_binary(body) -> bool:
    if isinstance(body, bytes):
        return True
    return any((ord(ch) < 32 and ch not in "\t\n\r") for ch in body[:4096])


def _printf_subst(body) -> str:
    """`@<(printf '\\ooo...')` reproducing the exact bytes (latin-1 for str bodies that hold raw bytes)."""
    if isinstance(body, str):
        try:
            data = body.encode("latin-1")
        except UnicodeEncodeError:
            data = body.encode("utf-8")
    else:
        data = body
    esc = "".join(chr(b) if (32 <= b < 127 and chr(b) not in "\\'%") else f"\\{b:03o}" for b in data)
    return f"@<(printf '{esc}')"


def _canon(h: str) -> str:
    """Pretty header casing (HTTP/2 captures are lowercase); curl/servers are case-insensitive."""
    return "-".join(p[:1].upper() + p[1:] for p in h.split("-"))


def env_comment(env: dict) -> str:
    if not env:
        return ""
    return "\n".join(f"# export {k}='...'   # {d}" for k, d in env.items())


# ------------------------------------------------------------------ Postman (additive)

_PM_RE = _PH_RE  # same internal placeholder marker, rendered as {{VAR}} for Postman


def _pm(s: str) -> str:
    return _PM_RE.sub(lambda m: "{{" + m.group(1) + "}}", s)


def build_postman_parts(method: str, url: str, headers: dict | None, body: str | None, redact: bool = True,
                        token_var: str = "token") -> dict:
    """Pieces for a Postman v2.1 request, reusing the curl redaction rules.

    Returns {"headers": [{key, value}], "url": str (secrets as {{VAR}}), "body": str | None,
    "binary_body": bool, "vars": {VAR: desc}}. The Authorization header value becomes {{token_var}}."""
    v = _Vars()
    hdrs = []
    ct = None
    for k, val in (headers or {}).items():
        kl = k.lower()
        if kl.startswith(":") or kl in _SKIP or kl in ("content-length", "cookie"):
            continue
        val = "" if val is None else str(val)
        if kl == "content-type":
            ct = val
        if kl == "authorization" and (val == REDACTED or REDACTED in val or (redact and val)):
            val = "{{" + token_var + "}}"
        elif val == REDACTED or REDACTED in val or (redact and is_sensitive_header(kl) and val):
            val = _pm(v.ph(kl, f"value of the {k} header"))
        hdrs.append({"key": _canon(k), "value": val})
    out_url = _pm(_redact_url(url, v, redact))
    out_body, binary = None, False
    if body:
        if _is_binary(body):
            binary = True
        else:
            out_body = _pm(_redact_body(body, ct, v, redact))
    return {"headers": hdrs, "url": out_url, "body": out_body, "binary_body": binary, "vars": v.vars,
            "content_type": ct}
