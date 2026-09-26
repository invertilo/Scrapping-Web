"""Shared helpers for web-network-mapper (redaction, cookies, paths, JSON utils)."""
from __future__ import annotations

import json
import re
from pathlib import Path
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

REDACTED = "[REDACTED]"

# Header names whose *values* are secrets. Matched case-insensitively as substrings.
_SENSITIVE_HEADER_PARTS = (
    "authorization", "cookie", "token", "secret", "session", "api-key", "apikey",
    "api_key", "csrf", "xsrf", "signature", "password", "auth", "x-amz-security",
    "x-goog-api-key", "private",
)
# Query / form / JSON field names whose values are secrets.
_SENSITIVE_FIELD_RE = re.compile(
    r"(token|secret|passw(or)?d|passwd|apikey|api[_-]?key|signature|session|auth|credential|private[_-]?key)"
    r"|^(key|sig|pwd|sid|access[_-]?key|client[_-]?secret|code_verifier)$",
    re.I,
)

# Headers that never make sense to replay verbatim.
HOP_HEADERS = {
    "host", "connection", "content-length", "accept-encoding", "keep-alive",
    "transfer-encoding", "upgrade", "te", "trailer", "proxy-connection",
    "if-none-match", "if-modified-since", "priority",
}


def is_sensitive_header(name: str) -> bool:
    n = name.lower()
    if n.startswith(":"):  # HTTP/2 pseudo headers (:authority, :path ...)
        return False
    return any(p in n for p in _SENSITIVE_HEADER_PARTS)


def is_sensitive_field(name: str) -> bool:
    return bool(_SENSITIVE_FIELD_RE.search(str(name)))


def lower_headers(h: dict | None) -> dict:
    out: dict = {}
    for k, v in (h or {}).items():
        out[str(k).lower()] = v
    return out


def redact_headers(h: dict | None) -> dict:
    return {k: (REDACTED if is_sensitive_header(k) and v not in (None, "") else v) for k, v in (h or {}).items()}


def redact_url(url: str) -> str:
    try:
        parts = urlsplit(url)
    except ValueError:
        return url
    if not parts.query:
        return url
    q = parse_qsl(parts.query, keep_blank_values=True)
    if not any(is_sensitive_field(k) for k, _ in q):
        return url
    q2 = [(k, REDACTED if is_sensitive_field(k) else v) for k, v in q]
    return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(q2, safe="[]"), parts.fragment))


def redact_obj(o):
    if isinstance(o, dict):
        return {k: (REDACTED if is_sensitive_field(k) and isinstance(v, (str, int, float)) else redact_obj(v)) for k, v in o.items()}
    if isinstance(o, list):
        return [redact_obj(x) for x in o]
    return o


def redact_post_data(data: str | None, content_type: str | None = None) -> str | None:
    if not data:
        return data
    ct = (content_type or "").lower()
    s = data.strip()
    if s[:1] in "[{":
        try:
            obj = json.loads(s)
            red = redact_obj(obj)
            # keep the original bytes unless something was actually redacted
            return data if red == obj else json.dumps(red, ensure_ascii=False)
        except ValueError:
            pass
    if "x-www-form-urlencoded" in ct or ("=" in s and not re.search(r"\s", s)):
        q = parse_qsl(s, keep_blank_values=True)
        if q:
            return urlencode([(k, REDACTED if is_sensitive_field(k) else v) for k, v in q], safe="[]")
    return data


# ---------------------------------------------------------------- cookies

_SAMESITE = {"no_restriction": "None", "none": "None", "lax": "Lax", "strict": "Strict"}


def _norm_cookie(c: dict) -> dict | None:
    if not c.get("name"):
        return None
    out = {"name": str(c["name"]), "value": str(c.get("value", ""))}
    if c.get("url"):
        out["url"] = c["url"]
    else:
        dom = c.get("domain") or c.get("host")
        if not dom:
            return None
        out["domain"] = dom
        out["path"] = c.get("path") or "/"
    exp = c.get("expires", c.get("expirationDate", c.get("expiry")))
    if isinstance(exp, (int, float)) and exp > 0:
        out["expires"] = float(exp)
    if "httpOnly" in c:
        out["httpOnly"] = bool(c["httpOnly"])
    if "secure" in c:
        out["secure"] = bool(c["secure"])
    ss = c.get("sameSite")
    if isinstance(ss, str) and ss.lower() in _SAMESITE:
        out["sameSite"] = _SAMESITE[ss.lower()]
        if out["sameSite"] == "None" and not out.get("secure"):
            del out["sameSite"]  # Chrome rejects SameSite=None without Secure
    return out


def load_cookies_file(path: str | Path) -> list[dict]:
    """Load cookies from JSON (list, {cookies:[...]}, Playwright storage state, browser-extension
    export) or Netscape cookies.txt. Returns Playwright add_cookies()-compatible dicts."""
    text = Path(path).read_text(encoding="utf-8", errors="replace")
    st = text.strip()
    cookies: list[dict] = []
    if st[:1] in "[{":
        data = json.loads(st)
        raw = data.get("cookies", []) if isinstance(data, dict) else data
        for c in raw:
            n = _norm_cookie(c)
            if n:
                cookies.append(n)
        return cookies
    for line in text.splitlines():
        http_only = False
        if line.startswith("#HttpOnly_"):
            line = line[len("#HttpOnly_"):]
            http_only = True
        if not line.strip() or line.startswith("#"):
            continue
        parts = line.split("\t")
        if len(parts) < 7:
            continue
        domain, _flag, cpath, secure, expiry, name, value = parts[:7]
        c = {"name": name, "value": value, "domain": domain, "path": cpath or "/",
             "secure": secure.upper() == "TRUE", "httpOnly": http_only}
        try:
            if int(expiry) > 0:
                c["expires"] = float(expiry)
        except ValueError:
            pass
        cookies.append(c)
    return cookies


def parse_header_args(items: list[str] | None) -> dict:
    out = {}
    for it in items or []:
        if ":" not in it:
            raise SystemExit(f"--header expects 'Name: value', got {it!r}")
        k, v = it.split(":", 1)
        out[k.strip()] = v.strip()
    return out


# ---------------------------------------------------------------- misc

def slugify(s: str, maxlen: int = 80) -> str:
    s = re.sub(r"[^A-Za-z0-9._-]+", "_", s).strip("_.")
    return (s or "x")[:maxlen]


def get_path(obj, path: str | None):
    """Dot path getter: 'data.items', 'a.0.b', 'quotes[*]'. '' or '$' returns obj."""
    if path in (None, "", "$"):
        return obj
    path = path.lstrip("$").lstrip(".")
    cur = obj
    for part in re.split(r"\.", path.replace("[*]", "").replace("[", ".").replace("]", "")):
        if part == "":
            continue
        if isinstance(cur, dict):
            cur = cur.get(part)
        elif isinstance(cur, list) and part.lstrip("-").isdigit():
            i = int(part)
            cur = cur[i] if -len(cur) <= i < len(cur) else None
        else:
            return None
        if cur is None:
            return None
    return cur


def set_path(obj, path: str, value):
    parts = [p for p in path.lstrip("$").lstrip(".").split(".") if p]
    cur = obj
    for p in parts[:-1]:
        if isinstance(cur, list):
            cur = cur[int(p)]
        else:
            cur = cur.setdefault(p, {})
    last = parts[-1]
    if isinstance(cur, list):
        cur[int(last)] = value
    else:
        cur[last] = value


XSSI_PREFIXES = (")]}'", ")]}',", "for(;;);", "while(1);", "while (1);")


def loads_lenient(text: str):
    """Parse JSON, tolerating XSSI prefixes and NDJSON. Raises ValueError if not JSON."""
    t = text.lstrip("\ufeff").strip()
    for p in XSSI_PREFIXES:
        if t.startswith(p):
            t = t[len(p):].lstrip()
    try:
        return json.loads(t)
    except ValueError:
        lines = [ln for ln in t.splitlines() if ln.strip()]
        if len(lines) > 1 and all(ln.lstrip()[:1] in "[{" for ln in lines[:5]):
            return [json.loads(ln) for ln in lines[:500]]
        raise


# ------------------------------------------------------------------ safety: restricted domains
import os as _os
from urllib.parse import urlsplit as _urlsplit

# Government TLDs / second-level suffixes blocked by default to prevent misuse of this tool
# against official government sites. Override only with explicit authorization via env var.
RESTRICTED_SUFFIXES = (
    ".gob.bo", ".gob", ".gov", ".gov.bo", ".gob.mx", ".gob.pe", ".gob.ar", ".gob.cl",
    ".gob.gt", ".gob.hn", ".gob.sv", ".gob.pa", ".gob.do", ".gob.ec", ".gob.ve", ".gob.es",
    ".gov.br", ".gov.co", ".gov.uk", ".gov.au", ".gov.ca", ".gouv.fr", ".go.jp", ".go.kr",
    ".gc.ca", ".mil", ".mil.bo",
)


def is_restricted_host(host: str) -> bool:
    if not host:
        return False
    h = host.lower().rstrip(".")
    labels = h.split(".")
    # match .gov / .gob / .mil as a TLD or as a second-level label (e.g. gob.bo, gov.co)
    for suf in RESTRICTED_SUFFIXES:
        s = suf.lstrip(".")
        if h == s or h.endswith("." + s):
            return True
    if labels and labels[-1] in ("gov", "gob", "mil"):
        return True
    if len(labels) >= 2 and labels[-2] in ("gov", "gob", "mil"):
        return True
    return False


def guard_target(target: str, kind: str = "url"):
    """Refuse to operate on government (.gob/.gov/.mil) domains unless the user explicitly
    authorizes it by setting WNM_ALLOW_RESTRICTED=1. Prevents misuse of the tool.
    `target` may be a URL or a bare hostname/domain."""
    if kind == "url":
        host = (_urlsplit(target).hostname or "")
    else:
        host = target.strip().lower()
        if "//" in host:
            host = _urlsplit(host).hostname or host
    if is_restricted_host(host) and _os.environ.get("WNM_ALLOW_RESTRICTED", "").strip() not in ("1", "true", "yes"):
        raise SystemExit(
            f"BLOQUEADO: '{host}' es un dominio gubernamental (.gob/.gov/.mil). "
            "Esta skill no opera sobre sitios de gobierno para evitar un uso indebido. "
            "Si tienes autorización explícita para probar este sitio, ejecuta de nuevo con "
            "la variable de entorno WNM_ALLOW_RESTRICTED=1."
        )
