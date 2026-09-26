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


# ------------------------------------------------------------------ body decoding + type detection

# Compressed-stream magic bytes.
_GZIP_MAGIC = b"\x1f\x8b"
_ZSTD_MAGIC = b"\x28\xb5\x2f\xfd"


def _maybe_import(name):
    try:
        return __import__(name)
    except Exception:
        return None


def _looks_like_text(b: bytes) -> bool:
    head = b[:512]
    if not head:
        return True
    try:
        head.decode("utf-8")
    except UnicodeDecodeError:
        try:  # a multibyte char may be cut at the 512-byte boundary
            head[:-3].decode("utf-8")
        except UnicodeDecodeError:
            return False
    ctrl = sum(1 for c in head if c < 9 or 13 < c < 32)
    return ctrl <= len(head) * 0.02


def decode_body_bytes(raw: bytes, content_encoding: str | None = None) -> bytes:
    """Transparently decompress a response body (gzip / deflate / brotli / zstd).

    Uses the Content-Encoding header when present, and also sniffs magic bytes so a body saved
    raw (compressed on disk) is still decoded. Best-effort: returns the original bytes on any
    failure so callers never crash. brotli needs the `brotli` package, zstd needs `zstandard`
    (both listed in requirements.txt)."""
    if not raw:
        return raw
    enc = (content_encoding or "").lower()
    encs = [e.strip() for e in enc.split(",") if e.strip()]

    def _try_gzip(b):
        import gzip
        return gzip.decompress(b)

    def _try_deflate(b):
        import zlib
        try:
            return zlib.decompress(b)
        except Exception:
            return zlib.decompress(b, -zlib.MAX_WBITS)

    def _try_brotli(b):
        brotli = _maybe_import("brotli")
        if brotli is None:
            raise RuntimeError("brotli not installed")
        return brotli.decompress(b)

    def _try_zstd(b):
        zstd = _maybe_import("zstandard")
        if zstd is None:
            raise RuntimeError("zstandard not installed")
        return zstd.ZstdDecompressor().decompress(b)

    # 1) honour explicit Content-Encoding (apply in reverse order for chained encodings), unless the
    #    bytes already look like decoded text (CDP's getResponseBody normally returns decoded data)
    if _looks_like_text(raw):
        encs = []
    for e in reversed(encs):
        try:
            if e in ("gzip", "x-gzip"):
                raw = _try_gzip(raw)
            elif e == "deflate":
                raw = _try_deflate(raw)
            elif e == "br":
                raw = _try_brotli(raw)
            elif e == "zstd":
                raw = _try_zstd(raw)
        except Exception:
            pass  # leave as-is; sniffing below may still help
    # 2) sniff magic bytes (covers bodies stored raw without a decoded header)
    for _ in range(3):  # unwrap up to a few nested layers
        try:
            if raw[:2] == _GZIP_MAGIC:
                raw = _try_gzip(raw)
                continue
            if raw[:4] == _ZSTD_MAGIC:
                raw = _try_zstd(raw)
                continue
        except Exception:
            pass
        break
    return raw


# gRPC / protobuf content-type detection.
_GRPC_CT_RE = re.compile(r"application/grpc(-web)?(\+proto|\+json)?", re.I)
_PROTOBUF_CT_RE = re.compile(r"application/(x-)?protobuf|application/vnd\..*\+?protobuf|application/octet-stream\+proto", re.I)


def detect_body_kind(content_type: str | None, raw: bytes | None = None) -> str | None:
    """Classify a body beyond JSON. Returns one of 'grpc', 'protobuf', or None.

    Detection is by content-type first (application/grpc*, grpc-web, application/x-protobuf),
    which is authoritative; we do not attempt to actually decode the binary payload."""
    ct = (content_type or "").lower()
    if _GRPC_CT_RE.search(ct) or "grpc-web" in ct:
        return "grpc"
    if _PROTOBUF_CT_RE.search(ct):
        return "protobuf"
    return None


# ------------------------------------------------------------------ anti-bot / challenge fingerprinting

def _cookie_names(cookies) -> list[str]:
    """Accept a list of cookie dicts, a list of names, or a raw Cookie/Set-Cookie header string."""
    names = []
    if not cookies:
        return names
    if isinstance(cookies, str):
        for part in re.split(r"[;\n]", cookies):
            part = part.strip()
            if not part:
                continue
            nm = part.split("=", 1)[0].strip()
            if nm:
                names.append(nm)
        return names
    for c in cookies:
        if isinstance(c, dict):
            nm = c.get("name") or c.get("Name")
            if nm:
                names.append(str(nm))
        elif isinstance(c, str):
            names.append(c.split("=", 1)[0].strip())
    return names


# Each rule: vendor, human strategy, and detectors over (headers, body, cookie names).
_ANTI_BOT_RULES = [
    {
        "vendor": "Cloudflare",
        "url_substr": ["challenges.cloudflare.com", "/cdn-cgi/challenge-platform"],
        "header_substr": [("server", "cloudflare"), ("cf-ray", ""), ("cf-mitigated", ""), ("cf-chl-bypass", "")],
        "cookies": ["__cf_bm", "cf_clearance", "__cfwaituntil", "__cfruid"],
        "body_substr": ["challenges.cloudflare.com/turnstile", "cf-turnstile", "/cdn-cgi/challenge-platform", "cf_chl_opt", "window._cf_chl"],
        "strategy": "Cloudflare (Turnstile / JS challenge). Usar navegador headed con UA real, resolver el desafío como humano y reutilizar la cookie cf_clearance/__cf_bm en la misma sesión (mismo IP y UA).",
    },
    {
        "vendor": "hCaptcha",
        "url_substr": ["hcaptcha.com"],
        "header_substr": [],
        "cookies": [],
        "body_substr": ["hcaptcha.com/1/api.js", "js.hcaptcha.com", "h-captcha", "data-hcaptcha-sitekey"],
        "strategy": "hCaptcha. Requiere que un humano resuelva el captcha en modo headed; capturar el token h-captcha-response y enviarlo antes de que caduque.",
    },
    {
        "vendor": "reCAPTCHA",
        "url_substr": ["google.com/recaptcha", "gstatic.com/recaptcha", "recaptcha.net"],
        "header_substr": [],
        "cookies": [],
        "body_substr": ["google.com/recaptcha", "gstatic.com/recaptcha", "www.recaptcha.net", "g-recaptcha", "grecaptcha.execute"],
        "strategy": "Google reCAPTCHA. Resolver con un humano en modo headed (v2) o vigilar el score (v3); pasar el g-recaptcha-response en el envío.",
    },
    {
        "vendor": "Akamai Bot Manager",
        "url_substr": ["akamaihd.net/", "/akam/"],
        "header_substr": [("server", "akamaighost"), ("x-akamai", "")],
        "cookies": ["_abck", "ak_bmsc", "bm_sz", "bm_sv", "bm_mi"],
        "body_substr": ["akamaihd.net", "/akam/", "bazadebezolkohpepadr"],
        "strategy": "Akamai Bot Manager. Genera sensor data desde JS; usar navegador real (headed) con la misma sesión y UA; difícil de automatizar sin ejecutar su script de sensor.",
    },
    {
        "vendor": "PerimeterX / HUMAN",
        "url_substr": ["px-cdn.net", "perimeterx.net", "px-cloud.net"],
        "header_substr": [("x-px", "")],
        "cookies": ["_px", "_px2", "_px3", "_pxhd", "_pxvid", "pxcts"],
        "body_substr": ["px-cdn", "perimeterx.net", "client.perimeterx.net", "captcha.px-cdn", "_pxAppId"],
        "strategy": "PerimeterX/HUMAN. Ejecuta JS de fingerprinting; usar navegador headed real, resolver el PX captcha si aparece y conservar las cookies _px* en la sesión.",
    },
    {
        "vendor": "DataDome",
        "url_substr": ["datadome.co", "captcha-delivery.com"],
        "header_substr": [("x-datadome", ""), ("x-dd-b", "")],
        "cookies": ["datadome"],
        "body_substr": ["datadome", "js.datadome.co", "geo.captcha-delivery.com", "captcha-delivery.com"],
        "strategy": "DataDome. Puede mostrar captcha de captcha-delivery.com; usar navegador headed real, resolver el captcha y mantener la cookie datadome con el mismo UA/IP.",
    },
    {
        "vendor": "Imperva / Incapsula",
        "url_substr": ["_incapsula_resource"],
        "header_substr": [("x-iinfo", ""), ("x-cdn", "incapsula")],
        "cookies": ["incap_ses", "visid_incap", "nlbi_"],
        "body_substr": ["_Incapsula_Resource", "incapsula.com", "/_Incapsula_"],
        "strategy": "Imperva/Incapsula. Reto JS/cookie; usar navegador real headed y conservar las cookies incap_ses/visid_incap en la sesión.",
    },
]


def detect_anti_bot(headers=None, body=None, cookies=None, status: int | None = None,
                    url: str | None = None) -> list[dict]:
    """Detect anti-bot / challenge technology from a page's headers, body and cookies.

    Shared by analyze.py (over captured requests) and recon.py (over a freshly fetched page).
    Returns a list of {vendor, evidence: [..], active, strategy}. `active` is True when a real
    challenge was seen (challenge script/body, challenge cookie or a 403/429/503), False when only
    passive signals were seen (e.g. Cloudflare as a plain CDN). Never raises: bad input yields [].
    `status` (optional) is the HTTP status code of the response; `url` (optional) is the request URL
    (a request to e.g. challenges.cloudflare.com or hcaptcha.com is itself evidence).
    `headers` may be a dict (case-insensitive keys are handled). `cookies` may be cookie dicts,
    names, or a raw Cookie/Set-Cookie header string. `body` is the (decoded) response text."""
    try:
        hdrs = {}
        for k, v in (headers or {}).items():
            hdrs[str(k).lower()] = "" if v is None else str(v)
        body_l = (body or "")
        if not isinstance(body_l, str):
            try:
                body_l = body_l.decode("utf-8", "replace")
            except Exception:
                body_l = str(body_l)
        body_l = body_l.lower()
        # cookies may be explicit, or read from headers (set-cookie / cookie)
        cnames = _cookie_names(cookies)
        for hk in ("set-cookie", "cookie"):
            if hk in hdrs:
                cnames += _cookie_names(hdrs[hk])
        cnames_l = [c.lower() for c in cnames]
        url_l = (url or "").lower()
        try:
            status = int(status or hdrs.get(":status") or 0) or None
        except Exception:
            status = None

        out = []
        for rule in _ANTI_BOT_RULES:
            evidence = []
            for hname, hval in rule["header_substr"]:
                if hname in hdrs and (hval == "" or hval in hdrs[hname].lower()):
                    hv_clean = " / ".join(x.strip() for x in hdrs[hname].splitlines() if x.strip())
                    ev = f"header {hname}" + (f": {hv_clean[:60]}" if hv_clean else "")
                    evidence.append(ev)
            for ck in rule["cookies"]:
                if any(cn == ck.lower() or cn.startswith(ck.lower()) for cn in cnames_l):
                    evidence.append(f"cookie {ck}")
            for bs in rule["body_substr"]:
                if bs.lower() in body_l:
                    evidence.append(f"body:{bs}")
            for us in rule.get("url_substr", []):
                if url_l and us in url_l:
                    evidence.append(f"url:{us}")
            if evidence:
                active = any(e.startswith(("body:", "cookie ", "url:")) for e in evidence) or status in (403, 429, 503) \
                    or "cf-mitigated" in hdrs
                if rule["vendor"] == "Cloudflare" and all(e.startswith("cookie __cfruid") or e.startswith("header")
                                                          for e in evidence) and status not in (403, 429, 503) \
                        and "cf-mitigated" not in hdrs:
                    active = False
                strategy = rule["strategy"] if active else (
                    f"{rule['vendor']} presente (señales pasivas, sin desafío observado). Normalmente basta con "
                    "UA real y ritmo moderado; si aparece un 403/503 o un captcha, pasar a navegador headed + humano.")
                out.append({"vendor": rule["vendor"], "evidence": sorted(set(evidence))[:8],
                            "active": bool(active), "strategy": strategy})

        # self-hosted captcha (image/JSF/PHP captcha served by the site itself, no third-party vendor)
        if not any(o["vendor"] in ("hCaptcha", "reCAPTCHA", "Cloudflare") for o in out):
            ev = []
            path_l = url_l.split("?", 1)[0]
            if re.search(r"captcha[^/]*\.(png|jpe?g|gif|bmp|webp|svg)$|/captcha(image|img)?(\.(php|aspx?|jsp|jsf|do))?$|"
                         r"/(jcaptcha|simplecaptcha|kaptcha|securimage)", path_l):
                ev.append(f"url:{path_l.rsplit('/', 1)[-1][:60]}")
            if re.search(r"javax\.faces\.resource/captcha/", url_l):
                ev.append("url:PrimeFaces captcha.js")
            if re.search(r"<img[^>]+(src|id|alt)=[\"'][^\"']*captcha", body_l):
                ev.append("body:<img captcha>")
            if re.search(r"<input[^>]+name=[\"'][^\"']*(captcha|codigo_?seguridad)[^\"']*[\"']", body_l):
                ev.append("body:campo de captcha en formulario")
            if ev:
                out.append({"vendor": "Captcha propio (servidor)", "evidence": ev, "active": True,
                            "strategy": "Captcha de imagen servido por el propio sitio. Un humano debe verlo y teclear el "
                                        "texto (flow.sh pausa en ese paso); mantener la misma sesión/cookie en la que se "
                                        "descargó la imagen. No se evade ni se resuelve automáticamente."})

        # generic JS challenge: 403/503 with a small HTML body that isn't a known vendor
        if status in (403, 429, 503) and not out and ("<html" in body_l or not body_l):
            hint = "Posible desafío JS genérico (403/503 con HTML de reto). Reintentar en navegador headed real con UA/idioma normales y sesión persistente."
            if re.search(r"challenge|captcha|verify you are|checking your browser|just a moment|access denied|robot", body_l):
                out.append({"vendor": "Desafío JS genérico", "evidence": [f"status {status}", "body: HTML de reto"],
                            "active": True, "strategy": hint})
        return out
    except Exception:
        return []


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


# ------------------------------------------------------------------ session / captcha cache
# Reusable cache of a resolved browser session (Playwright storage_state: cookies + localStorage),
# one JSON file per domain, so a human does not have to repeat login/captcha on every run.
# Location: $WNM_SESSION_CACHE_DIR if set, else ~/.cache/wnm/sessions/ (dir 0700, files 0600).
# It lives OUTSIDE the tool dir on purpose so it never ends up in the tool zip / shared runs.
# TTL: $WNM_SESSION_TTL (seconds, or with suffix s/m/h/d, e.g. "12h"); default 24h.
# The files contain live secrets (cookie values). Only summaries (counts, cookie *names*, age)
# are meant to be logged or written to run_meta.json; never print the storage_state itself.
import time as _time
from datetime import datetime as _datetime

SESSION_CACHE_VERSION = 1
SESSION_TTL_DEFAULT = 24 * 3600


def session_ttl() -> int:
    """TTL in seconds from WNM_SESSION_TTL ('86400', '90m', '12h', '2d'). Bad values -> default."""
    raw = (_os.environ.get("WNM_SESSION_TTL") or "").strip().lower()
    if not raw:
        return SESSION_TTL_DEFAULT
    try:
        mult = {"s": 1, "m": 60, "h": 3600, "d": 86400}.get(raw[-1])
        val = float(raw[:-1]) * mult if mult else float(raw)
        return int(val) if val > 0 else SESSION_TTL_DEFAULT
    except Exception:
        return SESSION_TTL_DEFAULT


def session_domain(target: str) -> str:
    """Cache key for a URL or host: lowercase hostname without port and without a leading 'www.'."""
    t = (target or "").strip().lower()
    try:
        host = (_urlsplit(t).hostname or "") if "//" in t else t.split("/")[0].split(":")[0]
    except Exception:
        host = t
    host = host.rstrip(".")
    return host[4:] if host.startswith("www.") else host


def session_cache_dir(create: bool = True) -> Path:
    env = (_os.environ.get("WNM_SESSION_CACHE_DIR") or "").strip()
    d = Path(env).expanduser() if env else Path.home() / ".cache" / "wnm" / "sessions"
    if create:
        try:
            d.mkdir(parents=True, exist_ok=True)
            _os.chmod(d, 0o700)
        except Exception:
            pass
    return d


def session_cache_path(domain: str) -> Path:
    return session_cache_dir(create=False) / f"{slugify(session_domain(domain), 120)}.json"


def session_summary(storage_state) -> dict:
    """Secret-free summary of a storage_state (counts + cookie names only)."""
    try:
        st = storage_state or {}
        cookies = st.get("cookies") or []
        origins = st.get("origins") or []
        return {"cookies": len(cookies),
                "cookie_names": sorted({str(c.get("name")) for c in cookies if isinstance(c, dict)})[:40],
                "origins": len(origins),
                "local_storage_keys": sum(len(o.get("localStorage") or []) for o in origins if isinstance(o, dict))}
    except Exception:
        return {"cookies": 0, "cookie_names": [], "origins": 0, "local_storage_keys": 0}


def _drop_expired_cookies(st: dict, now: float) -> tuple[dict, int]:
    cookies = st.get("cookies") or []
    keep = [c for c in cookies if not (isinstance(c, dict) and isinstance(c.get("expires"), (int, float))
                                       and 0 < c["expires"] < now)]
    out = dict(st)
    out["cookies"] = keep
    out.setdefault("origins", [])
    return out, len(cookies) - len(keep)


def save_session(domain: str, storage_state: dict, extra: dict | None = None) -> dict:
    """Persist a storage_state for `domain` (atomic write, chmod 600). Never raises.
    Returns a secret-free info dict: {ok, path, saved_at, saved_iso, summary} or {ok: False, error}."""
    try:
        if not isinstance(storage_state, dict):
            raise ValueError("storage_state debe ser un dict")
        dom = session_domain(domain)
        if not dom:
            raise ValueError("dominio vacío")
        session_cache_dir(create=True)
        path = session_cache_path(dom)
        now = _time.time()
        doc = {"version": SESSION_CACHE_VERSION, "domain": dom, "saved_at": now,
               "saved_iso": _datetime.fromtimestamp(now).astimezone().isoformat(timespec="seconds"),
               "summary": session_summary(storage_state), "extra": extra or {},
               "storage_state": storage_state}
        tmp = path.with_name(f".{path.name}.{_os.getpid()}.tmp")
        fd = _os.open(str(tmp), _os.O_WRONLY | _os.O_CREAT | _os.O_TRUNC, 0o600)
        with _os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(doc, f, ensure_ascii=False)
        _os.replace(tmp, path)
        try:
            _os.chmod(path, 0o600)
        except Exception:
            pass
        return {"ok": True, "path": str(path), "saved_at": now, "saved_iso": doc["saved_iso"],
                "summary": doc["summary"]}
    except Exception as e:
        return {"ok": False, "error": f"{type(e).__name__}: {str(e)[:200]}"}


def load_session(domain: str, ttl: int | None = None) -> dict:
    """Load the cached session for `domain`. Never raises.
    Returns {status, path, ttl_s, age_s?, saved_iso?, storage_state?, summary?, extra?, expired_cookies_dropped?, error?}
    status: 'hit' | 'miss' (no file) | 'expired' (older than TTL) | 'corrupt' | 'empty' (no usable cookies/storage).
    Only when status == 'hit' is `storage_state` present (dict usable as Playwright new_context(storage_state=...))."""
    ttl = session_ttl() if ttl is None else int(ttl)
    info: dict = {"status": "miss", "ttl_s": ttl}
    try:
        path = session_cache_path(domain)
        info["path"] = str(path)
        if not path.exists():
            return info
        try:
            doc = json.loads(path.read_text(encoding="utf-8"))
            st = doc.get("storage_state")
            saved_at = float(doc.get("saved_at"))
            if not isinstance(st, dict):
                raise ValueError("storage_state ausente")
        except Exception as e:
            info.update(status="corrupt", error=f"{type(e).__name__}: {str(e)[:160]}")
            return info
        now = _time.time()
        info["age_s"] = int(max(0, now - saved_at))
        info["saved_iso"] = doc.get("saved_iso")
        if ttl > 0 and now - saved_at > ttl:
            info["status"] = "expired"
            return info
        st, dropped = _drop_expired_cookies(st, now)
        if dropped:
            info["expired_cookies_dropped"] = dropped
        summ = session_summary(st)
        if not summ["cookies"] and not summ["local_storage_keys"]:
            info["status"] = "empty"
            return info
        info.update(status="hit", storage_state=st, summary=summ, extra=doc.get("extra") or {})
        return info
    except Exception as e:
        info.update(status="corrupt", error=f"{type(e).__name__}: {str(e)[:160]}")
        return info


def delete_session(domain: str) -> bool:
    """Remove the cached session file for `domain` (e.g. after it proved invalid). Never raises."""
    try:
        p = session_cache_path(domain)
        if p.exists():
            p.unlink()
            return True
    except Exception:
        pass
    return False


# ------------------------------------------------------------------ SSE parsing
def parse_sse(text: str, max_events: int = 1000, max_data: int = 65536) -> tuple[list[dict], str]:
    """Parse a text/event-stream chunk into events. Returns (events, leftover_incomplete_text).
    Each event: {"event": str ("message" if absent), "data": str, "id": str|None, "retry": int|None}.
    Comment lines (':') are ignored. Feed leftover back with the next chunk for streaming use."""
    events: list[dict] = []
    if not text:
        return events, ""
    t = text.replace("\r\n", "\n").replace("\r", "\n")
    blocks = t.split("\n\n")
    leftover = blocks.pop()  # last piece is incomplete unless text ended with a blank line
    for blk in blocks:
        if len(events) >= max_events:
            break
        ev = {"event": "message", "data": [], "id": None, "retry": None}
        seen = False
        for line in blk.split("\n"):
            if not line or line.startswith(":"):
                continue
            field, _, val = line.partition(":")
            if val.startswith(" "):
                val = val[1:]
            if field == "data":
                ev["data"].append(val)
                seen = True
            elif field == "event":
                ev["event"] = val or "message"
                seen = True
            elif field == "id":
                ev["id"] = val
                seen = True
            elif field == "retry":
                try:
                    ev["retry"] = int(val)
                    seen = True
                except ValueError:
                    pass
        if seen:
            data = "\n".join(ev["data"])
            ev["data"] = data[:max_data]
            if len(data) > max_data:
                ev["truncated"] = True
            events.append(ev)
    return events, leftover
