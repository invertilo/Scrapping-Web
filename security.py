#!/usr/bin/env python3
"""security.py - modulo de testing de seguridad para web-network-mapper.

Lee el api_map.json (+ bodies/ + network.har) que produce analyze.py y ejecuta:

  PARTE A - ANALISIS PASIVO (siempre corre, NO envia requests):
    - Scan de secretos/fugas (API keys, tokens, JWT, AWS/Google, claves privadas, PII).
    - Analisis de JWT (header/payload sin verificar firma; alg:none, exp, claims sensibles).
    - Scorecard de headers de seguridad + flags de cookies (por respuesta observada en el HAR).
    - Matriz de autenticacion (que endpoints exigen que token/rol) para detectar huecos.
    - Superficie GraphQL (introspeccion / batching).

  PARTE B - PRUEBAS ACTIVAS (solo con --authorized / --i-have-permission):
    1. Headers ausentes / manipulados (sin auth, minimo, auth basura, token expirado).
    2. Request incompleto (quitar params requeridos uno a uno).
    3. IDOR / BOLA de bajo impacto (ids vecinos en endpoints DETAIL; NUNCA sobre .gob).
    4. Sondeo de inyeccion (deteccion, NO explotacion: comillas, 1=1, valor largo, XSS, SSTI).
    5. Robustez de sesion / CORS (reuso de token, OPTIONS/Allow, Origin arbitrario).
    6. Rate-limit real (rafaga pequena y acotada para ver si frena con 429).

Uso:  security.py <run_dir | api_map.json> [--authorized] [opciones]

Etica: modulo para objetivos AUTORIZADOS (pentest propio / bug bounty con permiso).
Todas las pruebas ACTIVAS estan APAGADAS por defecto. Solo GET/HEAD/OPTIONS o el MISMO
metodo observado, con payloads de SONDEO (nunca exploits, nunca datos destructivos).
Respeta el bloqueo de dominios .gob/.gov/.mil (guard_target) y un cap duro de requests.
"""
from __future__ import annotations

import argparse
import base64
import json
import os
import re
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import parse_qsl, urlencode, urljoin, urlsplit, urlunsplit

sys.path.insert(0, str(Path(__file__).resolve().parent))

# ---- reuso de helpers del tool (con fallbacks si cambia la interfaz) ---------------------
REDACTED = "[REDACTED]"
try:
    from wnm_common import REDACTED as _RED  # noqa
    REDACTED = _RED
except Exception:
    pass

try:
    from wnm_common import guard_target
except Exception:  # fallback minimo si no se puede importar
    def guard_target(target, kind="url"):  # type: ignore
        host = (urlsplit(target).hostname or target).lower()
        labels = host.split(".")
        restricted = (labels and labels[-1] in ("gov", "gob", "mil")) or \
                     (len(labels) >= 2 and labels[-2] in ("gov", "gob", "mil"))
        if restricted and os.environ.get("WNM_ALLOW_RESTRICTED", "").strip() not in ("1", "true", "yes"):
            raise SystemExit("BLOQUEADO: '%s' es un dominio gubernamental (.gob/.gov/.mil). "
                             "Ejecuta con WNM_ALLOW_RESTRICTED=1 solo si tienes autorizacion." % host)

try:
    from wnm_common import is_restricted_host
except Exception:
    def is_restricted_host(host):  # type: ignore
        if not host:
            return False
        labels = host.lower().rstrip(".").split(".")
        return (labels[-1] in ("gov", "gob", "mil")) or (len(labels) >= 2 and labels[-2] in ("gov", "gob", "mil"))

try:
    from wnm_common import redact_url
except Exception:
    def redact_url(url):  # type: ignore
        return url

try:
    from wnm_common import is_sensitive_header, is_sensitive_field
except Exception:
    def is_sensitive_header(name):  # type: ignore
        return bool(re.search(r"authorization|cookie|token|secret|session|api[-_]?key|auth", name, re.I))
    def is_sensitive_field(name):  # type: ignore
        return bool(re.search(r"token|secret|passw|apikey|api[-_]?key|session|auth|credential", str(name), re.I))

try:
    from wnm_common import HOP_HEADERS
except Exception:
    HOP_HEADERS = {"host", "connection", "content-length", "accept-encoding", "keep-alive",
                   "transfer-encoding", "upgrade", "te", "trailer", "proxy-connection"}

try:
    from wnm_common import get_path as _get_path
except Exception:
    def _get_path(obj, path):  # type: ignore
        cur = obj
        for part in (path or "").split("."):
            if isinstance(cur, dict) and part in cur:
                cur = cur[part]
            else:
                return None
        return cur

# httpx si esta en el venv; si no, urllib de stdlib
try:
    import httpx  # noqa
    _HAVE_HTTPX = True
except Exception:
    _HAVE_HTTPX = False
    import urllib.request
    import urllib.error


# ================================================================= util / severidades
SEVERITIES = ["Critico", "Alto", "Medio", "Bajo", "Info"]
SEV_RANK = {s: i for i, s in enumerate(SEVERITIES)}


def log(*a):
    print(*a, file=sys.stderr, flush=True)


def mask(value, keep_start=4, keep_end=2):
    """Enmascara un secreto dejando solo puntas, para evidencia redactada."""
    if value is None:
        return ""
    s = str(value)
    if len(s) <= keep_start + keep_end:
        return "*" * len(s)
    return "%s\u2026%s (len=%d)" % (s[:keep_start], s[-keep_end:], len(s))


def now_utc():
    return time.time()


# ================================================================= carga del api_map
def load_map(p):
    path = Path(p)
    if path.is_dir():
        run_dir = path
        mp = path / "api_map.json"
    else:
        mp = path
        run_dir = path.parent
    if not mp.exists():
        raise SystemExit("no se encontro api_map.json en %r" % p)
    data = json.loads(mp.read_text())
    return data, run_dir


def endpoint_host(m):
    for e in m.get("endpoints", []):
        h = e.get("host")
        if h:
            return h
    return urlsplit(m.get("start_url") or "").netloc


def iter_bodies(run_dir):
    """Genera (nombre_relativo, texto, tipo) de bodies/ capturados."""
    bd = run_dir / "bodies"
    if not bd.is_dir():
        return
    for f in sorted(bd.iterdir()):
        if not f.is_file():
            continue
        try:
            raw = f.read_bytes()
        except Exception:
            continue
        try:
            text = raw.decode("utf-8", "replace")
        except Exception:
            continue
        ext = f.suffix.lower().lstrip(".")
        kind = {"json": "json", "html": "html", "js": "js", "txt": "txt"}.get(ext, ext or "bin")
        yield (f.name, text, kind)


# ================================================================= modelo de hallazgos
class Findings:
    def __init__(self):
        self.items = []
        self._n = 0

    def add(self, title, severity, category, recommendation, endpoint=None, evidence=None, extra=None):
        assert severity in SEV_RANK, severity
        self._n += 1
        fid = "WNM-%s-%03d" % (category[:4].upper(), self._n)
        f = {
            "id": fid, "title": title, "severity": severity, "category": category,
            "endpoint": endpoint, "evidence": evidence if evidence is not None else [],
            "recommendation": recommendation,
        }
        if extra:
            f.update(extra)
        self.items.append(f)
        return f

    def counts(self):
        c = {s: 0 for s in SEVERITIES}
        for f in self.items:
            c[f["severity"]] += 1
        return c

    def sorted(self):
        return sorted(self.items, key=lambda f: (SEV_RANK[f["severity"]], f["category"], f["id"]))


# ================================================================= PARTE A: PASIVO
AKIA_RE = re.compile(r"\bAKIA[0-9A-Z]{16}\b")
GOOGLE_API_RE = re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b")
SLACK_RE = re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b")
STRIPE_RE = re.compile(r"\bsk_live_[0-9A-Za-z]{16,}\b")
GITHUB_PAT_RE = re.compile(r"\bghp_[0-9A-Za-z]{36}\b")
PRIVATE_KEY_RE = re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----")
GENERIC_SECRET_RE = re.compile(
    r"(?P<key>(?:api[_-]?key|apikey|secret|access[_-]?token|auth[_-]?token|client[_-]?secret|password|passwd|pwd))"
    r"['\"]?\s*[:=]\s*['\"](?P<val>[A-Za-z0-9_\-\.]{12,})['\"]", re.I)
JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{0,}")
EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b")
PHONE_RE = re.compile(r"(?<!\d)(?:\+?\d{1,3}[ .\-]?)?(?:\(\d{2,4}\)[ .\-]?)?\d{3}[ .\-]?\d{3,4}(?:[ .\-]?\d{2,4})?(?!\d)")


def scan_secrets(run_dir, F):
    named = [
        ("clave de acceso AWS", AKIA_RE, "Critico"),
        ("API key de Google", GOOGLE_API_RE, "Alto"),
        ("token de Slack", SLACK_RE, "Alto"),
        ("clave secreta de Stripe", STRIPE_RE, "Critico"),
        ("token de acceso personal de GitHub", GITHUB_PAT_RE, "Critico"),
        ("clave privada (PEM)", PRIVATE_KEY_RE, "Critico"),
    ]
    for fname, text, kind in iter_bodies(run_dir):
        low_ctx = "bodies/%s (%s)" % (fname, kind)
        for label, rx, sev in named:
            for mt in rx.finditer(text):
                val = mt.group(0)
                F.add(title="Posible %s expuesta en respuesta capturada" % label, severity=sev,
                      category="secrets", endpoint=None,
                      evidence=["archivo: %s" % low_ctx, "coincidencia: %s" % mask(val, 6, 4)],
                      recommendation="Rotar la credencial de inmediato y dejar de exponerla en respuestas/JS del "
                                     "cliente. Las credenciales de servidor nunca deben viajar al navegador.")
        for mt in GENERIC_SECRET_RE.finditer(text):
            key = mt.group("key")
            val = mt.group("val")
            if val.lower() in ("null", "none", "example", "changeme", "your_api_key", "xxxxxxxxxxxx"):
                continue
            sev = "Alto" if kind in ("js", "html") else "Medio"
            F.add(title="Posible secreto embebido (`%s`) en %s" % (key, kind), severity=sev, category="secrets",
                  evidence=["archivo: %s" % low_ctx, "%s = %s" % (key, mask(val, 4, 3))],
                  recommendation="No incrustar secretos en el cliente (JS/HTML) ni devolverlos en respuestas. "
                                 "Mover a variables de entorno/servidor y rotar el valor si es real.")
        emails = set(EMAIL_RE.findall(text))
        emails = {e for e in emails if not e.lower().endswith((".png", ".jpg", ".svg", ".js", ".css"))}
        if len(emails) >= 5:
            sample = ", ".join(mask(e, 3, 6) for e in list(emails)[:5])
            F.add(title="PII sobre-expuesta: %d correos en una sola respuesta" % len(emails), severity="Medio",
                  category="secrets", evidence=["archivo: %s" % low_ctx, "muestra: %s" % sample],
                  recommendation="Revisar si el endpoint debe exponer datos personales en masa. Aplicar "
                                 "minimizacion de datos, control de acceso y paginacion con autorizacion.")
        phones = set(p for p in PHONE_RE.findall(text) if len(re.sub(r"\D", "", p)) >= 8)
        if len(phones) >= 8:
            F.add(title="PII sobre-expuesta: ~%d numeros telefonicos en una sola respuesta" % len(phones),
                  severity="Bajo", category="secrets",
                  evidence=["archivo: %s" % low_ctx, "muestra: %s" % ", ".join(mask(p, 3, 2) for p in list(phones)[:4])],
                  recommendation="Confirmar que la exposicion masiva de telefonos es intencional y autorizada; "
                                 "de lo contrario minimizar y proteger tras autenticacion.")


def b64url_decode(s):
    s = s + "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s.encode())


def decode_jwt(tok):
    parts = tok.split(".")
    if len(parts) < 2:
        return None
    try:
        header = json.loads(b64url_decode(parts[0]))
        payload = json.loads(b64url_decode(parts[1]))
    except Exception:
        return None
    if not isinstance(header, dict) or not isinstance(payload, dict):
        return None
    return {"header": header, "payload": payload, "has_sig": len(parts) >= 3 and bool(parts[2])}


SENSITIVE_CLAIM_RE = re.compile(r"(email|phone|password|passwd|ssn|dni|address|role|admin|scope|perm|is_admin|credit)", re.I)


def scan_jwts(run_dir, F):
    seen = set()
    for fname, text, kind in iter_bodies(run_dir):
        for mt in JWT_RE.finditer(text):
            tok = mt.group(0)
            dec = decode_jwt(tok)
            if not dec:
                continue
            sig = tok.split(".")[0] + "." + tok.split(".")[1]
            if sig in seen:
                continue
            seen.add(sig)
            hdr, pl = dec["header"], dec["payload"]
            alg = str(hdr.get("alg", "")).lower()
            claims_view = {k: (mask(str(v), 3, 2) if SENSITIVE_CLAIM_RE.search(k) else v) for k, v in pl.items()}
            ev = ["archivo: bodies/%s" % fname, "header: %s" % json.dumps(hdr, ensure_ascii=False),
                  "payload (claims): %s" % json.dumps(claims_view, ensure_ascii=False)[:600]]
            if alg in ("none", ""):
                F.add(title="JWT con alg:none (firma no verificable / falsificable)", severity="Critico",
                      category="jwt", evidence=ev,
                      recommendation="Rechazar tokens con alg:none. Exigir un algoritmo fuerte (RS256/ES256) y "
                                     "verificar SIEMPRE la firma en el servidor.")
            elif alg in ("hs256", "hs384", "hs512"):
                F.add(title="JWT firmado con HMAC (%s) - riesgo si la clave es debil/compartida" % alg.upper(),
                      severity="Bajo", category="jwt", evidence=ev,
                      recommendation="Verificar que la clave HMAC sea larga y secreta; considerar algoritmos "
                                     "asimetricos (RS256/ES256) para que el cliente no pueda re-firmar tokens.")
            exp = pl.get("exp")
            iat = pl.get("iat") or pl.get("nbf")
            if isinstance(exp, (int, float)):
                if exp < now_utc():
                    F.add(title="JWT capturado ya vencido (exp en el pasado)", severity="Info", category="jwt",
                          evidence=ev + ["exp: %s" % datetime.fromtimestamp(exp, timezone.utc).isoformat()],
                          recommendation="Confirmar que el servidor rechaza tokens vencidos (ver prueba activa de sesion).")
                elif isinstance(iat, (int, float)) and (exp - iat) > 7 * 86400:
                    dias = round((exp - iat) / 86400, 1)
                    F.add(title="JWT de muy larga duracion (%s dias)" % dias, severity="Medio", category="jwt",
                          evidence=ev + ["vida util: %s dias" % dias],
                          recommendation="Acortar la expiracion de los access tokens y usar refresh tokens revocables. "
                                         "Tokens de larga vida amplian el impacto de un robo.")
            sens = [k for k in pl if SENSITIVE_CLAIM_RE.search(k)]
            if sens:
                F.add(title="JWT con claims sensibles (%s)" % ", ".join(sens[:6]), severity="Bajo", category="jwt",
                      evidence=ev,
                      recommendation="Evitar poner PII o datos de autorizacion en claims legibles (el payload JWT es "
                                     "solo base64, no cifrado). Minimizar claims.")


SEC_HEADERS = {
    "strict-transport-security": ("HSTS (Strict-Transport-Security)", "Medio",
        "Anadir `Strict-Transport-Security: max-age=63072000; includeSubDomains; preload` en HTTPS."),
    "content-security-policy": ("CSP (Content-Security-Policy)", "Medio",
        "Definir una CSP restrictiva para mitigar XSS e inyeccion de contenido."),
    "x-frame-options": ("X-Frame-Options", "Bajo",
        "Anadir `X-Frame-Options: DENY` (o `frame-ancestors` en la CSP) para evitar clickjacking."),
    "x-content-type-options": ("X-Content-Type-Options", "Bajo",
        "Anadir `X-Content-Type-Options: nosniff` para evitar MIME sniffing."),
    "referrer-policy": ("Referrer-Policy", "Bajo",
        "Anadir `Referrer-Policy: no-referrer` o `strict-origin-when-cross-origin`."),
    "permissions-policy": ("Permissions-Policy", "Info",
        "Anadir `Permissions-Policy` para limitar APIs del navegador (camara, microfono, geoloc, etc.)."),
}


def _har_entries(run_dir):
    har = run_dir / "network.har"
    if not har.exists():
        return []
    try:
        data = json.loads(har.read_text())
        return data.get("log", {}).get("entries", []) or []
    except Exception:
        return []


def _headers_dict(hlist):
    out = {}
    setcookies = []
    for h in hlist or []:
        n = str(h.get("name", "")).lower()
        v = h.get("value", "")
        if n == "set-cookie":
            setcookies.append(v)
        else:
            out[n] = v
    return out, setcookies


def header_scorecard(run_dir, m, F, target_host):
    from collections import Counter
    entries = _har_entries(run_dir)
    origins = {}
    for e in entries:
        req = e.get("request", {})
        resp = e.get("response", {})
        url = req.get("url", "")
        p = urlsplit(url)
        if p.scheme not in ("http", "https"):
            continue
        if target_host and p.hostname and p.hostname not in target_host and target_host not in p.hostname:
            continue
        status = resp.get("status", 0)
        if not (200 <= status < 400):
            continue
        hdrs, setcookies = _headers_dict(resp.get("headers"))
        origin = "%s://%s" % (p.scheme, p.netloc)
        o = origins.setdefault(origin, {"count": 0, "missing": Counter(), "cookies": [], "sample": url, "scheme": p.scheme})
        o["count"] += 1
        for hk in SEC_HEADERS:
            if hk not in hdrs:
                o["missing"][hk] += 1
        for sc in setcookies:
            o["cookies"].append(sc)
    for origin, o in origins.items():
        total = o["count"]
        for hk, cnt in o["missing"].items():
            if cnt == total and total > 0:
                label, sev, rec = SEC_HEADERS[hk]
                if hk == "strict-transport-security" and o["scheme"] != "https":
                    continue
                F.add(title="Falta header de seguridad %s en %s" % (label, origin), severity=sev, category="headers",
                      endpoint=origin,
                      evidence=["ausente en %d/%d respuestas observadas" % (cnt, total), "ejemplo: %s" % redact_url(o["sample"])],
                      recommendation=rec)
        seen_cookie = set()
        for sc in o["cookies"]:
            name = sc.split("=", 1)[0].strip()
            if name in seen_cookie:
                continue
            seen_cookie.add(name)
            low = sc.lower()
            probs = []
            if o["scheme"] == "https" and "secure" not in low:
                probs.append("sin Secure")
            if "httponly" not in low:
                probs.append("sin HttpOnly")
            if "samesite" not in low:
                probs.append("sin SameSite")
            if probs:
                session_like = bool(re.search(r"sess|sid|token|auth|jwt|login|csrf", name, re.I))
                sev = "Medio" if session_like and ("sin HttpOnly" in probs or "sin Secure" in probs) else "Bajo"
                F.add(title="Cookie `%s` con flags debiles (%s)" % (name, ", ".join(probs)), severity=sev,
                      category="headers", endpoint=origin,
                      evidence=["Set-Cookie: %s=...; %s" % (name, "; ".join(sc.split(";")[1:]).strip()[:120])],
                      recommendation="Marcar cookies de sesion como `HttpOnly; Secure; SameSite=Lax` (o Strict). "
                                     "HttpOnly evita robo via XSS, Secure exige HTTPS, SameSite mitiga CSRF.")
    return origins


def auth_matrix(m, F):
    af = m.get("auth_flow") or {}
    eps = m.get("endpoints", [])
    has_auth_scheme = bool(af.get("tokens")) or any(e.get("auth_headers") for e in eps)
    for e in eps:
        if e.get("likely_tracking") or e.get("third_party"):
            continue
        is_data = e.get("likely_data_endpoint") or (e.get("response_records") or {}).get("length")
        auth_h = [h for h in (e.get("auth_headers") or []) if h]
        consumes = e.get("consumes_token") or []
        if is_data and has_auth_scheme and not auth_h and not consumes:
            F.add(title="Endpoint de datos sin token/credencial observada: %s" % e.get("key"), severity="Medio",
                  category="auth_matrix", endpoint=e.get("key"),
                  evidence=["rol: %s" % e.get("role"),
                            "registros por respuesta: %s" % (e.get("response_records") or {}).get("length"),
                            "el sitio usa autenticacion en otros endpoints pero este no envio credencial"],
                  recommendation="Confirmar si este endpoint deberia exigir autenticacion/autorizacion. Si expone "
                                 "datos sensibles, protegerlo (ver prueba activa de bypass de auth).")
    if af.get("tokens"):
        rows = []
        for t in af["tokens"][:20]:
            consumers = ", ".join(c.get("endpoint", "") for c in (t.get("consumed_by") or [])[:5])
            rows.append("%s:%s -> consumido por [%s]" % (t.get("kind"), t.get("name"), consumers or "\u2014"))
        F.add(title="Matriz de autenticacion (tokens emitidos/consumidos)", severity="Info", category="auth_matrix",
              evidence=rows,
              recommendation="Revisar que cada endpoint sensible consuma el token/rol correcto y que no existan "
                             "endpoints equivalentes sin proteccion.")


def graphql_surface(run_dir, m, F):
    gql_eps = [e for e in m.get("endpoints", []) if "GRAPHQL" in (e.get("flags") or []) or e.get("graphql_operations")]
    if not gql_eps:
        return
    introspection = False
    batching = False
    ev_intro = []
    for fname, text, kind in iter_bodies(run_dir):
        if "__schema" in text or "IntrospectionQuery" in text or "__type" in text:
            introspection = True
            ev_intro.append("bodies/%s: contiene __schema/IntrospectionQuery" % fname)
        st = text.strip()
        if st.startswith("[") and ("query" in text or "operationName" in text):
            batching = True
    ep_key = gql_eps[0].get("key")
    if introspection:
        F.add(title="GraphQL: introspeccion aparentemente habilitada", severity="Medio", category="graphql",
              endpoint=ep_key, evidence=ev_intro[:5],
              recommendation="Deshabilitar la introspeccion en produccion para reducir la superficie expuesta del esquema.")
    else:
        ops = ", ".join(sorted({op for e in gql_eps for op in (e.get("graphql_operations") or [])}))
        F.add(title="GraphQL detectado (verificar introspeccion/limites en produccion)", severity="Info",
              category="graphql", endpoint=ep_key, evidence=["operaciones: %s" % ops[:200]],
              recommendation="Confirmar que la introspeccion este deshabilitada y que haya limites de "
                             "profundidad/costo y control de batching en produccion.")
    if batching:
        F.add(title="GraphQL: parece aceptar batching de operaciones (array de queries)", severity="Bajo",
              category="graphql", endpoint=ep_key,
              evidence=["se observo un cuerpo con un array de operaciones GraphQL"],
              recommendation="Limitar o deshabilitar el batching para evitar amplificacion de ataques (fuerza bruta, DoS).")


# ================================================================= PARTE B: ACTIVO
SQL_ERR_RE = re.compile(
    r"(you have an error in your sql syntax|warning: mysql|unclosed quotation mark|quoted string not properly terminated|"
    r"pg::|psql:|postgresql|sqlite3?\.|sqlstate\[|ora-\d{4,5}|odbc|native client|syntax error at or near|"
    r"pdoexception|sql syntax|mysql_fetch|mysqli|supplied argument is not a valid mysql)", re.I)
STACK_RE = re.compile(
    r"(traceback \(most recent call last\)|at [\w.$]+\([\w.]+\.java:\d+\)|exception in thread|"
    r"stack ?trace|goroutine \d+ \[|node:internal/|\bat Object\.<anonymous>|System\.\w+Exception|"
    r"werkzeug|django\.core|\.py\", line \d+)", re.I)
AUTH_ERR_RE = re.compile(r"(unauthori[sz]ed|forbidden|not authenticated|invalid token|access denied|login required|"
                         r"permission denied|no autorizado|acceso denegado|inicia sesion)", re.I)

XSS_MARKER = "grokz9x1"
INJECTION_PAYLOADS = [
    ("sqli_squote", "'"),
    ("sqli_dquote", '"'),
    ("sqli_tautology", "1=1"),
    ("long_value", "A" * 2048),
    ("xss_reflect", "<%s>" % XSS_MARKER),
    ("ssti_dollar", "${7*7}"),
    ("ssti_brace", "{{7*7}}"),
]


class Budget:
    def __init__(self, maxreq):
        self.max = maxreq
        self.used = 0
        self.exhausted_reported = False

    def allow(self):
        return self.used < self.max

    def spend(self):
        self.used += 1


class Ctx:
    def __init__(self, args, run_dir, m, F):
        self.args = args
        self.run_dir = run_dir
        self.m = m
        self.F = F
        self.budget = Budget(args.max_requests)
        self.target_host = endpoint_host(m)
        self.client = None
        self.rate_limited = False
        self.notes = []
        self._cur_observed = None
        if _HAVE_HTTPX:
            self.client = httpx.Client(follow_redirects=True, timeout=args.timeout,
                                       verify=not args.insecure, http2=False)

    def close(self):
        if self.client is not None:
            try:
                self.client.close()
            except Exception:
                pass


def build_base_request(ep, args):
    rp = ep.get("replay") or {}
    url = rp.get("url") or (ep.get("example_urls") or [None])[0]
    method = (rp.get("method") or ep.get("method") or "GET").upper()
    headers = {}
    for k, v in (rp.get("headers") or {}).items():
        kl = k.lower()
        if kl.startswith(":") or kl in HOP_HEADERS:
            continue
        if v == REDACTED or (isinstance(v, str) and REDACTED in v):
            continue
        headers[k] = v
    for h in (args.header or []):
        if ":" in h:
            k, v = h.split(":", 1)
            headers[k.strip()] = v.strip()
    if args.user_agent:
        headers["User-Agent"] = args.user_agent
    body = rp.get("post_data")
    if method in ("GET", "HEAD") and not rp.get("post_data"):
        body = None
    return {"url": url, "method": method, "headers": headers, "body": body}


def auth_header_keys(ep, headers):
    return [k for k in headers if is_sensitive_header(k)]


def http_send(ctx, method, url, headers, body=None):
    """Envia UN request. Devuelve dict con status/size/text/headers/error. Respeta guard y budget."""
    if not ctx.budget.allow():
        if not ctx.budget.exhausted_reported:
            ctx.budget.exhausted_reported = True
            log("[!] Cap de requests alcanzado (%d); se detienen las pruebas activas restantes." % ctx.budget.max)
        return {"skipped": "budget"}
    guard_target(url, "url")
    method = method.upper()
    if method in ("PUT", "PATCH", "DELETE") and method != (ctx._cur_observed or method):
        return {"skipped": "metodo destructivo bloqueado"}
    ctx.budget.spend()
    t0 = time.time()
    try:
        if _HAVE_HTTPX:
            content = body.encode("utf-8") if isinstance(body, str) else body
            r = ctx.client.request(method, url, headers=headers, content=content)
            text = r.text
            rh = {k.lower(): v for k, v in r.headers.items()}
            status = r.status_code
        else:
            data = body.encode("utf-8") if isinstance(body, str) else body
            req = urllib.request.Request(url, data=data, method=method, headers=headers)
            try:
                resp = urllib.request.urlopen(req, timeout=ctx.args.timeout)
                raw = resp.read()
                status = resp.status
                rh = {k.lower(): v for k, v in resp.headers.items()}
            except urllib.error.HTTPError as he:
                raw = he.read()
                status = he.code
                rh = {k.lower(): v for k, v in (he.headers or {}).items()}
            text = raw.decode("utf-8", "replace")
        out = {"status": status, "text": text, "size": len(text), "headers": rh,
               "elapsed_ms": round((time.time() - t0) * 1000, 1)}
    except Exception as e:
        out = {"error": str(e)[:200], "elapsed_ms": round((time.time() - t0) * 1000, 1)}
    if out.get("status") == 429:
        ctx.rate_limited = True
        ra = out["headers"].get("retry-after") if out.get("headers") else None
        wait = 2.0
        try:
            if ra:
                wait = min(30.0, float(ra))
        except Exception:
            pass
        log("[i] 429 recibido; respetando rate-limit (espera %.1fs)" % wait)
        time.sleep(wait)
    else:
        if ctx.args.delay > 0:
            time.sleep(ctx.args.delay)
    return out


def load_captured_baseline(ctx, ep):
    sb = ep.get("sample_bodies") or []
    text = ""
    if sb:
        p = ctx.run_dir / sb[0]
        if p.exists():
            try:
                text = p.read_text("utf-8", "replace")
            except Exception:
                text = ""
    statuses = ep.get("statuses") or {}
    good_status = 200
    for s in statuses:
        try:
            if 200 <= int(s) < 300:
                good_status = int(s)
                break
        except Exception:
            pass
    return {"status": good_status, "text": text, "size": len(text), "source": "captura"}


def returns_data(resp, baseline):
    if not resp or resp.get("error") or resp.get("skipped"):
        return False
    st = resp.get("status", 0)
    if not (200 <= st < 300):
        return False
    txt = resp.get("text", "") or ""
    if AUTH_ERR_RE.search(txt[:2000]):
        return False
    base_size = baseline.get("size") or 0
    if base_size and resp.get("size", 0) < max(16, 0.4 * base_size):
        return False
    if resp.get("size", 0) < 8:
        return False
    return True


def redacted_req(method, url, headers):
    safe_h = {k: (mask(str(v)) if is_sensitive_header(k) else v) for k, v in (headers or {}).items()}
    return ["%s %s" % (method, redact_url(url)), "headers: %s" % json.dumps(safe_h, ensure_ascii=False)[:400]]


def _set_query(url, updates, drop=()):
    p = urlsplit(url)
    q = [(k, v) for k, v in parse_qsl(p.query, keep_blank_values=True) if k not in updates and k not in drop]
    q += [(k, str(v)) for k, v in updates.items()]
    return urlunsplit((p.scheme, p.netloc, p.path, urlencode(q), p.fragment))


# ---- Prueba 1: headers ausentes / manipulados ----
def test_auth_headers(ctx, ep, base, baseline):
    ctx._cur_observed = base["method"]
    akeys = auth_header_keys(ep, base["headers"])
    observed_auth = akeys or (ep.get("auth_headers") or [])
    if not observed_auth:
        return
    method, url = base["method"], base["url"]
    h_noauth = {k: v for k, v in base["headers"].items() if not is_sensitive_header(k)}
    r = http_send(ctx, method, url, h_noauth, base["body"])
    if returns_data(r, baseline):
        ctx.F.add(title="Autorizacion rota: %s devuelve datos SIN header de auth" % ep.get("key"), severity="Critico",
                  category="auth_bypass", endpoint=ep.get("key"),
                  evidence=redacted_req(method, url, h_noauth) +
                           ["respuesta: status=%s size=%s (baseline %s)" % (r["status"], r["size"], baseline["size"]),
                            "quitados: %s" % ", ".join(observed_auth)],
                  recommendation="Exigir autenticacion/autorizacion en el servidor para este endpoint. Nunca confiar "
                                 "solo en que el cliente envie el token.")
    h_min = {k: v for k, v in base["headers"].items() if k.lower() in ("user-agent", "accept", "content-type")}
    r = http_send(ctx, method, url, h_min, base["body"])
    if returns_data(r, baseline):
        ctx.F.add(title="%s devuelve datos con headers minimos (sin auth ni contexto)" % ep.get("key"), severity="Alto",
                  category="auth_bypass", endpoint=ep.get("key"),
                  evidence=redacted_req(method, url, h_min) + ["respuesta: status=%s size=%s" % (r["status"], r["size"])],
                  recommendation="Validar autenticacion y no depender de headers de contexto (Referer, X-Requested-With).")
    h_bogus = dict(base["headers"])
    for k in list(h_bogus):
        if k.lower() == "authorization":
            h_bogus[k] = "Bearer not_a_real_token_00000"
        elif k.lower() == "cookie":
            h_bogus[k] = "session=invalid_garbage_value"
        elif is_sensitive_header(k):
            h_bogus[k] = "invalid_value_123"
    r = http_send(ctx, method, url, h_bogus, base["body"])
    if returns_data(r, baseline):
        ctx.F.add(title="%s devuelve datos con credencial INVALIDA/basura" % ep.get("key"), severity="Critico",
                  category="auth_bypass", endpoint=ep.get("key"),
                  evidence=redacted_req(method, url, h_bogus) + ["respuesta: status=%s size=%s" % (r["status"], r["size"])],
                  recommendation="El servidor debe rechazar tokens/cookies invalidos con 401/403. Aparentemente no valida.")
    if any(k.lower() == "authorization" for k in base["headers"]):
        expired = _make_expired_jwt()
        h_exp = dict(base["headers"])
        for k in list(h_exp):
            if k.lower() == "authorization":
                h_exp[k] = "Bearer %s" % expired
        r = http_send(ctx, method, url, h_exp, base["body"])
        if returns_data(r, baseline):
            ctx.F.add(title="%s acepta un JWT EXPIRADO/invalido" % ep.get("key"), severity="Alto",
                      category="auth_bypass", endpoint=ep.get("key"),
                      evidence=redacted_req(method, url, h_exp) + ["respuesta: status=%s size=%s" % (r["status"], r["size"])],
                      recommendation="Verificar exp y firma del JWT en el servidor; rechazar tokens vencidos.")


def _make_expired_jwt():
    hdr = base64.urlsafe_b64encode(json.dumps({"alg": "HS256", "typ": "JWT"}).encode()).rstrip(b"=").decode()
    pl = base64.urlsafe_b64encode(json.dumps({"sub": "test", "exp": int(now_utc()) - 86400}).encode()).rstrip(b"=").decode()
    return "%s.%s.invalidsignature" % (hdr, pl)


# ---- Prueba 2: request incompleto ----
def test_incomplete(ctx, ep, base, baseline):
    ctx._cur_observed = base["method"]
    method, url = base["method"], base["url"]
    qparams = list((ep.get("query_params") or {}).keys())
    tested = 0
    for name in qparams:
        if tested >= 6 or not ctx.budget.allow():
            break
        new_url = _set_query(url, {}, drop=(name,))
        if new_url == url:
            continue
        tested += 1
        r = http_send(ctx, method, new_url, base["headers"], base["body"])
        if returns_data(r, baseline):
            ctx.F.add(title="Validacion laxa: %s responde igual sin el parametro `%s`" % (ep.get("key"), name),
                      severity="Bajo", category="input_validation", endpoint=ep.get("key"),
                      evidence=["quitado query param: %s" % name] + redacted_req(method, new_url, base["headers"]) +
                               ["respuesta: status=%s size=%s (baseline %s)" % (r["status"], r["size"], baseline["size"])],
                      recommendation="Validar la presencia y el tipo de parametros requeridos; evitar valores por "
                                     "defecto que expongan datos amplios cuando falta un filtro.")
    rb = ep.get("request_body") or {}
    if method not in ("GET", "HEAD") and rb.get("kind") == "json" and base.get("body"):
        try:
            obj = json.loads(base["body"])
        except Exception:
            obj = None
        if isinstance(obj, dict):
            for name in list(obj.keys())[:4]:
                if not ctx.budget.allow():
                    break
                mut = {k: v for k, v in obj.items() if k != name}
                r = http_send(ctx, method, url, base["headers"], json.dumps(mut))
                if returns_data(r, baseline):
                    ctx.F.add(title="Validacion laxa: %s responde sin el campo de body `%s`" % (ep.get("key"), name),
                              severity="Bajo", category="input_validation", endpoint=ep.get("key"),
                              evidence=["quitado campo body: %s" % name, "respuesta: status=%s size=%s" % (r["status"], r["size"])],
                              recommendation="Validar campos requeridos del cuerpo en el servidor.")


# ---- Prueba 3: IDOR / BOLA ----
UUID_RE = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")


def _find_ids(ep, url):
    out = []
    p = urlsplit(url)
    segs = [s for s in p.path.split("/") if s]
    for i, s in enumerate(segs):
        if re.fullmatch(r"\d+", s) or UUID_RE.match(s):
            out.append(("path", i, s))
    for k, v in parse_qsl(p.query, keep_blank_values=True):
        if re.fullmatch(r"\d+", v) or UUID_RE.match(v):
            if re.search(r"id$|^id$|uuid|guid|user|account|order|doc", k, re.I) or re.fullmatch(r"\d+", v):
                out.append(("query", k, v))
    return out


def _replace_path_seg(url, idx, newval):
    p = urlsplit(url)
    segs = p.path.split("/")
    count = -1
    for pos, s in enumerate(segs):
        if s:
            count += 1
            if count == idx:
                segs[pos] = str(newval)
                break
    return urlunsplit((p.scheme, p.netloc, "/".join(segs), p.query, p.fragment))


def _neighbors(value, ep):
    vals = []
    if re.fullmatch(r"\d+", value):
        n = int(value)
        for cand in (n - 1, n + 1):
            if cand >= 0:
                vals.append(str(cand))
    for u in (ep.get("example_urls") or []):
        for _loc, _k, v in _find_ids(ep, u):
            if v != value and v not in vals:
                vals.append(v)
    return vals[:4]


def test_idor(ctx, ep, base, baseline):
    method, url = base["method"], base["url"]
    if method not in ("GET", "HEAD"):
        return
    host = urlsplit(url).hostname or ""
    if is_restricted_host(host):
        ctx.notes.append("IDOR omitido en dominio restringido: %s" % host)
        return
    ctx._cur_observed = method
    ids = _find_ids(ep, url)
    if not ids:
        return
    tried = 0
    for loc, key, value in ids:
        if tried >= ctx.args.max_idor or not ctx.budget.allow():
            break
        for nb in _neighbors(value, ep):
            if tried >= ctx.args.max_idor or not ctx.budget.allow():
                break
            tried += 1
            if loc == "path":
                new_url = _replace_path_seg(url, key, nb)
            else:
                new_url = _set_query(url, {key: nb})
            r = http_send(ctx, method, new_url, base["headers"], base["body"])
            if returns_data(r, baseline) and _looks_different_object(r.get("text", ""), baseline.get("text", "")):
                ctx.F.add(title="Posible IDOR/BOLA en %s: id vecino devuelve otro objeto valido" % ep.get("key"),
                          severity="Alto", category="idor", endpoint=ep.get("key"),
                          evidence=["id original: %s -> probado: %s" % (mask(value, 2, 2), mask(nb, 2, 2)),
                                    "%s %s" % (method, redact_url(new_url)),
                                    "respuesta: status=%s size=%s (baseline %s), objeto DISTINTO" % (r["status"], r["size"], baseline["size"])],
                          recommendation="Aplicar control de acceso a nivel de objeto (BOLA): verificar que el usuario "
                                         "autenticado sea dueno del recurso solicitado, no solo que el id exista.")


def _looks_different_object(text, base_text):
    if not text or not base_text:
        return bool(text) and text != base_text
    if text == base_text:
        return False
    try:
        a = json.loads(text)
        b = json.loads(base_text)
    except Exception:
        return abs(len(text) - len(base_text)) < max(len(base_text), 1) * 0.9
    if isinstance(a, dict) and isinstance(b, dict):
        return set(a.keys()) == set(b.keys()) and a != b
    return a != b


# ---- Prueba 4: sondeo de inyeccion ----
def _inject_targets(ep, base):
    targets = []
    dp = ep.get("data_param")
    if dp and dp.get("name") and dp.get("in") in ("query", "body", "path"):
        targets.append((dp["in"], dp["name"]))
    qp = list((ep.get("query_params") or {}).keys())
    for k in qp[:2]:
        if ("query", k) not in targets:
            targets.append(("query", k))
    rb = ep.get("request_body") or {}
    if rb.get("kind") == "json" and base.get("body"):
        try:
            obj = json.loads(base["body"])
            if isinstance(obj, dict):
                for k in list(obj.keys())[:1]:
                    targets.append(("body", k))
        except Exception:
            pass
    return targets[:3]


def _apply_injection(base, loc, name, payload):
    url, body = base["url"], base["body"]
    if loc == "query":
        url = _set_query(url, {name: payload})
    elif loc == "path":
        p = urlsplit(url)
        segs = p.path.rstrip("/").split("/")
        if segs:
            segs[-1] = segs[-1] + payload
        url = urlunsplit((p.scheme, p.netloc, "/".join(segs), p.query, p.fragment))
    elif loc == "body":
        try:
            obj = json.loads(body) if body else {}
            if isinstance(obj, dict):
                obj[name] = payload
                body = json.dumps(obj)
        except Exception:
            pass
    return url, body


def test_injection(ctx, ep, base, baseline):
    ctx._cur_observed = base["method"]
    method = base["method"]
    targets = _inject_targets(ep, base)
    if not targets:
        return
    sent = 0
    base_text = baseline.get("text", "") or ""
    for loc, name in targets:
        for pid, payload in INJECTION_PAYLOADS:
            if sent >= ctx.args.max_injection or not ctx.budget.allow():
                return
            sent += 1
            url, body = _apply_injection(base, loc, name, payload)
            r = http_send(ctx, method, url, base["headers"], body)
            if r.get("error") or r.get("skipped"):
                continue
            txt = r.get("text", "") or ""
            st = r.get("status", 0)
            signals = []
            sev = "Info"
            if SQL_ERR_RE.search(txt) and not SQL_ERR_RE.search(base_text):
                signals.append("mensaje de error SQL en la respuesta")
                sev = "Alto"
            if STACK_RE.search(txt) and not STACK_RE.search(base_text):
                signals.append("stack trace / traza de excepcion")
                sev = _max_sev(sev, "Medio")
            if pid == "xss_reflect" and payload in txt and payload not in base_text:
                signals.append("payload XSS reflejado sin codificar (%s)" % payload)
                sev = _max_sev(sev, "Alto")
            if pid in ("ssti_dollar", "ssti_brace"):
                if "49" in txt and payload not in txt and "49" not in base_text:
                    signals.append("posible SSTI: %s evaluado a 49" % payload)
                    sev = _max_sev(sev, "Medio")
            if st >= 500 and baseline.get("status", 200) < 500:
                signals.append("error %s del servidor ante el payload" % st)
                sev = _max_sev(sev, "Medio")
            if signals:
                cat_label = {"sqli_squote": "SQLi", "sqli_dquote": "SQLi", "sqli_tautology": "SQLi",
                             "xss_reflect": "XSS", "ssti_dollar": "SSTI", "ssti_brace": "SSTI",
                             "long_value": "robustez"}.get(pid, "inyeccion")
                ctx.F.add(title="Senal de %s en %s (param `%s`)" % (cat_label, ep.get("key"), name), severity=sev,
                          category="injection", endpoint=ep.get("key"),
                          evidence=["payload de SONDEO (%s): %s" % (pid, payload[:60]),
                                    "%s %s" % (method, redact_url(url)),
                                    "respuesta: status=%s size=%s" % (st, r.get("size")),
                                    "senales: %s" % "; ".join(signals)],
                          recommendation="Usar consultas parametrizadas/ORM (SQLi), codificar salida y CSP (XSS), y no "
                                         "evaluar plantillas con entrada del usuario (SSTI). SOLO se envio un sondeo, "
                                         "no un exploit; confirmar y remediar.")


def _max_sev(a, b):
    return a if SEV_RANK[a] <= SEV_RANK[b] else b


# ---- Prueba 5: robustez de sesion / CORS ----
def test_session_cors(ctx, ep, base, baseline):
    ctx._cur_observed = "OPTIONS"
    method, url = base["method"], base["url"]
    r = http_send(ctx, "OPTIONS", url, {k: v for k, v in base["headers"].items() if not is_sensitive_header(k)})
    if r and not r.get("error") and not r.get("skipped"):
        rh = r.get("headers") or {}
        allow = rh.get("allow") or rh.get("access-control-allow-methods")
        if allow and re.search(r"put|delete|patch", allow, re.I):
            ctx.F.add(title="OPTIONS expone metodos de escritura en %s" % ep.get("key"), severity="Info",
                      category="session_cors", endpoint=ep.get("key"), evidence=["Allow: %s" % allow],
                      recommendation="Confirmar que los metodos de escritura expuestos requieren autorizacion adecuada.")
    ctx._cur_observed = method
    evil = "https://evil.example.com"
    h_cors = dict(base["headers"])
    h_cors["Origin"] = evil
    r = http_send(ctx, method if method in ("GET", "HEAD") else "GET", url, h_cors, None)
    if r and not r.get("error") and not r.get("skipped"):
        rh = r.get("headers") or {}
        acao = rh.get("access-control-allow-origin")
        acac = rh.get("access-control-allow-credentials")
        if acao and (acao == evil or acao == "*"):
            reflected = acao == evil
            with_creds = str(acac).lower() == "true"
            if reflected and with_creds:
                sev = "Alto"
            elif acao == "*" and with_creds:
                sev = "Alto"
            elif reflected:
                sev = "Medio"
            else:
                sev = "Bajo"
            ctx.F.add(title="CORS permisivo en %s (refleja Origin arbitrario)" % ep.get("key"), severity=sev,
                      category="session_cors", endpoint=ep.get("key"),
                      evidence=["Origin enviado: %s" % evil, "Access-Control-Allow-Origin: %s" % acao,
                                "Access-Control-Allow-Credentials: %s" % acac],
                      recommendation="No reflejar Origin arbitrario. Usar una allowlist estricta y NO combinar "
                                     "`Allow-Origin: *` (o reflejado) con `Allow-Credentials: true`.")


# ---- Prueba 6: rate-limit real ----
def test_rate_limit(ctx, ep, base, baseline):
    method, url = base["method"], base["url"]
    if method not in ("GET", "HEAD"):
        return
    ctx._cur_observed = method
    burst = min(ctx.args.burst, max(2, ctx.budget.max - ctx.budget.used))
    saw_429 = False
    n = 0
    for _ in range(burst):
        if not ctx.budget.allow():
            break
        r = http_send(ctx, method, url, base["headers"], None)
        n += 1
        if r.get("status") == 429:
            saw_429 = True
            break
    if n >= 3 and not saw_429:
        ctx.F.add(title="Sin rate-limit observable en %s (rafaga de %d sin 429)" % (ep.get("key"), n), severity="Bajo",
                  category="rate_limit", endpoint=ep.get("key"),
                  evidence=["se enviaron %d requests seguidos y ninguno recibio 429" % n],
                  recommendation="Implementar rate-limiting / throttling por IP y por credencial para mitigar fuerza "
                                 "bruta y scraping abusivo.")
    elif saw_429:
        ctx.F.add(title="Rate-limit activo en %s (respondio 429)" % ep.get("key"), severity="Info",
                  category="rate_limit", endpoint=ep.get("key"), evidence=["429 tras %d requests" % n],
                  recommendation="Correcto: el endpoint aplica rate-limit. Verificar que el umbral sea adecuado.")


# ================================================================= orquestacion activa
def run_active(ctx):
    args = ctx.args
    eps = [e for e in ctx.m.get("endpoints", []) if not e.get("likely_tracking") and not e.get("third_party")]
    eps = [e for e in eps if (e.get("replay") or {}).get("url") or e.get("example_urls")]
    for ep in eps:
        if not ctx.budget.allow():
            break
        base = build_base_request(ep, args)
        if not base["url"]:
            continue
        guard_target(base["url"], "url")
        baseline = load_captured_baseline(ctx, ep)
        ctx._cur_observed = base["method"]
        live = http_send(ctx, base["method"], base["url"], base["headers"], base["body"])
        if live and not live.get("error") and not live.get("skipped") and 200 <= live.get("status", 0) < 300 and live.get("size", 0) > 8:
            baseline = {"status": live["status"], "text": live["text"], "size": live["size"], "source": "vivo"}
        if not args.no_auth_test:
            test_auth_headers(ctx, ep, base, baseline)
        if not args.no_incomplete:
            test_incomplete(ctx, ep, base, baseline)
        if not args.no_idor:
            test_idor(ctx, ep, base, baseline)
        if not args.no_injection:
            test_injection(ctx, ep, base, baseline)
        if not args.no_session:
            test_session_cors(ctx, ep, base, baseline)
        if not args.no_ratelimit:
            test_rate_limit(ctx, ep, base, baseline)


# ================================================================= salida
def render_md(m, F, mode, ctx):
    counts = F.counts()
    now = datetime.now().astimezone().strftime("%Y-%m-%d %H:%M %Z")
    L = []
    L.append("# Reporte de seguridad \u2014 web-network-mapper")
    L.append("")
    if mode == "authorized":
        L.append("**Modo:** AUTORIZADO (pruebas activas habilitadas). Requests enviados: %d / cap %d." %
                 (ctx.budget.used if ctx else 0, ctx.budget.max if ctx else 0))
    else:
        L.append("**Modo:** PASIVO (solo analisis de datos capturados; **no se envio ningun request**).")
    L.append("")
    L.append("- Objetivo (host observado): `%s`" % endpoint_host(m))
    L.append("- Run dir: `%s`" % m.get("run_dir"))
    L.append("- Endpoints analizados: %d" % len(m.get("endpoints", [])))
    L.append("- Generado: %s" % now)
    L.append("")
    L.append("## Resumen ejecutivo")
    L.append("")
    L.append("| Severidad | Hallazgos |")
    L.append("|---|---|")
    for s in SEVERITIES:
        L.append("| %s | %d |" % (s, counts[s]))
    L.append("| **Total** | **%d** |" % sum(counts.values()))
    L.append("")
    if ctx and ctx.notes:
        L.append("> Notas: " + "; ".join(ctx.notes))
        L.append("")
    L.append("## Hallazgos")
    L.append("")
    if not F.items:
        L.append("_No se identificaron hallazgos con las comprobaciones ejecutadas._")
    for f in F.sorted():
        L.append("### [%s] %s" % (f["severity"], f["title"]))
        L.append("")
        L.append("- **ID:** %s" % f["id"])
        L.append("- **Categoria:** %s" % f["category"])
        if f.get("endpoint"):
            L.append("- **Endpoint:** `%s`" % f["endpoint"])
        if f.get("evidence"):
            L.append("- **Evidencia (redactada):**")
            for e in f["evidence"]:
                L.append("  - `%s`" % e)
        L.append("- **Recomendacion:** %s" % f["recommendation"])
        L.append("")
    L.append("---")
    L.append("_Generado por security.py (web-network-mapper). Uso exclusivo sobre objetivos autorizados._")
    return "\n".join(L) + "\n"


def print_summary(F, mode, ctx):
    counts = F.counts()
    bar = "=" * 64
    log(bar)
    if mode == "authorized":
        log("  MODO AUTORIZADO \u2014 pruebas activas ejecutadas (requests: %d/%d)" %
            (ctx.budget.used if ctx else 0, ctx.budget.max if ctx else 0))
    else:
        log("  MODO PASIVO \u2014 solo analisis de capturas; NO se envio ningun request")
    log(bar)
    for s in SEVERITIES:
        log("  %-8s: %d" % (s, counts[s]))
    log("  %-8s: %d" % ("TOTAL", sum(counts.values())))
    log(bar)


def main(argv=None):
    ap = argparse.ArgumentParser(prog="wnm-scan", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("target", help="run dir o ruta a api_map.json")
    ap.add_argument("--authorized", "--i-have-permission", dest="authorized", action="store_true",
                    help="habilita las pruebas ACTIVAS (envian requests). Requiere autorizacion del objetivo.")
    ap.add_argument("--only", choices=["passive", "active"], help="ejecutar solo pasivo o solo activo")
    ap.add_argument("--out", metavar="DIR", help="directorio de salida (default: el run dir)")
    ap.add_argument("--json", action="store_true", help="volcar security_findings.json a stdout")
    ap.add_argument("--max-requests", type=int, default=100, help="cap duro de requests activos (default 100)")
    ap.add_argument("--delay", type=float, default=0.5, help="segundos de espera entre requests activos (default 0.5)")
    ap.add_argument("--timeout", type=float, default=20, help="timeout por request (s)")
    ap.add_argument("--insecure", action="store_true", help="omitir verificacion TLS")
    ap.add_argument("--header", action="append", metavar="'Name: value'",
                    help="header extra para las pruebas activas (p.ej. para suministrar el token real; repetible)")
    ap.add_argument("--cookies", metavar="FILE", help="(reservado) archivo de cookies para baseline autenticado")
    ap.add_argument("--storage-state", metavar="FILE", help="(reservado) storage_state de Playwright")
    ap.add_argument("--user-agent", help="user-agent para las pruebas activas")
    ap.add_argument("--max-idor", type=int, default=3, help="max intentos IDOR por endpoint (default 3)")
    ap.add_argument("--max-injection", type=int, default=8, help="max sondeos de inyeccion por endpoint (default 8)")
    ap.add_argument("--burst", type=int, default=8, help="tamano de la rafaga de rate-limit (default 8)")
    ap.add_argument("--no-auth-test", action="store_true", help="desactiva la prueba de headers/auth")
    ap.add_argument("--no-incomplete", action="store_true", help="desactiva la prueba de request incompleto")
    ap.add_argument("--no-idor", action="store_true", help="desactiva la prueba IDOR/BOLA")
    ap.add_argument("--no-injection", action="store_true", help="desactiva el sondeo de inyeccion")
    ap.add_argument("--no-session", action="store_true", help="desactiva la prueba de sesion/CORS")
    ap.add_argument("--no-ratelimit", action="store_true", help="desactiva la prueba de rate-limit")
    args = ap.parse_args(argv)

    m, run_dir = load_map(args.target)
    out_dir = Path(args.out) if args.out else run_dir
    out_dir.mkdir(parents=True, exist_ok=True)

    want_active = (args.only == "active") or (args.only is None)
    want_passive = (args.only == "passive") or (args.only is None)

    if args.only == "active" and not args.authorized:
        log("ABORTADO: pediste solo pruebas ACTIVAS pero no confirmaste autorizacion.")
        log("Las pruebas activas envian requests al objetivo y solo deben usarse sobre sistemas")
        log("para los que tienes permiso explicito (pentest propio / bug bounty autorizado).")
        log("Vuelve a ejecutar con --authorized (o --i-have-permission) para confirmarlo.")
        return 2

    F = Findings()
    ctx = None
    mode = "passive"

    if want_passive:
        scan_secrets(run_dir, F)
        scan_jwts(run_dir, F)
        header_scorecard(run_dir, m, F, endpoint_host(m))
        auth_matrix(m, F)
        graphql_surface(run_dir, m, F)

    if want_active and args.authorized:
        ctx = Ctx(args, run_dir, m, F)
        mode = "authorized"
        try:
            host = endpoint_host(m)
            if host:
                guard_target(host if "//" in host else "http://" + host, "url")
            run_active(ctx)
        finally:
            ctx.close()
    elif want_active and not args.authorized and args.only is None:
        log("[i] Pruebas ACTIVAS omitidas: falta --authorized (por seguridad). Corriendo solo analisis PASIVO.")

    findings_obj = {
        "generated_by": "web-network-mapper/security.py",
        "target": endpoint_host(m),
        "run_dir": m.get("run_dir"),
        "mode": mode,
        "requests_sent": ctx.budget.used if ctx else 0,
        "request_cap": args.max_requests,
        "summary": F.counts(),
        "findings": F.sorted(),
    }
    md_path = out_dir / "security_report.md"
    json_path = out_dir / "security_findings.json"
    md_path.write_text(render_md(m, F, mode, ctx))
    json_path.write_text(json.dumps(findings_obj, ensure_ascii=False, indent=2))

    print_summary(F, mode, ctx)
    log("[ok] reporte:  %s" % md_path)
    log("[ok] hallazgos: %s" % json_path)
    if args.json:
        print(json.dumps(findings_obj, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
