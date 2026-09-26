#!/usr/bin/env python3
"""watch.py - watch/diff mode for API endpoints (web-network-mapper).

Takes a normalized "snapshot" of a site's API (from a URL -> runs mapper.py + analyze.py,
or from an existing run dir / api_map.json), stores it under <tool>/.watch/<name>/ and diffs it
against the previous snapshot (or --baseline FILE): endpoints added/removed, response/request
field changes (added/removed/type), status codes, rate-limit, anti-bot, tokens, websockets.

Exit codes:  0 = no changes / baseline created / --save-only / --list
            10 = changes detected
             1 = error (pipeline failed, bad input, blocked domain)
             2 = usage error (argparse)

Examples:
  wnm-watch https://quotes.toscrape.com/scroll --depth 1 --max-pages 3
  wnm-watch runs/quotes.toscrape.com-20260926-145241
  wnm-watch runs/x/api_map.json --baseline .watch/quotes.toscrape.com/snapshot-20260926-170000.json
  wnm-watch --list
  wnm-watch https://example.com/ -- --scroll 5 --wait 2000      (args after -- go to mapper.py)
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
from datetime import datetime
from pathlib import Path
from urllib.parse import urlsplit

TOOL_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(TOOL_DIR))
from wnm_common import guard_target, redact_url  # noqa: E402

SNAPSHOT_VERSION = 1
DIFF_VERSION = 1
EXIT_OK = 0
EXIT_CHANGES = 10
EXIT_ERROR = 1
MAX_SCHEMA_DEPTH = 10
MAX_FIELDS = 3000


def py_exe() -> str:
    v = TOOL_DIR / ".venv" / "bin" / "python"
    return str(v) if v.exists() else sys.executable


def note(*a):
    print(*a, file=sys.stderr, flush=True)


def now_ts() -> str:
    return datetime.now().strftime("%Y%m%d-%H%M%S")


def now_iso() -> str:
    return datetime.now().astimezone().isoformat(timespec="seconds")


def safe_name(s: str) -> str:
    s = re.sub(r"[^A-Za-z0-9._-]+", "_", (s or "").strip().lower()).strip("_.")
    return s[:100] or "sitio"


# ------------------------------------------------------------------ schema flattening
def _types(node) -> list[str]:
    t = (node or {}).get("type")
    if t is None:
        return []
    return sorted(set(t)) if isinstance(t, list) else [t]


def flatten_schema(schema, prefix: str = "", depth: int = 0, out: dict | None = None) -> dict:
    """{path: 'type|type'} for every node of an analyze.py inferred schema.
    Paths: 'a.b', arrays as 'a[]', id-keyed maps as 'a.{id}'. The root is '$'."""
    if out is None:
        out = {}
    if not isinstance(schema, dict) or len(out) >= MAX_FIELDS:
        return out
    path = prefix or "$"
    ts = _types(schema)
    if ts:
        out[path] = "|".join(ts)
    if depth >= MAX_SCHEMA_DEPTH:
        return out
    base = prefix  # '' for root
    for k, sub in (schema.get("properties") or {}).items():
        flatten_schema(sub, f"{base}.{k}" if base else str(k), depth + 1, out)
    if isinstance(schema.get("items"), dict):
        flatten_schema(schema["items"], f"{base}[]" if base else "[]", depth + 1, out)
    if isinstance(schema.get("additionalProperties"), dict):
        kp = schema.get("key_pattern") or "{key}"
        flatten_schema(schema["additionalProperties"], f"{base}.{kp}" if base else kp, depth + 1, out)
    return out


def request_fields(rb) -> dict:
    if not isinstance(rb, dict):
        return {}
    kind = rb.get("kind")
    if kind == "json":
        return flatten_schema(rb.get("schema") or {})
    if kind == "form":
        return {str(k): "form" for k in (rb.get("fields") or {})}
    if kind == "multipart":
        return {str(k): "multipart" for k in (rb.get("fields") or [])}
    if kind:
        return {"$": str(kind)}
    return {}


def _tok_list(items) -> list[str]:
    out = set()
    for it in items or []:
        if isinstance(it, dict):
            out.add(f"{it.get('kind', '?')}:{it.get('name', '?')}")
        elif it:
            out.add(str(it))
    return sorted(out)


def _rate_limit(rl) -> dict | None:
    if not isinstance(rl, dict):
        return None
    return {
        "status_429": int(rl.get("status_429") or 0),
        "limit": rl.get("limit"),
        "retry_after": rl.get("retry_after"),
        "headers": sorted((rl.get("headers") or {}).keys(), key=str.lower),
    }


def normalize_endpoint(e: dict) -> dict:
    rr = e.get("response_records") or {}
    return {
        "method": e.get("method"),
        "host": e.get("host"),
        "path_template": e.get("path_template"),
        "role": e.get("role"),
        "flags": sorted(e.get("flags") or []),
        "likely_data_endpoint": bool(e.get("likely_data_endpoint")),
        "third_party": bool(e.get("third_party")),
        "likely_tracking": bool(e.get("likely_tracking")),
        "statuses": sorted(str(s) for s in (e.get("statuses") or {})),
        "response_content_types": sorted(e.get("response_content_types") or {}),
        "body_kind": e.get("body_kind"),
        "auth_headers": sorted(e.get("auth_headers") or []),
        "query_params": sorted(e.get("query_params") or {}),
        "pagination_params": sorted(e.get("pagination_params") or []),
        "graphql_operations": sorted(str(x) for x in (e.get("graphql_operations") or [])),
        "request_body_kind": (e.get("request_body") or {}).get("kind") if isinstance(e.get("request_body"), dict) else None,
        "request_fields": request_fields(e.get("request_body")),
        "response_fields": flatten_schema(e.get("response_schema") or {}),
        "records_path": rr.get("path") if rr else None,
        "rate_limit": _rate_limit(e.get("rate_limit")),
        "issues_token": _tok_list(e.get("issues_token")),
        "consumes_token": _tok_list(e.get("consumes_token")),
    }


def fingerprint(snap: dict) -> str:
    body = {k: snap.get(k) for k in ("endpoints", "websockets", "anti_bot", "tokens", "auth", "rate_limit_summary")}
    return hashlib.sha256(json.dumps(body, sort_keys=True, ensure_ascii=False).encode()).hexdigest()


def snapshot_from_api_map(api_map: dict, source: dict) -> dict:
    start_url = api_map.get("start_url") or ""
    eps = {}
    for e in api_map.get("endpoints") or []:
        k = e.get("key")
        if k:
            eps[k] = normalize_endpoint(e)
    ab = {}
    for a in api_map.get("anti_bot") or []:
        if isinstance(a, dict) and a.get("vendor"):
            ab[a["vendor"]] = {"active": a.get("active")}
    af = api_map.get("auth_flow") or {}
    tokens = {}
    for t in af.get("tokens") or []:
        if isinstance(t, dict):
            tokens[f"{t.get('kind', '?')}:{t.get('name', '?')}"] = {
                "session_like": t.get("session_like"),
                "carried_by": t.get("carried_by"),
                "issued_by": sorted({i.get("endpoint") for i in t.get("issued_by") or [] if isinstance(i, dict) and i.get("endpoint")}),
            }
    rls = api_map.get("rate_limit_summary") or {}
    snap = {
        "snapshot_version": SNAPSHOT_VERSION,
        "generated_by": "web-network-mapper/watch.py",
        "taken_at": now_iso(),
        "watch_name": None,
        "domain": (urlsplit(start_url).hostname or "").lower(),
        "start_url": start_url,
        "source": source,
        "pages_visited": api_map.get("pages_visited"),
        "total_requests": api_map.get("total_requests"),
        "endpoint_count": len(eps),
        "endpoints": dict(sorted(eps.items())),
        "websockets": sorted({redact_url(w.get("url") or "") for w in api_map.get("websockets") or [] if isinstance(w, dict) and w.get("url")}),
        "anti_bot": dict(sorted(ab.items())),
        "tokens": dict(sorted(tokens.items())),
        "auth": {k: af.get(k) for k in ("has_bearer", "has_session_cookie") if k in af},
        "rate_limit_summary": {
            "endpoints_with_rate_limit": int(rls.get("endpoints_with_rate_limit") or 0),
            "status_429_total": int(rls.get("status_429_total") or 0),
        },
    }
    snap["fingerprint"] = fingerprint(snap)
    return snap


# ------------------------------------------------------------------ loading inputs
def load_json(p: Path):
    return json.loads(Path(p).read_text(encoding="utf-8"))


def run_analyze(run_dir: Path, analyze_args: list[str]) -> None:
    cmd = [py_exe(), str(TOOL_DIR / "analyze.py"), str(run_dir), *analyze_args]
    note(f"[watch] analizando: {run_dir}")
    r = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=sys.stderr, text=True)
    if r.returncode != 0:
        raise SystemExit(f"ERROR: analyze.py falló (código {r.returncode}) sobre {run_dir}")


def analyze_args_from_mapper_args(margs: list[str]) -> list[str]:
    """Forward the flags that change api_map content so re-analysis matches the mapper run."""
    p = argparse.ArgumentParser(add_help=False)
    p.add_argument("--map-documents", action="store_true")
    p.add_argument("--emit-curl", nargs="?", const="all")
    p.add_argument("--curl-redact", action="store_true")
    a, _ = p.parse_known_args(margs)
    out = []
    if a.map_documents:
        out.append("--map-documents")
    if a.emit_curl:
        out += ["--emit-curl", a.emit_curl]
    if a.curl_redact:
        out.append("--curl-redact")
    return out


def run_pipeline(url: str, mapper_args: list[str]) -> Path:
    cmd = [py_exe(), str(TOOL_DIR / "mapper.py"), url, *mapper_args]
    note(f"[watch] capturando {url} con mapper.py ...")
    r = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=sys.stderr, text=True)
    lines = [l.strip() for l in (r.stdout or "").splitlines() if l.strip()]
    run_dir = Path(lines[-1]) if lines else None
    if r.returncode != 0 or not run_dir or not run_dir.is_dir():
        raise SystemExit(f"ERROR: mapper.py falló (código {r.returncode}); no se obtuvo run dir.")
    run_analyze(run_dir, analyze_args_from_mapper_args(mapper_args))
    return run_dir


def resolve_api_map(path: Path, reanalyze: bool) -> Path:
    """rundir or api_map.json -> api_map.json path (running analyze.py when needed)."""
    if path.is_dir():
        am = path / "api_map.json"
        if reanalyze or not am.exists():
            if not (path / "requests.jsonl").exists():
                raise SystemExit(f"ERROR: {path} no contiene api_map.json ni requests.jsonl")
            _guard_run_dir(path)
            run_analyze(path, [])
        return am
    if path.is_file():
        if reanalyze and path.name == "api_map.json":
            return resolve_api_map(path.parent, True)
        return path
    raise SystemExit(f"ERROR: no existe {path}")


def _guard_run_dir(run_dir: Path) -> None:
    meta = run_dir / "run_meta.json"
    try:
        su = load_json(meta).get("start_url") if meta.exists() else None
    except Exception:
        su = None
    if su:
        guard_target(su, "url")


def load_any_snapshot(path: Path, reanalyze: bool = False) -> dict:
    """Accepts a snapshot-*.json, an api_map.json or a run dir (converted on the fly)."""
    path = Path(path)
    if path.is_file():
        d = load_json(path)
        if isinstance(d, dict) and d.get("snapshot_version"):
            d.setdefault("_file", str(path))
            return d
    am = resolve_api_map(path, reanalyze)
    api_map = load_json(am)
    if not isinstance(api_map, dict) or "endpoints" not in api_map:
        raise SystemExit(f"ERROR: {am} no parece un api_map.json ni un snapshot de watch")
    snap = snapshot_from_api_map(api_map, {"kind": "api_map", "api_map": str(am.resolve()),
                                           "run_dir": api_map.get("run_dir") or str(am.resolve().parent)})
    snap["_file"] = str(path)
    return snap


# ------------------------------------------------------------------ diff
def _ch(op, area, path, text, before=None, after=None, **extra):
    d = {"op": op, "area": area, "path": path, "text": text}
    if before is not None:
        d["before"] = before
    if after is not None:
        d["after"] = after
    d.update(extra)
    return d


def _collapse(paths: list[str], universe: set[str]) -> list[tuple[str, int]]:
    """Keep only top-most paths (drop children whose parent is also in the list). Returns (path, n_children)."""
    s = set(paths)

    def parents(p):
        out = []
        cur = p
        while True:
            m = re.match(r"^(.*)(\.[^.\[]+|\[\])$", cur)
            if not m or not m.group(1):
                break
            cur = m.group(1)
            out.append(cur)
        return out

    top = [p for p in paths if not any(pp in s for pp in parents(p))]
    res = []
    for p in sorted(top):
        n = sum(1 for q in s if q != p and (q.startswith(p + ".") or q.startswith(p + "[]")))
        res.append((p, n))
    return res


def diff_fields(before: dict, after: dict, area: str, label: str) -> list[dict]:
    out = []
    b, a = before or {}, after or {}
    added = [p for p in a if p not in b]
    removed = [p for p in b if p not in a]
    for p, n in _collapse(added, set(a)):
        extra = f" (+{n} subcampos)" if n else ""
        out.append(_ch("+", area, p, f"{label} nuevo: {p} ({a[p]}){extra}", after=a[p], children=n))
    for p, n in _collapse(removed, set(b)):
        extra = f" (-{n} subcampos)" if n else ""
        out.append(_ch("-", area, p, f"{label} eliminado: {p} ({b[p]}){extra}", before=b[p], children=n))
    for p in sorted(set(a) & set(b)):
        if a[p] != b[p]:
            tb, ta = set(b[p].split("|")), set(a[p].split("|"))
            null_only = (tb - {"null"} == ta - {"null"}) or tb == {"null"} or ta == {"null"}
            suf = " (solo cambió la nulabilidad / valor nulo en la muestra)" if null_only else ""
            out.append(_ch("~", area, p, f"tipo de {label.lower()} {p}: {b[p]} → {a[p]}{suf}",
                           before=b[p], after=a[p], null_only=null_only))
    return out


def _set_diff(b, a, area, label) -> list[dict]:
    b, a = set(b or []), set(a or [])
    out = [_ch("+", area, x, f"{label} nuevo: {x}", after=x) for x in sorted(a - b)]
    out += [_ch("-", area, x, f"{label} eliminado: {x}", before=x) for x in sorted(b - a)]
    return out


def _scalar(b, a, area, label) -> list[dict]:
    if b != a:
        return [_ch("~", area, area, f"{label}: {b if b not in (None, '') else '(ninguno)'} → {a if a not in (None, '') else '(ninguno)'}",
                    before=b, after=a)]
    return []


def diff_endpoint(b: dict, a: dict) -> list[dict]:
    ch = []
    ch += _set_diff(b.get("statuses"), a.get("statuses"), "status", "código de status")
    ch += diff_fields(b.get("response_fields"), a.get("response_fields"), "response", "campo de respuesta")
    ch += diff_fields(b.get("request_fields"), a.get("request_fields"), "request", "campo de request")
    ch += _scalar(b.get("request_body_kind"), a.get("request_body_kind"), "request_body_kind", "tipo de body de request")
    ch += _set_diff(b.get("query_params"), a.get("query_params"), "query", "parámetro de query")
    ch += _set_diff(b.get("response_content_types"), a.get("response_content_types"), "content_type", "content-type de respuesta")
    ch += _scalar(b.get("body_kind"), a.get("body_kind"), "body_kind", "tipo de body de respuesta")
    ch += _scalar(b.get("role"), a.get("role"), "role", "rol")
    ch += _scalar(b.get("records_path"), a.get("records_path"), "records_path", "ruta de registros")
    ch += _set_diff(b.get("flags"), a.get("flags"), "flags", "flag")
    ch += _set_diff(b.get("auth_headers"), a.get("auth_headers"), "auth", "header de auth")
    ch += _set_diff(b.get("graphql_operations"), a.get("graphql_operations"), "graphql", "operación GraphQL")
    ch += _set_diff(b.get("issues_token"), a.get("issues_token"), "tokens", "token emitido")
    ch += _set_diff(b.get("consumes_token"), a.get("consumes_token"), "tokens", "token consumido")
    rb, ra = b.get("rate_limit"), a.get("rate_limit")
    if rb != ra:
        if rb is None:
            ch.append(_ch("+", "rate_limit", "rate_limit", f"rate-limit detectado: {_rl_txt(ra)}", after=ra))
        elif ra is None:
            ch.append(_ch("-", "rate_limit", "rate_limit", f"rate-limit ya no aparece (antes: {_rl_txt(rb)})", before=rb))
        else:
            ch.append(_ch("~", "rate_limit", "rate_limit", f"rate-limit: {_rl_txt(rb)} → {_rl_txt(ra)}", before=rb, after=ra))
    return ch


def _rl_txt(rl) -> str:
    if not rl:
        return "(ninguno)"
    parts = []
    if rl.get("limit") is not None:
        parts.append(f"límite={rl['limit']}")
    if rl.get("status_429"):
        parts.append(f"429×{rl['status_429']}")
    if rl.get("retry_after") is not None:
        parts.append(f"retry-after={rl['retry_after']}")
    if rl.get("headers"):
        parts.append("headers=" + ",".join(rl["headers"]))
    return " ".join(parts) or "sí"


def _ep_brief(e: dict) -> str:
    bits = []
    if e.get("role"):
        bits.append(e["role"])
    if e.get("statuses"):
        bits.append("status " + ",".join(e["statuses"]))
    nf = len([p for p in (e.get("response_fields") or {}) if p != "$"])
    if nf:
        bits.append(f"{nf} campos")
    if e.get("likely_tracking"):
        bits.append("tracking")
    elif e.get("third_party"):
        bits.append("tercero")
    return ", ".join(bits)


def diff_snapshots(base: dict, cur: dict, include_tracking: bool = False) -> dict:
    be, ce = base.get("endpoints") or {}, cur.get("endpoints") or {}
    skipped = 0

    def tracked(k):
        return (be.get(k) or {}).get("likely_tracking") or (ce.get(k) or {}).get("likely_tracking")

    keys_b, keys_c = set(be), set(ce)
    if not include_tracking:
        tr = {k for k in keys_b | keys_c if tracked(k)}
        skipped = len(tr)
        keys_b -= tr
        keys_c -= tr
    added = [{"key": k, "brief": _ep_brief(ce[k]), "endpoint": ce[k]} for k in sorted(keys_c - keys_b)]
    removed = [{"key": k, "brief": _ep_brief(be[k]), "endpoint": be[k]} for k in sorted(keys_b - keys_c)]
    changed = []
    for k in sorted(keys_b & keys_c):
        chs = diff_endpoint(be[k], ce[k])
        if chs:
            changed.append({"key": k, "changes": chs})

    glob = []
    for sec, label in (("anti_bot", "anti-bot"), ("tokens", "token/sesión")):
        b, a = base.get(sec) or {}, cur.get(sec) or {}
        for k in sorted(set(a) - set(b)):
            glob.append(_ch("+", sec, k, f"{label} nuevo: {k}", after=a[k]))
        for k in sorted(set(b) - set(a)):
            glob.append(_ch("-", sec, k, f"{label} ya no aparece: {k}", before=b[k]))
        for k in sorted(set(a) & set(b)):
            if a[k] != b[k]:
                diffs = ", ".join(f"{f}: {b[k].get(f)} → {a[k].get(f)}" for f in sorted(set(a[k]) | set(b[k])) if a[k].get(f) != b[k].get(f))
                glob.append(_ch("~", sec, k, f"{label} {k} cambió ({diffs})", before=b[k], after=a[k]))
    glob += _set_diff(base.get("websockets"), cur.get("websockets"), "websockets", "WebSocket")
    for f, label in (("has_bearer", "usa Bearer"), ("has_session_cookie", "usa cookie de sesión")):
        bv, av = (base.get("auth") or {}).get(f), (cur.get("auth") or {}).get(f)
        if bv is not None and av is not None and bv != av:
            glob.append(_ch("~", "auth", f, f"{label}: {bv} → {av}", before=bv, after=av))
    for f, label in (("endpoints_with_rate_limit", "endpoints con rate-limit"), ("status_429_total", "respuestas 429")):
        bv, av = (base.get("rate_limit_summary") or {}).get(f, 0), (cur.get("rate_limit_summary") or {}).get(f, 0)
        if bv != av:
            glob.append(_ch("~", "rate_limit", f, f"{label}: {bv} → {av}", before=bv, after=av))

    changed_flag = bool(added or removed or changed or glob)
    warnings = []
    if base.get("start_url") and cur.get("start_url") and base["start_url"] != cur["start_url"]:
        warnings.append(f"la URL inicial difiere (línea base: {base['start_url']} / actual: {cur['start_url']}); "
                        "las diferencias pueden deberse al punto de partida y no a cambios del sitio")
    return {
        "diff_version": DIFF_VERSION,
        "generated_by": "web-network-mapper/watch.py",
        "created_at": now_iso(),
        "watch_name": cur.get("watch_name") or base.get("watch_name"),
        "domain": cur.get("domain") or base.get("domain"),
        "baseline": _meta(base),
        "current": _meta(cur),
        "changed": changed_flag,
        "summary": {
            "endpoints_added": len(added), "endpoints_removed": len(removed),
            "endpoints_changed": len(changed), "field_changes": sum(len(c["changes"]) for c in changed),
            "global_changes": len(glob), "tracking_endpoints_ignored": skipped,
        },
        "endpoints": {"added": added, "removed": removed, "changed": changed},
        "global": glob,
        "warnings": warnings,
    }


def _meta(s: dict) -> dict:
    return {"file": s.get("_file"), "taken_at": s.get("taken_at"), "start_url": s.get("start_url"),
            "run_dir": (s.get("source") or {}).get("run_dir"), "endpoint_count": s.get("endpoint_count"),
            "fingerprint": s.get("fingerprint")}


# ------------------------------------------------------------------ rendering
def render_text(d: dict, md: bool = False) -> str:
    L = []
    s = d["summary"]
    b, c = d["baseline"], d["current"]
    if md:
        L += [f"# Diff de API — {d.get('watch_name') or d.get('domain')}", "",
              f"- Generado: {d['created_at']}",
              f"- Línea base: `{b.get('file')}` ({b.get('taken_at')}, {b.get('endpoint_count')} endpoints)",
              f"- Actual: `{c.get('file') or c.get('run_dir')}` ({c.get('taken_at')}, {c.get('endpoint_count')} endpoints)"]
    else:
        L += [f"== Diff de API: {d.get('watch_name') or d.get('domain')}",
              f"   línea base: {b.get('file')} ({b.get('taken_at')}, {b.get('endpoint_count')} endpoints)",
              f"   actual:     {c.get('file') or c.get('run_dir')} ({c.get('taken_at')}, {c.get('endpoint_count')} endpoints)"]
    for w in d.get("warnings") or []:
        L.append(("> **Aviso:** " if md else "   AVISO: ") + w)
    if not d["changed"]:
        L.append("" if md else "")
        L.append("**Sin cambios** respecto a la línea base." if md else "Sin cambios respecto a la línea base.")
        if s.get("tracking_endpoints_ignored"):
            L.append(f"({s['tracking_endpoints_ignored']} endpoints de tracking ignorados; usa --include-tracking para incluirlos)")
        return "\n".join(L) + "\n"
    resumen = (f"{s['endpoints_added']} endpoints nuevos, {s['endpoints_removed']} eliminados, "
               f"{s['endpoints_changed']} modificados ({s['field_changes']} cambios), {s['global_changes']} cambios globales")
    L += ["", ("**Resumen:** " if md else "Resumen: ") + resumen]
    if s.get("tracking_endpoints_ignored"):
        L.append(f"({s['tracking_endpoints_ignored']} endpoints de tracking ignorados; usa --include-tracking para incluirlos)")
    ep = d["endpoints"]

    def line(op, txt, indent=0):
        if md:
            return f"{'  ' * indent}- `{op}` {txt}"
        return f"{'    ' * indent}  {op} {txt}"

    if ep["added"]:
        L += ["", "## Endpoints nuevos" if md else "Endpoints nuevos:"]
        for e in ep["added"]:
            L.append(line("+", (f"`{e['key']}`" if md else e["key"]) + (f" ({e['brief']})" if e["brief"] else "")))
    if ep["removed"]:
        L += ["", "## Endpoints eliminados" if md else "Endpoints eliminados:"]
        for e in ep["removed"]:
            L.append(line("-", (f"`{e['key']}`" if md else e["key"]) + (f" ({e['brief']})" if e["brief"] else "")))
    if ep["changed"]:
        L += ["", "## Endpoints modificados" if md else "Endpoints modificados:"]
        for e in ep["changed"]:
            L.append(line("~", f"`{e['key']}`" if md else e["key"]))
            for c2 in e["changes"]:
                L.append(line(c2["op"], c2["text"], 1))
    if d["global"]:
        L += ["", "## Cambios globales (anti-bot, tokens, rate-limit, websockets)" if md else "Cambios globales (anti-bot, tokens, rate-limit, websockets):"]
        for g in d["global"]:
            L.append(line(g["op"], g["text"]))
    return "\n".join(L) + "\n"


# ------------------------------------------------------------------ snapshot store
def watch_root(args) -> Path:
    return Path(args.watch_dir).resolve() if args.watch_dir else TOOL_DIR / ".watch"


def _ts_key(p: Path):
    m = re.match(r"^[a-z]+-(\d{8}-\d{6})(?:-(\d+))?\.json$", p.name)
    return (m.group(1), int(m.group(2) or 1)) if m else ("", 0)


def list_snapshots(d: Path, kind: str = "snapshot") -> list[Path]:
    """Chronological order (snapshot-<ts>.json < snapshot-<ts>-2.json < ...)."""
    return sorted(d.glob(f"{kind}-*.json"), key=_ts_key) if d.is_dir() else []


def unique_path(d: Path, stem: str, ts: str, ext: str) -> Path:
    p = d / f"{stem}-{ts}{ext}"
    i = 2
    while p.exists():
        p = d / f"{stem}-{ts}-{i}{ext}"
        i += 1
    return p


def cmd_list(args) -> int:
    root = watch_root(args)
    if args.target:
        name = safe_name(args.name or (urlsplit(args.target).hostname if "//" in args.target else args.target))
        dirs = [root / name]
    else:
        dirs = sorted(p for p in root.iterdir() if p.is_dir()) if root.is_dir() else []
    if not dirs or not any(list_snapshots(d) for d in dirs):
        print(f"No hay snapshots en {root}" + (f"/{dirs[0].name}" if args.target and dirs else ""))
        return EXIT_OK
    for d in dirs:
        snaps = list_snapshots(d)
        if not snaps:
            continue
        diffs = list_snapshots(d, "diff")
        print(f"{d.name}: {len(snaps)} snapshots, {len(diffs)} diffs  ({d})")
        for s in snaps:
            try:
                j = load_json(s)
                print(f"   {s.name}  {j.get('taken_at')}  {j.get('endpoint_count')} endpoints  {j.get('start_url')}")
            except Exception:
                print(f"   {s.name}  (ilegible)")
    return EXIT_OK


# ------------------------------------------------------------------ main
class _EsFormatter(argparse.RawDescriptionHelpFormatter):
    def add_usage(self, usage, actions, groups, prefix=None):
        return super().add_usage(usage, actions, groups, "uso: " if prefix is None else prefix)


def build_parser():
    ap = argparse.ArgumentParser(
        prog="wnm-watch",
        description="Modo watch/diff: toma un snapshot de la API de un sitio y lo compara con el anterior "
                    "(endpoints nuevos/eliminados, cambios de campos, tipos, status, rate-limit, anti-bot, tokens).",
        epilog="Códigos de salida: 0 = sin cambios / línea base creada / --save-only; 10 = hay cambios; 1 = error; 2 = uso incorrecto.\n"
               "Con una URL, las opciones no reconocidas (o todo lo que va después de --) se pasan a mapper.py, "
               "p.ej.: wnm-watch https://sitio/ --depth 1 --max-pages 3",
        formatter_class=_EsFormatter, add_help=False)
    ap._positionals.title = "argumentos"
    ap._optionals.title = "opciones"
    ap.add_argument("-h", "--help", action="help", help="mostrar esta ayuda y salir")
    ap.add_argument("target", nargs="?", help="URL (corre mapper.py + analyze.py), run dir, o api_map.json")
    ap.add_argument("--baseline", metavar="FILE", help="comparar contra este snapshot (o api_map.json / run dir) en vez del último guardado")
    ap.add_argument("--save-only", action="store_true", help="solo guardar el snapshot, sin comparar")
    ap.add_argument("--no-save", action="store_true", help="comparar sin guardar el snapshot actual (no avanza la línea base)")
    ap.add_argument("--json", action="store_true", help="imprimir solo el diff en JSON por stdout (notas a stderr)")
    ap.add_argument("--name", help="nombre del watch (default: host de la URL inicial); úsalo para vigilar varias URLs del mismo dominio")
    ap.add_argument("--watch-dir", help=f"directorio raíz de snapshots (default: {TOOL_DIR / '.watch'})")
    ap.add_argument("--reanalyze", action="store_true", help="con run dir: volver a correr analyze.py antes de tomar el snapshot")
    ap.add_argument("--include-tracking", action="store_true", help="incluir endpoints de tracking/analytics en el diff (ruidosos)")
    ap.add_argument("--list", action="store_true", help="listar watches/snapshots guardados y salir")
    return ap


def main(argv=None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    passthrough = []
    if "--" in argv:
        i = argv.index("--")
        argv, passthrough = argv[:i], argv[i + 1:]
    ap = build_parser()
    args, unknown = ap.parse_known_args(argv)
    mapper_args = unknown + passthrough

    if args.list:
        return cmd_list(args)
    if not args.target:
        ap.print_help()
        return 2
    if args.save_only and args.baseline:
        ap.error("--save-only y --baseline son incompatibles")
    if args.save_only and args.no_save:
        ap.error("--save-only y --no-save son incompatibles")

    t = args.target
    tp = Path(t)
    if tp.exists():
        if mapper_args:
            ap.error(f"opciones no reconocidas (solo válidas con una URL, se pasan a mapper.py): {' '.join(mapper_args)}")
        if tp.is_dir():
            _guard_run_dir(tp)
        cur = load_any_snapshot(tp, reanalyze=args.reanalyze)
        if cur.get("start_url"):
            guard_target(cur["start_url"], "url")
        src = dict(cur.get("source") or {})
        if tp.is_dir():
            src["kind"] = "run_dir"
        elif src.get("kind") not in ("api_map",):
            src["kind"] = "snapshot"
            cur["taken_at"] = now_iso()
        src["target"] = str(tp.resolve())
        cur["source"] = src
    else:
        if not re.match(r"^https?://", t, re.I):
            if re.fullmatch(r"[A-Za-z0-9.-]+\.[A-Za-z]{2,}(:\d+)?(/.*)?", t):
                t = "https://" + t
            else:
                ap.error(f"'{args.target}' no es una URL http(s) ni un run dir / api_map.json existente")
        guard_target(t, "url")
        run_dir = run_pipeline(t, mapper_args)
        cur = load_any_snapshot(run_dir)
        cur["source"] = {"kind": "url", "target": t, "run_dir": str(run_dir), "api_map": str(run_dir / "api_map.json"),
                         "mapper_args": mapper_args}
    cur.pop("_file", None)

    name = safe_name(args.name or cur.get("domain") or "sitio")
    cur["watch_name"] = name
    wdir = watch_root(args) / name
    ts = now_ts()

    # baseline selection (before saving the new one)
    base = None
    if args.baseline:
        base = load_any_snapshot(Path(args.baseline))
        if base.get("start_url"):
            guard_target(base["start_url"], "url")
    elif not args.save_only:
        prev = list_snapshots(wdir)
        if prev:
            base = load_any_snapshot(prev[-1])

    snap_path = None
    if not args.no_save:
        wdir.mkdir(parents=True, exist_ok=True)
        snap_path = unique_path(wdir, "snapshot", ts, ".json")
        snap_path.write_text(json.dumps(cur, indent=2, ensure_ascii=False), encoding="utf-8")
        cur["_file"] = str(snap_path)
    else:
        cur["_file"] = cur["source"].get("target")

    if args.save_only or base is None:
        msg = ("Snapshot guardado" if args.save_only else "Línea base creada") + \
              (f": {snap_path}" if snap_path else " (no guardada por --no-save)")
        info = {"changed": False, "baseline_created": base is None and not args.save_only, "save_only": bool(args.save_only),
                "snapshot": str(snap_path) if snap_path else None, "watch_name": name,
                "endpoint_count": cur.get("endpoint_count"), "start_url": cur.get("start_url")}
        if args.json:
            print(json.dumps(info, ensure_ascii=False, indent=2))
        else:
            print(f"== wnm-watch: {name}")
            print(f"   {msg}")
            print(f"   {cur.get('endpoint_count')} endpoints ({cur.get('start_url')})")
            if base is None and not args.save_only:
                print("   No había snapshot previo: la próxima corrida se comparará contra esta línea base.")
        return EXIT_OK

    d = diff_snapshots(base, cur, include_tracking=args.include_tracking)
    d["watch_name"] = name
    if snap_path:
        d["current"]["file"] = str(snap_path)
    wdir.mkdir(parents=True, exist_ok=True)
    jp = unique_path(wdir, "diff", ts, ".json")
    mp = jp.with_suffix(".md")
    d["diff_json"], d["diff_md"] = str(jp), str(mp)
    jp.write_text(json.dumps(d, indent=2, ensure_ascii=False), encoding="utf-8")
    mp.write_text(render_text(d, md=True), encoding="utf-8")
    if args.json:
        print(json.dumps(d, ensure_ascii=False, indent=2))
    else:
        sys.stdout.write(render_text(d))
        if snap_path:
            print(f"\nSnapshot guardado: {snap_path}")
        print(f"Diff: {mp}")
        print(f"      {jp}")
    return EXIT_CHANGES if d["changed"] else EXIT_OK


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\ninterrumpido", file=sys.stderr)
        sys.exit(130)
