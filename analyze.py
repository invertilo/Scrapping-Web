#!/usr/bin/env python3
"""Build api_map.json / api_map.md (and enrich pages.json) from a mapper run directory.

Usage: analyze.py RUN_DIR [--map-documents] [--emit-curl [all|api|nonstatic]] [--curl-secrets | --curl-redact]
       [--no-json-schema] [--no-postman] [--no-html] [--no-replay-script]
       [--proto FILE|DIR] [--descriptor FDS] [--proto-message TYPE]
Runs automatically at the end of mapper.py; re-run it by hand after tweaking heuristics.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter, OrderedDict
from pathlib import Path
from urllib.parse import parse_qsl, urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parent))
from wnm_common import (  # noqa: E402
    REDACTED, is_sensitive_field, is_sensitive_header, loads_lenient,
    decode_body_bytes, detect_body_kind, detect_anti_bot, get_path, slugify,
)
from wnm_curl import build_curl, env_comment  # noqa: E402

TOOL_DIR = Path(__file__).resolve().parent
REDACT_EXAMPLES = True  # set from run_meta (False when the run used --keep-secrets)
CURSOR_PARAM_RE = re.compile(r"^(cursor|after|before|next_?token|page_?token|continuation(token)?|marker|next|since_?id|max_?id)$", re.I)
PAGE_PARAM_RE = re.compile(r"^(page|p|pg|pagenum|page_?num(ber)?|pageindex|page_index)$", re.I)
OFFSET_PARAM_RE = re.compile(r"^(offset|start|skip|from|startindex|start_index)$", re.I)
CURSOR_RESP_RE = re.compile(r"(endcursor|next_?cursor|nextcursor|cursor|next_?token|nextpagetoken|next_page_token|continuation)$", re.I)

UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I)
HEX_RE = re.compile(r"^[0-9a-f]{8,}$", re.I)
TOKEN_RE = re.compile(r"^[A-Za-z0-9_\-]{16,}$")
DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}([T ][\d:.]+Z?)?$")
PAGINATION_PARAM_RE = re.compile(
    r"^(page|p|pg|pagenum|page_?num(ber)?|pageindex|page_index|offset|start|skip|from|cursor|after|before|"
    r"since|until|max_?id|since_?id|limit|per_?page|page_?size|size|count|take|rows|first|last|next|"
    r"next_?token|next_?page|continuation|continuationtoken|pagetoken|page_?token|marker|startindex|start_index)$",
    re.I,
)
RESP_PAGINATION_KEYS = {
    "has_next", "hasnext", "has_more", "hasmore", "hasnextpage", "haspreviouspage", "next", "next_page", "nextpage",
    "next_cursor", "nextcursor", "cursor", "endcursor", "startcursor", "pageinfo", "total", "total_count",
    "totalcount", "total_pages", "totalpages", "total_results", "totalresults", "page", "pages", "offset",
    "limit", "per_page", "perpage", "page_size", "pagesize", "next_token", "nexttoken", "continuation",
    "links", "_links", "paging", "pagination", "meta",
}
TRACKER_HOSTS = (
    "google-analytics.com", "googletagmanager.com", "doubleclick.net", "googlesyndication.com", "googleadservices.com",
    "facebook.com/tr", "connect.facebook.net", "facebook.net", "hotjar.", "segment.io", "segment.com", "mixpanel.com",
    "amplitude.com", "sentry.io", "sentry-cdn", "newrelic.com", "nr-data.net", "bat.bing.com", "clarity.ms",
    "fullstory.com", "datadoghq", "browser-intake", "scorecardresearch", "quantserve", "criteo", "taboola", "outbrain",
    "analytics.tiktok", "ads.linkedin.com", "px.ads", "cloudflareinsights.com", "plausible.io", "matomo", "piwik",
    "adservice.google", "stats.g.doubleclick", "cdn.mxpnl", "heapanalytics", "optimizely", "branch.io", "braze",
    "onetrust", "cookielaw.org", "/cdn-cgi/rum", "/cdn-cgi/challenge-platform", "google.com/rmkt", "google.com/ccm",
    "google.com/pagead", "/collect?v=", "region1.google-analytics", "sb.scorecardresearch", "stats.wp.com", "gstatic.com/recaptcha", "recaptcha", "hs-analytics", "hubspot", "adsrvr",
    "quora.com/_/ad", "pinterest.com/ct", "snapchat.com/p", "yandex.ru/metrika", "mc.yandex",
)
API_TYPES = {"XHR", "Fetch", "EventSource"}
STATIC_TYPES = {"Image", "Stylesheet", "Font", "Media", "Script", "Manifest", "TextTrack", "Ping", "CSPViolationReport"}
JSON_MIME_RE = re.compile(r"json|graphql|ndjson", re.I)


# ------------------------------------------------------------------ normalisation

def norm_segment(seg: str) -> str:
    if not seg:
        return seg
    m = re.match(r"^(.+?)(\.(json|xml|html?|php|aspx?))$", seg, re.I)
    base, ext = (m.group(1), m.group(2)) if m else (seg, "")
    if base.isdigit() or UUID_RE.match(base) or (HEX_RE.match(base) and re.search(r"\d", base)):
        return "{id}" + ext
    if DATE_RE.match(base):
        return "{date}" + ext
    if TOKEN_RE.match(base) and re.search(r"\d", base) and re.search(r"[A-Za-z]", base) and not re.search(r"[-_]", base[:3]):
        # long mixed alnum chunk (hash / base64 id / slug-with-id)
        if sum(c.isdigit() for c in base) >= 3:
            return "{id}" + ext
    return seg


def norm_path(path: str) -> str:
    segs = (path or "/").split("/")
    return "/".join(norm_segment(s) for s in segs) or "/"


def is_tracker(url: str) -> bool:
    u = url.lower()
    return any(t in u for t in TRACKER_HOSTS)


def graphql_ops(rec) -> list[str] | None:
    """Return list of GraphQL operation names ([] if GraphQL but unnamed) or None if not GraphQL."""
    url = rec.get("url") or ""
    pd = rec.get("post_data") or ""
    ct = (rec.get("request_headers") or {}).get("content-type", "")
    path_gql = "graphql" in urlsplit(url).path.lower() or "graphql" in ct
    bodies = []
    if pd.strip()[:1] in "[{":
        try:
            b = json.loads(pd)
            bodies = b if isinstance(b, list) else [b]
        except ValueError:
            pass
    if not bodies and path_gql:
        q = dict(parse_qsl(urlsplit(url).query))
        if "query" in q or "operationName" in q or "extensions" in q:
            bodies = [q]
    ops = []
    is_gql = path_gql
    for b in bodies:
        if not isinstance(b, dict):
            continue
        qtext = b.get("query")
        if b.get("operationName"):
            ops.append(str(b["operationName"]))
            is_gql = True
        elif isinstance(qtext, str) and re.match(r"\s*(query|mutation|subscription|\{)", qtext):
            is_gql = True
            m = re.match(r"\s*(?:query|mutation|subscription)\s+(\w+)", qtext)
            if m:
                ops.append(m.group(1))
        elif isinstance(b.get("extensions"), (dict, str)) and "persistedQuery" in json.dumps(b.get("extensions")):
            is_gql = True
    return ops if is_gql else None


def is_api(rec, include_documents=False) -> bool:
    t = rec.get("resource_type")
    mime = rec.get("mime_type") or ""
    url = rec.get("url") or ""
    if t in API_TYPES:
        return True
    if t == "WebSocket":
        return False
    if JSON_MIME_RE.search(mime) and t not in ("Script",):
        return True
    path = urlsplit(url).path.lower()
    if t not in STATIC_TYPES and ("/api/" in path or path.endswith(".json") or "graphql" in path):
        return True
    if include_documents and t == "Document":
        return True
    if t == "Other" and rec.get("method") not in ("GET", None) and not is_tracker(url):
        return True
    return False


# ------------------------------------------------------------------ schema inference

def _t(v):
    if v is None:
        return "null"
    if isinstance(v, bool):
        return "boolean"
    if isinstance(v, int):
        return "integer"
    if isinstance(v, float):
        return "number"
    if isinstance(v, str):
        return "string"
    if isinstance(v, list):
        return "array"
    return "object"


def infer(v, depth=0):
    t = _t(v)
    if depth > 8:
        return {"type": t}
    if t == "object":
        keys = list(v.keys())
        if len(keys) > 5 and all(re.fullmatch(r"[0-9a-f\-]{1,40}", str(k), re.I) and re.search(r"\d", str(k)) for k in keys):
            ap = None
            for k in keys[:20]:
                ap = merge(ap, infer(v[k], depth + 1))
            return {"type": "object", "additionalProperties": ap, "key_pattern": "{id}", "key_count": len(keys)}
        props = OrderedDict()
        for k in keys[:100]:
            sub = infer(v[k], depth + 1)
            if REDACT_EXAMPLES and "example" in sub and is_sensitive_field(k):
                sub["example"] = REDACTED
            props[k] = sub
        return {"type": "object", "properties": props}
    if t == "array":
        items = None
        for x in v[:25]:
            items = merge(items, infer(x, depth + 1))
        out = {"type": "array", "length": len(v)}
        if items is not None:
            out["items"] = items
        return out
    out = {"type": t}
    if t == "string":
        out["example"] = v if len(v) <= 80 else v[:77] + "..."
    elif t in ("integer", "number", "boolean"):
        out["example"] = v
    return out


def merge(a, b):
    if a is None:
        return b
    if b is None:
        return a
    ta = a["type"] if isinstance(a["type"], list) else [a["type"]]
    tb = b["type"] if isinstance(b["type"], list) else [b["type"]]
    out = dict(a)
    types = sorted(set(ta) | set(tb))
    out["type"] = types[0] if len(types) == 1 else types
    if "properties" in a or "properties" in b:
        props = OrderedDict(a.get("properties", {}))
        for k, v in b.get("properties", {}).items():
            props[k] = merge(props.get(k), v)
        out["properties"] = props
    if "items" in a or "items" in b:
        out["items"] = merge(a.get("items"), b.get("items"))
    if "length" in a or "length" in b:
        out["length"] = max(a.get("length", 0), b.get("length", 0))
    if "additionalProperties" in b and "additionalProperties" in a:
        out["additionalProperties"] = merge(a["additionalProperties"], b["additionalProperties"])
    if "example" not in out and "example" in b:
        out["example"] = b["example"]
    return out


def find_record_arrays(v, path="", depth=0, out=None):
    """Find arrays of objects that look like record lists. Returns [(path, length, keys)]."""
    if out is None:
        out = []
    if depth > 7:
        return out
    if isinstance(v, list):
        objs = [x for x in v if isinstance(x, dict)]
        if objs and len(objs) >= max(1, int(len(v) * 0.8)):
            keys = []
            for o in objs[:25]:
                for k in o.keys():
                    if k not in keys:
                        keys.append(k)
            if len(objs) >= 2 or len(keys) >= 3:
                out.append((path, len(v), keys))
            for o in objs[:3]:
                for k, sub in o.items():
                    if isinstance(sub, (list, dict)):
                        find_record_arrays(sub, f"{path}[*].{k}" if path else f"[*].{k}", depth + 1, out)
    elif isinstance(v, dict):
        for k, sub in v.items():
            if isinstance(sub, (list, dict)):
                find_record_arrays(sub, f"{path}.{k}" if path else str(k), depth + 1, out)
    return out


def best_record_array(v):
    cands = [c for c in find_record_arrays(v) if "[*]" not in c[0]]
    if not cands:
        return None
    cands.sort(key=lambda c: (c[1] * max(1, len(c[2])), -c[0].count(".")), reverse=True)
    p, n, keys = cands[0]
    return {"path": p, "jsonpath": "$" + ("." + p if p else "") + "[*]", "length": n, "item_keys": keys[:40]}


def find_pagination_keys(v, prefix="", depth=0, out=None):
    if out is None:
        out = []
    if isinstance(v, dict) and depth <= 3:
        for k, sub in v.items():
            if str(k).lower() in RESP_PAGINATION_KEYS and not isinstance(sub, list):
                out.append(f"{prefix}{k}")
            if isinstance(sub, dict):
                find_pagination_keys(sub, f"{prefix}{k}.", depth + 1, out)
    return out


def schema_outline(s, indent=0, max_lines=40, lines=None, name="$"):
    if lines is None:
        lines = []
    if s is None or len(lines) >= max_lines:
        return lines
    t = s["type"] if isinstance(s["type"], str) else "|".join(s["type"])
    extra = ""
    if "length" in s:
        extra = f" (len {s['length']})"
    if "example" in s:
        ex = json.dumps(s["example"], ensure_ascii=False)
        extra += f" e.g. {ex[:60]}"
    lines.append("  " * indent + f"{name}: {t}{extra}")
    if "properties" in s:
        for k, v in s["properties"].items():
            if len(lines) >= max_lines:
                lines.append("  " * (indent + 1) + "...")
                break
            schema_outline(v, indent + 1, max_lines, lines, k)
    if "additionalProperties" in s and s["additionalProperties"]:
        schema_outline(s["additionalProperties"], indent + 1, max_lines, lines, "{id}")
    if "items" in s and s["items"]:
        schema_outline(s["items"], indent + 1, max_lines, lines, "[]")
    return lines


def body_shape(rec):
    pd = rec.get("post_data")
    if not pd:
        return None
    ct = (rec.get("request_headers") or {}).get("content-type", "")
    s = pd.strip()
    if s[:1] in "[{":
        try:
            obj = json.loads(s)
            shape = {"kind": "json", "schema": infer(obj)}
            if isinstance(obj, dict):
                shape["keys"] = list(obj.keys())[:50]
            return shape
        except ValueError:
            pass
    if "form-urlencoded" in ct or ("=" in s and not re.search(r"\s", s)):
        q = parse_qsl(s, keep_blank_values=True)
        if q:
            return {"kind": "form", "fields": {k: (v[:60] if v != REDACTED else v) for k, v in q[:60]}}
    if "multipart" in ct:
        return {"kind": "multipart", "fields": re.findall(r'name="([^"]+)"', s)[:60]}
    return {"kind": "text", "length": len(pd), "sample": pd[:200]}


# ------------------------------------------------------------------ build

def read_jsonl(path: Path):
    if not path.exists():
        return []
    out = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    out.append(json.loads(line))
                except ValueError:
                    pass
    return out


def read_body_bytes(run_dir: Path, rec) -> bytes | None:
    """Read a saved body, transparently decoding gzip/deflate/br/zstd (by Content-Encoding or magic bytes)."""
    bf = rec.get("body_file")
    if not bf:
        return None
    try:
        raw = (run_dir / bf).read_bytes()
    except OSError:
        return None
    try:
        return decode_body_bytes(raw, (rec.get("response_headers") or {}).get("content-encoding"))
    except Exception:
        return raw


def read_body_text(run_dir: Path, rec) -> str | None:
    raw = read_body_bytes(run_dir, rec)
    if raw is None:
        return None
    return raw.decode("utf-8", errors="replace")


def load_body_json(run_dir: Path, rec):
    bf = rec.get("body_file")
    if not bf or rec.get("body_truncated"):
        return None
    text = read_body_text(run_dir, rec)
    if text is None:
        return None
    if not text.strip() or text.lstrip()[:1] not in "[{)fw":
        return None
    try:
        return loads_lenient(text)
    except ValueError:
        return None


def endpoint_key(rec, ops):
    u = urlsplit(rec["url"])
    key = f"{rec.get('method', 'GET')} {u.netloc}{norm_path(u.path)}"
    if ops:
        key += f" [op:{','.join(sorted(set(ops)))}]"
    return key


def resolve_curl_redact(run_redacted: bool, curl_secrets: bool = False, curl_redact: bool = False) -> bool:
    """Default: curl placeholders unless the run was captured with --keep-secrets."""
    if curl_redact:
        return True
    if curl_secrets:
        if run_redacted:
            print("note: run was captured with redaction; secrets are not available, placeholders kept "
                  "(re-run mapper.py with --keep-secrets)", file=sys.stderr)
        return False
    return run_redacted


def emit_curls(run_dir: Path, recs, redact: bool, scope: str = "all") -> tuple[Path, int]:
    """Write every captured request as a one-line curl command to curls.sh (deduplicated)."""
    seen, lines, env = set(), [], {}
    for r in recs:
        url = r.get("url") or ""
        if not url.lower().startswith(("http://", "https://")) or r.get("resource_type") == "WebSocket":
            continue
        if scope == "api" and not is_api(r):
            continue
        if scope == "nonstatic" and r.get("resource_type") in STATIC_TYPES:
            continue
        c = build_curl(r.get("method") or "GET", url, r.get("request_headers"), r.get("post_data"), redact=redact)
        if c["oneline"] in seen:
            continue
        seen.add(c["oneline"])
        env.update(c["env"])
        tag = f"{r.get('resource_type') or '?'} {r.get('status') if r.get('status') is not None else r.get('state')}"
        lines.append(f"{c['oneline']}  # [{tag}] seq={r.get('seq')}")
    head = ["#!/usr/bin/env bash",
            f"# curl commands for every captured request ({len(lines)} unique, scope={scope}) - generated by web-network-mapper",
            "# One request per line: copy the line you need. Do NOT run this whole file against a live site.",
            f"# Secrets: {'replaced by shell variables (set them first)' if redact else 'REAL VALUES INCLUDED - keep this file private'}"]
    if env:
        head.append(env_comment(env))
    out = run_dir / "curls.sh"
    out.write_text("\n".join(head + [""] + lines) + "\n")
    return out, len(lines)


def build(run_dir, include_documents=False, emit_curl: str | None = None, curl_secrets: bool = False,
          curl_redact: bool = False, write_openapi: bool = True, write_json_schema: bool = True,
          write_postman: bool = True, write_html: bool = True, write_replay: bool = True,
          proto: str | None = None, descriptor: str | None = None, proto_message: str | None = None) -> dict:
    run_dir = Path(run_dir)
    recs = read_jsonl(run_dir / "requests.jsonl")
    # entradas WS/SSE (kind: websocket|sse) de otros capturadores: fuera del pipeline HTTP, solo para su sección
    recs_all = recs
    try:
        # solo se excluyen frames/eventos (sin status HTTP); la request HTTP de un EventSource se mantiene
        recs = [r for r in recs if isinstance(r, dict) and not (_is_stream_entry(r) and r.get("status") is None)]
    except Exception:
        recs = recs_all
    pages_path = run_dir / "pages.json"
    pages = json.loads(pages_path.read_text()) if pages_path.exists() else []
    meta = json.loads((run_dir / "run_meta.json").read_text()) if (run_dir / "run_meta.json").exists() else {}
    start_url = meta.get("start_url") or (pages[0]["url"] if pages else "")
    start_host = (urlsplit(start_url).hostname or "").lower()
    redacted = meta.get("redacted", True)
    global REDACT_EXAMPLES
    REDACT_EXAMPLES = redacted
    curl_red = resolve_curl_redact(redacted, curl_secrets, curl_redact)

    _TOKEN_ISSUES_CACHE.clear()
    try:
        _enrich_cookie_names(run_dir, recs)
    except Exception:
        pass
    eps: "OrderedDict[str, dict]" = OrderedDict()
    page_calls: dict[str, list] = {}
    for rec in recs:
        if not rec.get("url") or not is_api(rec, include_documents):
            continue
        ops = graphql_ops(rec)
        key = endpoint_key(rec, ops)
        u = urlsplit(rec["url"])
        ep = eps.get(key)
        if ep is None:
            ep = eps[key] = {
                "key": key, "method": rec.get("method"), "scheme": u.scheme, "host": u.netloc,
                "path_template": norm_path(u.path), "calls": 0, "statuses": Counter(),
                "resource_types": Counter(), "response_mime_types": Counter(), "request_content_types": Counter(),
                "example_urls": [], "query_params": OrderedDict(), "request_header_names": set(),
                "auth_headers": set(), "pages": [], "graphql_operations": set(), "is_graphql": ops is not None,
                "request_body": None, "response_schema": None, "response_top_keys": [], "records": None,
                "response_pagination_keys": set(), "sample_bodies": [], "failed": 0, "avg_duration_ms": None,
                "body_kinds": Counter(), "persisted_query": None, "rate_limit": None,
                "_pag_obs": [], "issues_token": [], "consumes_token": [], "set_cookies": set(),
                "response_is_array": False,
                "_durations": [], "_sizes": [], "_replay": None, "third_party": (u.hostname or "").lower() != start_host
                and not (u.hostname or "").lower().endswith("." + start_host.removeprefix("www.")),
                "likely_tracking": is_tracker(rec["url"]),
            }
        ep["calls"] += 1
        ep["statuses"][str(rec.get("status") if rec.get("status") is not None else rec.get("state"))] += 1
        ep["resource_types"][rec.get("resource_type") or "?"] += 1
        if rec.get("mime_type"):
            ep["response_mime_types"][rec["mime_type"]] += 1
        rh = rec.get("request_headers") or {}
        if rh.get("content-type"):
            ep["request_content_types"][rh["content-type"].split(";")[0]] += 1
        if rec["url"] not in ep["example_urls"] and len(ep["example_urls"]) < 5:
            ep["example_urls"].append(rec["url"])
        for k, v in parse_qsl(u.query, keep_blank_values=True):
            qp = ep["query_params"].setdefault(k, {"count": 0, "values": []})
            qp["count"] += 1
            if v not in qp["values"] and len(qp["values"]) < 10:
                qp["values"].append(v[:100])
        for h, v in rh.items():
            if h.startswith(":"):
                continue
            ep["request_header_names"].add(h)
            if is_sensitive_header(h) or h in ("x-requested-with",) and False:
                ep["auth_headers"].add(h)
        if rec.get("page") and rec["page"] not in ep["pages"]:
            ep["pages"].append(rec["page"])
        try:
            _scan_body_kind(ep, rec)
            _scan_rate_limit(ep, rec)
            _scan_token_consume(ep, rec, rh)
            _scan_token_issue(ep, rec, run_dir)
        except Exception:
            pass
        if ops:
            ep["graphql_operations"].update(ops)
        if ep["request_body"] is None:
            ep["request_body"] = body_shape(rec)
        if rec.get("state") == "failed":
            ep["failed"] += 1
        if rec.get("duration_ms") is not None:
            ep["_durations"].append(rec["duration_ms"])
        if rec.get("body_size") is not None:
            ep["_sizes"].append(rec["body_size"])
        body = load_body_json(run_dir, rec)
        rec_ra = best_record_array(body) if body is not None else None
        try:
            if isinstance(body, list):
                ep["response_is_array"] = True
            qd = {k: v for k, v in parse_qsl(u.query, keep_blank_values=True)}
            bpd = {}
            pd = rec.get("post_data") or ""
            if pd.strip()[:1] in "[{":
                try:
                    bpd = _flatten_scalars(json.loads(pd))
                except ValueError:
                    bpd = {}
            elif "=" in pd and not re.search(r"\s", pd):
                bpd = {"body:" + k: v for k, v in parse_qsl(pd, keep_blank_values=True)}
            rlen = rec_ra["length"] if rec_ra else (len(body) if isinstance(body, list) else None)
            rfp = None
            if body is not None:
                arr = get_path_simple(body, rec_ra["path"]) if rec_ra else (body if isinstance(body, list) else None)
                if isinstance(arr, list):
                    rfp = hash(json.dumps(arr[:50], sort_keys=True, default=str))
            if len(ep["_pag_obs"]) < 60:  # bounded: confirm_pagination is pairwise
                ep["_pag_obs"].append({"q": qd, "b": bpd, "rlen": rlen, "rfp": rfp})
        except Exception:
            pass
        if body is not None:
            if len(ep["sample_bodies"]) < 3 and rec.get("body_file"):
                ep["sample_bodies"].append(rec["body_file"])
            if ep["calls"] <= 10:
                ep["response_schema"] = merge(ep["response_schema"], infer(body))
            ra = rec_ra
            if ra and (ep["records"] is None or ra["length"] > ep["records"]["length"]):
                ep["records"] = ra
            if isinstance(body, dict):
                for k in body.keys():
                    if k not in ep["response_top_keys"] and len(ep["response_top_keys"]) < 60:
                        ep["response_top_keys"].append(k)
            ep["response_pagination_keys"].update(find_pagination_keys(body))
        elif rec.get("body_file") and len(ep["sample_bodies"]) < 3:
            ep["sample_bodies"].append(rec["body_file"])
        status = rec.get("status") or 0
        # replay/curl template: the FIRST call with the best score (2xx, then non-empty records)
        tscore = (200 <= status < 300, bool(rec_ra and rec_ra["length"] > 0) or bool(body) and rec_ra is None)
        if ep["_replay"] is None or tscore > ep["_replay_score"]:
            ep["_replay_score"] = tscore
            ep["_replay"] = {
                "url": rec["url"], "method": rec.get("method"),
                "headers": {k: v for k, v in rh.items() if not k.startswith(":")},
                "post_data": rec.get("post_data"), "status": rec.get("status"),
                "headers_redacted": bool(rec.get("redacted")),
            }
        if rec.get("page"):
            page_calls.setdefault(rec["page"], []).append({"endpoint": key, "url": rec["url"], "status": rec.get("status")})

    # finalize
    out_eps = []
    for ep in eps.values():
        pag_params = [k for k in ep["query_params"] if PAGINATION_PARAM_RE.match(k)]
        body_pag = []
        rb = ep["request_body"]
        if rb and rb.get("kind") == "json":
            def walk(s, pre=""):
                for k, v in (s.get("properties") or {}).items():
                    if PAGINATION_PARAM_RE.match(k):
                        body_pag.append(pre + k)
                    if isinstance(v, dict) and v.get("type") == "object":
                        walk(v, pre + k + ".")
            walk(rb["schema"])
        elif rb and rb.get("kind") == "form":
            body_pag = [k for k in rb["fields"] if PAGINATION_PARAM_RE.match(k)]
        for k, qp in ep["query_params"].items():
            qp["varies"] = len(qp["values"]) > 1
        mimes = " ".join(ep["response_mime_types"])
        returns_json = bool(JSON_MIME_RE.search(mimes)) or ep["response_schema"] is not None
        flags = []
        if ep["records"] and ep["records"]["length"] >= 2:
            flags.append("RECORDS")
        if ep["is_graphql"]:
            flags.append("GRAPHQL")
        if pag_params or body_pag:
            flags.append("PAGINATED")
        if ep["response_pagination_keys"]:
            flags.append("PAGINATION_IN_RESPONSE")
        if ep["auth_headers"] - {"cookie"}:
            flags.append("AUTH_HEADER")
        if ep["likely_tracking"]:
            flags.append("TRACKING")
        if ep["third_party"]:
            flags.append("THIRD_PARTY")
        if ep["body_kinds"].get("grpc"):
            flags.append("GRPC")
        if ep["body_kinds"].get("protobuf"):
            flags.append("PROTOBUF")
        if ep["persisted_query"]:
            flags.append("PERSISTED_QUERY")
        if ep["rate_limit"]:
            flags.append("RATE_LIMIT")
        if ep["issues_token"] and any(t["kind"] != "cookie" or t.get("session_like") for t in ep["issues_token"]):
            flags.append("ISSUES_TOKEN")
        try:
            pag_confirmed, confirmed_param = confirm_pagination(ep["_pag_obs"])
        except Exception:
            pag_confirmed, confirmed_param = False, None
        if pag_confirmed:
            flags.append("PAGINATION_CONFIRMED")
            if confirmed_param.startswith("body:"):
                leaf = confirmed_param[5:]
                if leaf not in body_pag:
                    body_pag.append(leaf)
            elif confirmed_param not in pag_params:
                pag_params.append(confirmed_param)
            if "PAGINATED" not in flags:
                flags.append("PAGINATED")
        likely_data = (not ep["likely_tracking"]) and returns_json and (
            "RECORDS" in flags or "GRAPHQL" in flags or "PAGINATED" in flags or "PAGINATION_IN_RESPONSE" in flags)
        if likely_data:
            flags.insert(0, "DATA")
        d = ep["_durations"]
        rp = ep["_replay"]
        pag_suggest, suggested_args = suggest_pagination(pag_params, body_pag, ep)
        final = OrderedDict([
            ("key", ep["key"]), ("method", ep["method"]), ("host", ep["host"]), ("scheme", ep["scheme"]),
            ("path_template", ep["path_template"]), ("flags", flags), ("likely_data_endpoint", likely_data),
            ("calls", ep["calls"]), ("failed", ep["failed"]), ("statuses", dict(ep["statuses"])),
            ("resource_types", dict(ep["resource_types"])), ("response_content_types", dict(ep["response_mime_types"])),
            ("request_content_types", dict(ep["request_content_types"])),
            ("example_urls", ep["example_urls"]), ("query_params", ep["query_params"]),
            ("pagination_params", pag_params), ("body_pagination_params", body_pag),
            ("suggested_paginate", pag_suggest), ("suggested_replay_args", suggested_args),
            ("request_body", ep["request_body"]),
            ("graphql_operations", sorted(ep["graphql_operations"])),
            ("auth_headers", sorted(ep["auth_headers"])),
            ("request_header_names", sorted(ep["request_header_names"])),
            ("response_top_keys", ep["response_top_keys"]),
            ("response_records", ep["records"]),
            ("response_pagination_keys", sorted(ep["response_pagination_keys"])),
            ("response_schema", ep["response_schema"]),
            ("sample_bodies", ep["sample_bodies"]),
            ("avg_duration_ms", round(sum(d) / len(d), 1) if d else None),
            ("avg_body_bytes", round(sum(ep["_sizes"]) / len(ep["_sizes"])) if ep["_sizes"] else None),
            ("pages", ep["pages"]),
            ("third_party", ep["third_party"]), ("likely_tracking", ep["likely_tracking"]),
            ("replay", rp),
        ])
        # ---- additive fields (improvements): keep existing keys/ordering above untouched
        try:
            final["role"] = classify_role(ep, final)
        except Exception:
            final["role"] = "OTHER"
        final["pagination_confirmed"] = bool(pag_confirmed)
        try:
            final["data_param"] = detect_data_param(dict(final, pagination_params=pag_params))
        except Exception:
            final["data_param"] = None
        final["confirmed_paginator"] = confirmed_param
        if pag_confirmed and not pag_suggest and confirmed_param:
            leaf = confirmed_param.split(":")[-1].split(".")[-1]
            if not CURSOR_PARAM_RE.match(leaf):
                pag_suggest = confirmed_param
                final["suggested_paginate"] = pag_suggest
                final["suggested_replay_args"] = f"--paginate {confirmed_param}"
        final["rate_limit"] = ep["rate_limit"]
        final["rate_limit_note"] = rate_limit_note(ep["rate_limit"])
        final["body_kind"] = (ep["body_kinds"].most_common(1)[0][0] if ep["body_kinds"] else
                              ("json" if returns_json else None))
        if ep.get("binary_body"):
            final["binary_body"] = ep["binary_body"]
        final["persisted_query"] = ep["persisted_query"]
        final["issues_token"] = ep["issues_token"][:10]
        final["consumes_token"] = ep["consumes_token"][:10]
        if rp:
            c = build_curl(rp.get("method") or ep["method"], rp["url"], rp.get("headers"),
                           rp.get("post_data") if (rp.get("method") or "GET").upper() not in ("GET", "HEAD") or rp.get("post_data") else None,
                           redact=curl_red)
            final["curl"] = c["multiline"]
            final["curl_oneline"] = c["oneline"]
            final["curl_env"] = c["env"]
        out_eps.append(final)

    def score(e):
        return (e["likely_data_endpoint"], not e["likely_tracking"], not e["third_party"],
                (e["response_records"] or {}).get("length", 0), e["calls"])
    out_eps.sort(key=score, reverse=True)
    for i, e in enumerate(out_eps, 1):
        e["index"] = i
    try:
        _decode_protobuf_endpoints(run_dir, out_eps, proto, descriptor, None, proto_message)
    except Exception:
        pass

    # websockets
    ws = OrderedDict()
    for w in read_jsonl(run_dir / "websockets.jsonl"):
        rid = w.get("request_id")
        if w.get("event") == "created":
            ws[rid] = {"url": w.get("url"), "page": w.get("page"), "frames_sent": 0, "frames_received": 0, "samples": []}
        elif w.get("event") == "frame" and rid in ws:
            ws[rid]["frames_" + w["direction"]] += 1
            if len(ws[rid]["samples"]) < 3:
                ws[rid]["samples"].append({"dir": w["direction"], "payload": (w.get("payload") or "")[:300]})

    # overall stats
    by_type = Counter(r.get("resource_type") for r in recs)
    by_host = Counter(urlsplit(r.get("url", "")).netloc for r in recs)
    blocked_types = {t.strip().lower() for t in (meta.get("args", {}).get("block") or "").split(",") if t.strip()}
    failed = [r for r in recs if r.get("state") == "failed" and not r.get("canceled")
              and (r.get("resource_type") or "").lower() not in blocked_types]
    templates = page_templates(pages)
    for p in pages:
        emb = embedded_data(run_dir, p, recs)
        if emb:
            p["embedded_data"] = emb

    api_map = OrderedDict([
        ("generated_by", "web-network-mapper/analyze.py"),
        ("run_dir", str(run_dir.resolve())), ("start_url", start_url),
        ("pages_visited", len([p for p in pages if not p.get("skipped")])), ("total_requests", len(recs)),
        ("requests_by_type", dict(by_type.most_common())), ("requests_by_host", dict(by_host.most_common(30))),
        ("redacted", redacted), ("curl_redacted", curl_red),
        ("endpoint_count", len(out_eps)), ("data_endpoint_count", sum(e["likely_data_endpoint"] for e in out_eps)),
        ("endpoints", out_eps), ("websockets", list(ws.values())),
        ("page_templates", templates),
        ("pages_with_embedded_data", {p["url"]: p["embedded_data"] for p in pages if p.get("embedded_data")}),
    ])
    # ---- additive sections (never fatal)
    try:
        api_map["auth_flow"] = build_auth_flow(run_dir, recs, include_documents)
    except Exception as e:
        api_map["auth_flow"] = {"tokens": [], "issuers": [], "consumers": [], "error": str(e)[:200]}
    try:
        api_map["anti_bot"] = build_anti_bot(run_dir, recs)
    except Exception as e:
        api_map["anti_bot"] = []
        api_map["anti_bot_error"] = str(e)[:200]
    rl_eps = [e for e in out_eps if e.get("rate_limit")]
    api_map["rate_limit_summary"] = {
        "endpoints_with_rate_limit": len(rl_eps), "status_429_total": sum((e["rate_limit"] or {}).get("status_429", 0) for e in rl_eps),
        "notes": [{"endpoint": e["key"], "note": e.get("rate_limit_note")} for e in rl_eps[:20]]}
    api_map["endpoint_roles"] = dict(Counter(e.get("role") or "OTHER" for e in out_eps if not e["likely_tracking"]))
    try:
        api_map["ws_sse"] = load_ws_sse(run_dir, recs_all)
    except Exception as e:
        api_map["ws_sse"] = []
        api_map["ws_sse_error"] = str(e)[:200]
    if proto or descriptor:
        try:
            dec_info = get_proto_decoder(proto, descriptor)
            api_map["protobuf_decoder"] = {"enabled": dec_info.enabled, "error": dec_info.error,
                                           "types": dec_info.type_names[:50], "proto": proto, "descriptor": descriptor}
        except Exception as e:
            api_map["protobuf_decoder"] = {"enabled": False, "error": str(e)[:200]}
    api_map["protobuf_decoded_endpoints"] = sum(1 for e in out_eps if e.get("protobuf_decoded"))
    if write_json_schema:
        try:
            js = build_json_schemas(run_dir, out_eps, start_url)
            if js:
                api_map["json_schema_file"] = js["file"]
                api_map["json_schema_dir"] = js["dir"]
                api_map["json_schema_count"] = js["count"]
        except Exception as e:
            api_map["json_schema_error"] = str(e)[:200]
    if write_openapi:
        try:
            if [e for e in out_eps if not e["likely_tracking"] and not e["third_party"]]:
                oa = build_openapi(api_map)
                (run_dir / "openapi.json").write_text(json.dumps(oa, indent=2, ensure_ascii=False, default=list))
                api_map["openapi_file"] = str((run_dir / "openapi.json").resolve())
                api_map["openapi_paths"] = len(oa.get("paths") or {})
        except Exception as e:
            api_map["openapi_error"] = str(e)[:200]
    if write_postman:
        try:
            if [e for e in out_eps if not e["likely_tracking"] and not e["third_party"]]:
                pm = build_postman(api_map, redact=curl_red)
                (run_dir / "postman_collection.json").write_text(json.dumps(pm, indent=2, ensure_ascii=False, default=list))
                api_map["postman_file"] = str((run_dir / "postman_collection.json").resolve())
                api_map["postman_requests"] = sum(len(f["item"]) for f in pm["item"])
        except Exception as e:
            api_map["postman_error"] = str(e)[:200]
    if write_replay:
        try:
            (run_dir / "replay.sh").write_text(build_replay_script(run_dir, out_eps, start_url))
            try:
                (run_dir / "replay.sh").chmod(0o755)
            except OSError:
                pass
            api_map["replay_script"] = str((run_dir / "replay.sh").resolve())
        except Exception as e:
            api_map["replay_script_error"] = str(e)[:200]
    flow = build_flow(run_dir, recs, curl_red, start_host)
    try:
        annotate_flow_tokens(run_dir, flow, recs)
    except Exception:
        pass
    (run_dir / "flow.sh").write_text(render_flow_sh(flow, start_url))
    for st in flow:
        st.pop("_post_data", None)
        st.pop("_rec", None)
    api_map["flow"] = flow
    api_map["flow_needs_human"] = any(s["needs_human"] for s in flow)
    (run_dir / "flow.md").write_text(render_flow_md(flow, start_url, curl_red))
    api_map["flow_md"] = str((run_dir / "flow.md").resolve())
    api_map["flow_sh"] = str((run_dir / "flow.sh").resolve())
    if emit_curl:
        cpath, n = emit_curls(run_dir, recs, curl_red, emit_curl)
        api_map["curls_file"] = str(cpath.resolve())
        api_map["curls_count"] = n
    elif (run_dir / "curls.sh").exists():
        api_map["curls_file"] = str((run_dir / "curls.sh").resolve())
    if write_html:
        try:
            api_map["html_file"] = str((run_dir / "report.html").resolve())
            (run_dir / "report.html").write_text(render_html(api_map, pages, failed, run_dir), encoding="utf-8")
        except Exception as e:
            api_map.pop("html_file", None)
            api_map["html_error"] = str(e)[:200]
    (run_dir / "api_map.json").write_text(json.dumps(api_map, indent=2, ensure_ascii=False, default=list))

    # enrich pages.json
    for p in pages:
        calls = page_calls.get(p.get("url"), [])
        p["api_calls"] = calls[:500]
        p["api_endpoints"] = sorted({c["endpoint"] for c in calls})
    if pages_path.exists():
        pages_path.write_text(json.dumps(pages, indent=2, ensure_ascii=False))

    (run_dir / "api_map.md").write_text(render_md(api_map, pages, failed, run_dir))
    return {"endpoints": len(out_eps), "data_endpoints": api_map["data_endpoint_count"],
            "curls_file": api_map.get("curls_file"), "flow_steps": len(flow),
            "flow_needs_human": api_map["flow_needs_human"], "flow_md": api_map["flow_md"],
            "openapi_file": api_map.get("openapi_file"),
            "auth_tokens": len((api_map.get("auth_flow") or {}).get("tokens") or []),
            "anti_bot": [a["vendor"] for a in api_map.get("anti_bot") or []],
            "rate_limited_endpoints": api_map["rate_limit_summary"]["endpoints_with_rate_limit"],
            "roles": api_map.get("endpoint_roles"),
            "json_schema": api_map.get("json_schema_file"),
            "json_schema_count": api_map.get("json_schema_count", 0),
            "postman_file": api_map.get("postman_file"),
            "html_file": api_map.get("html_file"),
            "replay_script": api_map.get("replay_script"),
            "data_params": {e["key"]: f"{e['data_param']['in']}:{e['data_param']['name']}"
                            for e in out_eps if e.get("data_param") and not e["likely_tracking"]},
            "protobuf_decoded_endpoints": api_map.get("protobuf_decoded_endpoints", 0),
            "ws_sse_streams": len(api_map.get("ws_sse") or []),
            "api_map_json": str((run_dir / "api_map.json").resolve()),
            "api_map_md": str((run_dir / "api_map.md").resolve())}


# ------------------------------------------------------------------ extra analysis (additive, best-effort)

RATE_HDR_RE = re.compile(r"^(retry-after|x-ratelimit-[a-z-]+|ratelimit(-[a-z-]+)?|x-rate-limit-[a-z-]+|x-ratelimit)$", re.I)
TOKEN_BODY_KEY_RE = re.compile(r"^(access_?token|id_?token|refresh_?token|jwt|auth_?token|token|bearer|session_?token|"
                               r"csrf_?token|xsrf_?token|_csrf|authenticity_token)$", re.I)
JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{4,}")
SESSION_COOKIE_RE = re.compile(r"sess|sid$|^sid|jsessionid|phpsessid|asp\.net_sessionid|csrf|xsrf|token|auth|jwt|login", re.I)
CSRF_HEADER_RE = re.compile(r"^x-(csrf|xsrf)-token$|^x-csrftoken$|^csrf-token$|^x-requested-token$", re.I)
HIDDEN_TOKEN_FIELDS = ("javax.faces.ViewState", "__VIEWSTATE", "__EVENTVALIDATION", "__RequestVerificationToken",
                       "authenticity_token", "csrf_token", "_csrf", "csrfmiddlewaretoken", "_token", "csrf")
SEARCH_PARAM_RE = re.compile(r"^(q|query|search|keyword|keywords|term|s|buscar|busqueda|text|filter|find)$", re.I)
SEARCH_PATH_RE = re.compile(r"search|buscar|busqueda|/find|/query|autocomplete|suggest", re.I)


def _flatten_scalars(o, pre="", out=None, depth=0):
    """Flatten a JSON body to {"body:a.b": scalar} (used to compare paginated calls)."""
    if out is None:
        out = {}
    if depth > 6:
        return out
    if isinstance(o, dict):
        for k, v in o.items():
            _flatten_scalars(v, f"{pre}{k}." if not isinstance(v, (str, int, float, bool)) and v is not None else f"{pre}{k}",
                             out, depth + 1)
    elif isinstance(o, list):
        out["body:" + pre.rstrip(".") + "[]"] = json.dumps(o, sort_keys=True)[:200]
    else:
        out["body:" + pre.rstrip(".")] = o
    return out


def _cookie_names_from(value) -> list[str]:
    names = []
    for line in re.split(r"\n", str(value or "")):
        for part in (line.split(";")[:1] if "=" in line.split(";")[0] else []):
            nm = part.split("=", 1)[0].strip()
            if nm and nm != REDACTED:
                names.append(nm)
    return names


def _req_cookie_names(rec) -> list[str]:
    if rec.get("request_cookie_names"):
        return list(rec["request_cookie_names"])
    ck = (rec.get("request_headers") or {}).get("cookie") or ""
    if not ck or ck == REDACTED:
        return list(rec.get("_har_req_cookies") or [])
    return [p.split("=", 1)[0].strip() for p in ck.split(";") if "=" in p]


def _set_cookie_names(rec) -> list[str]:
    if rec.get("set_cookie_names"):
        return list(rec["set_cookie_names"])
    sc = (rec.get("response_headers") or {}).get("set-cookie") or ""
    if not sc or sc == REDACTED:
        return list(rec.get("_har_set_cookies") or [])
    return _cookie_names_from(sc)


def _scan_body_kind(ep, rec):
    rh = rec.get("request_headers") or {}
    kind = rec.get("body_kind") or detect_body_kind(rec.get("mime_type") or (rec.get("response_headers") or {}).get("content-type")) \
        or detect_body_kind(rh.get("content-type"))
    if kind:
        ep["body_kinds"][kind] += 1
        info = ep.setdefault("binary_body", {"content_types": [], "sizes": []})
        for ct in (rec.get("mime_type"), rh.get("content-type")):
            if ct and ct not in info["content_types"]:
                info["content_types"].append(ct)
        if rec.get("body_size") is not None and len(info["sizes"]) < 10:
            info["sizes"].append(rec["body_size"])
    # GraphQL persisted query: extensions.persistedQuery.sha256Hash and no query text
    pq = persisted_query(rec)
    if pq and ep["persisted_query"] is None:
        ep["persisted_query"] = pq


def persisted_query(rec) -> dict | None:
    """Return {sha256Hash, version, operationName, transport} for an APQ / persisted GraphQL request, else None."""
    try:
        bodies = []
        pd = rec.get("post_data") or ""
        if pd.strip()[:1] in "[{":
            try:
                b = json.loads(pd)
                bodies = b if isinstance(b, list) else [b]
            except ValueError:
                bodies = []
        transport = "body"
        if not bodies:
            q = dict(parse_qsl(urlsplit(rec.get("url") or "").query, keep_blank_values=True))
            if "extensions" in q:
                ext = q.get("extensions")
                try:
                    ext = json.loads(ext)
                except ValueError:
                    ext = None
                bodies = [{"extensions": ext, "query": q.get("query"), "operationName": q.get("operationName")}]
                transport = "query-string (GET)"
        for b in bodies:
            if not isinstance(b, dict):
                continue
            ext = b.get("extensions")
            if isinstance(ext, str):
                try:
                    ext = json.loads(ext)
                except ValueError:
                    ext = None
            pqd = (ext or {}).get("persistedQuery") if isinstance(ext, dict) else None
            if isinstance(pqd, dict) and pqd.get("sha256Hash") and not b.get("query"):
                return {"sha256Hash": pqd.get("sha256Hash"), "version": pqd.get("version"),
                        "operationName": b.get("operationName"), "transport": transport}
    except Exception:
        return None
    return None


def _scan_rate_limit(ep, rec):
    st = rec.get("status")
    hdrs = {k: v for k, v in (rec.get("response_headers") or {}).items() if RATE_HDR_RE.match(k)}
    if st != 429 and not hdrs:
        return
    rl = ep["rate_limit"] or {"status_429": 0, "headers": {}}
    if st == 429:
        rl["status_429"] += 1
    for k, v in hdrs.items():
        rl["headers"][k] = str(v)[:80]
    h = rl["headers"]

    def pick(*names):
        for n in names:
            for k, v in h.items():
                if k.lower() == n:
                    return v
        return None
    rl["limit"] = pick("x-ratelimit-limit", "ratelimit-limit", "x-rate-limit-limit")
    rl["remaining"] = pick("x-ratelimit-remaining", "ratelimit-remaining", "x-rate-limit-remaining")
    rl["reset"] = pick("x-ratelimit-reset", "ratelimit-reset", "x-rate-limit-reset")
    rl["retry_after"] = pick("retry-after")
    ep["rate_limit"] = rl


def rate_limit_note(rl) -> str | None:
    if not rl:
        return None
    parts = []
    if rl.get("status_429"):
        parts.append(f"{rl['status_429']}×429")
    if rl.get("limit"):
        parts.append(f"límite {rl['limit']}")
    if rl.get("remaining") is not None:
        parts.append(f"restantes {rl['remaining']}")
    if rl.get("reset"):
        parts.append(f"reset {rl['reset']}")
    if rl.get("retry_after"):
        parts.append(f"retry-after {rl['retry_after']}")
    if not parts:
        parts.append("headers: " + ", ".join(rl.get("headers", {}).keys()))
    return " · ".join(parts)


def _scan_token_consume(ep, rec, rh):
    for h, v in rh.items():
        hl = h.lower()
        if hl == "authorization":
            scheme = str(v).split(" ", 1)[0] if v and v != REDACTED else ("Bearer?" if v == REDACTED else "")
            ent = {"kind": "authorization", "name": "Authorization", "detail": scheme or "?"}
        elif CSRF_HEADER_RE.match(hl):
            ent = {"kind": "csrf-header", "name": h, "detail": ""}
        elif hl in ("x-api-key", "x-auth-token", "x-access-token", "x-session-token", "x-goog-api-key", "apikey", "api-key"):
            ent = {"kind": "api-header", "name": h, "detail": ""}
        else:
            continue
        if ent not in ep["consumes_token"]:
            ep["consumes_token"].append(ent)


def _hidden_fields(html: str) -> dict:
    """{name: value} of hidden inputs that carry one-time tokens (ViewState, CSRF ...)."""
    out = {}
    for m in re.finditer(r"<input\b[^>]*>", html, re.I):
        tag = m.group(0)
        nm = re.search(r'\bname=["\']([^"\']+)["\']', tag, re.I)
        if not nm:
            continue
        name = nm.group(1)
        if name in HIDDEN_TOKEN_FIELDS or re.search(r"csrf|xsrf|viewstate|verificationtoken|authenticity", name, re.I):
            val = re.search(r'\bvalue=["\']([^"\']*)["\']', tag, re.I)
            out[name] = val.group(1) if val else ""
    # JSF partial responses: <update id="...javax.faces.ViewState..."><![CDATA[value]]></update>
    for m in re.finditer(r'<update id="([^"]*ViewState[^"]*)"><!\[CDATA\[(.*?)\]\]>', html, re.S):
        out.setdefault("javax.faces.ViewState", m.group(2)[:200])
    return out


def _scan_token_issue(ep, rec, run_dir):
    """Record tokens this endpoint's response issues (body token fields, JWTs, session/csrf cookies)."""
    for ent in token_issues(run_dir, rec):
        if ent not in ep["issues_token"]:
            ep["issues_token"].append(ent)


_TOKEN_ISSUES_CACHE: dict = {}


def token_issues(run_dir, rec, include_refresh: bool = False) -> list[dict]:
    ck = (str(run_dir), rec.get("seq"), rec.get("request_id"), include_refresh)
    if rec.get("seq") is not None and ck in _TOKEN_ISSUES_CACHE:
        return [dict(x) for x in _TOKEN_ISSUES_CACHE[ck]]
    res = _token_issues(run_dir, rec, include_refresh)
    if rec.get("seq") is not None:
        _TOKEN_ISSUES_CACHE[ck] = [dict(x) for x in res]
    return res


def _token_issues(run_dir, rec, include_refresh: bool = False) -> list[dict]:
    out = []
    sent = set(_req_cookie_names(rec))
    for nm in _set_cookie_names(rec):
        if nm in sent and not include_refresh:
            continue  # the request already carried this cookie: a refresh, not a new issuance
        out.append({"kind": "cookie", "name": nm, "session_like": bool(SESSION_COOKIE_RE.search(nm))})
    for h in (rec.get("response_headers") or {}):
        if CSRF_HEADER_RE.match(h) or h.lower() in ("x-auth-token", "x-access-token", "authorization"):
            out.append({"kind": "header", "name": h})
    if rec.get("body_file") and (rec.get("resource_type") in ("XHR", "Fetch", "Document", "Other")
                                 or JSON_MIME_RE.search(rec.get("mime_type") or "")):
        text = None
        try:
            text = read_body_text(Path(run_dir), rec)
        except Exception:
            text = None
        if text:
            body = None
            if text.lstrip()[:1] in "[{)fw":
                try:
                    body = loads_lenient(text)
                except ValueError:
                    body = None
            if body is not None:
                for path in _token_paths(body):
                    out.append({"kind": "json", "name": path.split(".")[-1], "path": path})
            if "html" in (rec.get("mime_type") or "") or "xml" in (rec.get("mime_type") or "") or text.lstrip()[:1] == "<":
                for name in _hidden_fields(text[:2_000_000]):
                    out.append({"kind": "hidden-field", "name": name})
            if body is None and JWT_RE.search(text[:200_000]) and not any(o["kind"] == "json" for o in out):
                out.append({"kind": "jwt-in-body", "name": "jwt"})
    # dedupe preserving order
    seen, res = set(), []
    for o in out:
        k = (o["kind"], o["name"], o.get("path"))
        if k not in seen:
            seen.add(k)
            res.append(o)
    return res


def _token_value(run_dir, rec, iss) -> str | None:
    """Actual token value from a saved response body (kept in memory only; used to verify consumers)."""
    try:
        if iss.get("kind") != "json" or not iss.get("path"):
            return None
        body = load_body_json(Path(run_dir), rec)
        v = get_path(body, iss["path"].replace("[0]", ".0"))
        return v if isinstance(v, str) and len(v) >= 6 and v != REDACTED else None
    except Exception:
        return None


def _token_paths(v, pre="", depth=0, out=None):
    if out is None:
        out = []
    if depth > 5 or len(out) > 10:
        return out
    if isinstance(v, dict):
        for k, sub in v.items():
            p = f"{pre}.{k}" if pre else str(k)
            if isinstance(sub, str) and sub and (TOKEN_BODY_KEY_RE.match(str(k)) or JWT_RE.fullmatch(sub)):
                out.append(p)
            elif isinstance(sub, (dict, list)):
                _token_paths(sub, p, depth + 1, out)
    elif isinstance(v, list) and v and isinstance(v[0], dict) and depth < 2:
        _token_paths(v[0], pre + "[0]" if pre else "[0]", depth + 1, out)
    return out


def _consumed_tokens(rec) -> list[dict]:
    """Tokens a request sends: Authorization, CSRF headers, cookies, hidden token form fields."""
    out = []
    rh = rec.get("request_headers") or {}
    for h, v in rh.items():
        hl = h.lower()
        if hl == "authorization":
            out.append({"kind": "authorization", "name": "Authorization",
                        "scheme": (str(v).split(" ", 1)[0] if v and v != REDACTED else None)})
        elif CSRF_HEADER_RE.match(hl) or hl in ("x-auth-token", "x-access-token", "x-api-key"):
            out.append({"kind": "header", "name": h})
    for nm in _req_cookie_names(rec):
        out.append({"kind": "cookie", "name": nm})
    pd = rec.get("post_data") or ""
    if pd and pd.strip()[:1] not in "[{" and "=" in pd:
        for k, _v in parse_qsl(pd, keep_blank_values=True):
            if k in HIDDEN_TOKEN_FIELDS or re.search(r"csrf|xsrf|viewstate|verificationtoken|authenticity", k, re.I):
                out.append({"kind": "hidden-field", "name": k})
    elif pd.strip()[:1] == "{":
        try:
            b = json.loads(pd)
            if isinstance(b, dict):
                for k in b:
                    if re.search(r"csrf|xsrf|_token$|^token$", str(k), re.I):
                        out.append({"kind": "json-field", "name": k})
        except ValueError:
            pass
    return out


def _har_cookie_index(run_dir: Path) -> dict:
    """(method, url) -> [(req_cookie_names, set_cookie_names), ...] from network.har (names only)."""
    idx: dict = {}
    p = run_dir / "network.har"
    if not p.exists() or p.stat().st_size > 400_000_000:
        return idx
    try:
        har = json.loads(p.read_text(encoding="utf-8", errors="replace"))
    except Exception:
        return idx
    for ent in har.get("log", {}).get("entries", []):
        rq, rs = ent.get("request") or {}, ent.get("response") or {}
        rc = [c.get("name") for c in rq.get("cookies", []) if c.get("name")]
        sc = [c.get("name") for c in rs.get("cookies", []) if c.get("name")]
        if rc or sc:
            idx.setdefault((rq.get("method"), rq.get("url")), []).append((rc, sc))
    return idx


def build_auth_flow(run_dir: Path, recs, include_documents=False) -> dict:
    """Which requests ISSUE a token (session cookie, access_token/JWT, CSRF/ViewState) and which CONSUME it."""
    ordered = sorted(recs, key=lambda r: r.get("seq", 0))
    tokens: "OrderedDict[tuple, dict]" = OrderedDict()
    bearer_issuers = []

    def label(rec):
        try:
            return endpoint_key(rec, graphql_ops(rec))
        except Exception:
            return f"{rec.get('method')} {rec.get('url')}"

    for rec in ordered:
        if not rec.get("url"):
            continue
        static = rec.get("resource_type") in STATIC_TYPES
        # ---- issue
        if not static or _set_cookie_names(rec):
            for iss in token_issues(run_dir, rec):
                if iss["kind"] == "cookie":
                    key = ("cookie", iss["name"])
                    via = "Set-Cookie"
                elif iss["kind"] == "hidden-field":
                    key = ("hidden-field", iss["name"])
                    via = "campo oculto en el HTML/respuesta"
                elif iss["kind"] == "header":
                    key = ("header", iss["name"].lower())
                    via = f"header de respuesta {iss['name']}"
                else:  # json / jwt
                    key = ("bearer", iss.get("path") or iss["name"])
                    via = f"cuerpo JSON `{iss.get('path') or iss['name']}`"
                    bearer_issuers.append((rec.get("seq"), iss, label(rec), _token_value(run_dir, rec, iss)))
                t = tokens.setdefault(key, {"kind": key[0], "name": iss["name"], "issued_by": [], "consumed_by": OrderedDict(),
                                            "static_consumers": 0, "session_like": iss.get("session_like")})
                if len(t["issued_by"]) < 5:
                    t["issued_by"].append({"endpoint": label(rec), "seq": rec.get("seq"), "status": rec.get("status"), "via": via,
                                           "path": iss.get("path")})
        # ---- consume
        for c in _consumed_tokens(rec):
            if c["kind"] == "cookie":
                key = ("cookie", c["name"])
                if key not in tokens:
                    continue  # cookie never seen being set in this capture (pre-existing): reported below
            elif c["kind"] == "hidden-field":
                key = ("hidden-field", c["name"])
            elif c["kind"] == "authorization":
                prev = [b for b in bearer_issuers if (b[0] or 0) < (rec.get("seq") or 0)]
                hv = str((rec.get("request_headers") or {}).get("authorization") or "")
                verifiable = hv and REDACTED not in hv
                if verifiable:
                    prev = [b for b in prev if b[3] and b[3] in hv]  # the header really carries that token
                    c["verified"] = bool(prev)
                else:
                    c["verified"] = None  # values redacted at capture: attribution is only probable
                key = ("bearer", prev[-1][1].get("path") or prev[-1][1]["name"]) if prev else ("authorization", "Authorization")
            else:
                key = ("header", c["name"].lower())
            t = tokens.setdefault(key, {"kind": key[0], "name": c["name"] if key[0] != "bearer" else key[1].split(".")[-1],
                                        "issued_by": [], "consumed_by": OrderedDict(), "static_consumers": 0, "session_like": None})
            if static:
                t["static_consumers"] += 1
                continue
            lab = label(rec)
            cb = t["consumed_by"].setdefault(lab, {"endpoint": lab, "count": 0, "first_seq": rec.get("seq"),
                                                   "via": {"cookie": f"Cookie: {c['name']}", "authorization":
                                                           f"Authorization: {c.get('scheme') or 'Bearer'} …",
                                                           "hidden-field": f"campo de formulario {c['name']}",
                                                           "json-field": f"campo JSON {c['name']}"}.get(c["kind"], f"header {c['name']}")})
            cb["count"] += 1
            if c["kind"] == "authorization" and key[0] == "bearer":
                cb["verified"] = c.get("verified")
    out_tokens = []
    for (kind, _n), t in tokens.items():
        consumers = list(t["consumed_by"].values())
        if not t["issued_by"] and not consumers:
            continue
        if kind == "cookie" and not consumers and not t["session_like"]:
            continue  # a cookie nobody sends back to an API / page: noise
        if kind == "hidden-field" and not consumers and not t["issued_by"]:
            continue
        out_tokens.append({
            "kind": kind, "name": t["name"], "session_like": t["session_like"],
            "issued_by": t["issued_by"], "consumed_by": consumers[:30],
            "consumer_count": sum(c["count"] for c in consumers), "static_consumers": t["static_consumers"],
            "carried_by": {"cookie": "cookie jar (curl -b/-c)", "bearer": "header Authorization: Bearer",
                           "authorization": "header Authorization", "hidden-field": "campo de formulario (extraer del HTML previo)",
                           "header": "header HTTP"}.get(kind, kind),
        })
    issuers = sorted({i["endpoint"] for t in out_tokens for i in t["issued_by"]})
    consumers = sorted({c["endpoint"] for t in out_tokens for c in t["consumed_by"]})
    return {"tokens": out_tokens, "issuers": issuers, "consumers": consumers,
            "has_bearer": any(t["kind"] in ("bearer", "authorization") for t in out_tokens),
            "has_session_cookie": any(t["kind"] == "cookie" and t["session_like"] for t in out_tokens),
            "has_csrf": any(t["kind"] == "hidden-field" or (t["kind"] == "header" and "csrf" in t["name"].lower()
                                                            or "xsrf" in t["name"].lower()) for t in out_tokens)}


def classify_role(ep, final) -> str:
    """SEARCH / LIST / DETAIL heuristics (fallback ACTION for non-GET mutations, OTHER otherwise)."""
    qp = list(final.get("query_params") or {})
    rb = final.get("request_body") or {}
    body_keys = list(rb.get("keys") or rb.get("fields") or []) if isinstance(rb, dict) else []
    ops = " ".join(final.get("graphql_operations") or [])
    if final.get("graphql_operations") or ep.get("is_graphql"):
        # GraphQL envelopes always carry query/variables/operationName: judge by variables + op name
        body_keys = []
        qp = [k for k in qp if k not in ("query", "variables", "operationName", "extensions")]
        try:
            vs = ((rb.get("schema") or {}).get("properties") or {}).get("variables") or {}
            body_keys = list((vs.get("properties") or {}).keys())
        except Exception:
            body_keys = []
    path = final.get("path_template") or ""
    recs = final.get("response_records") or {}
    if any(SEARCH_PARAM_RE.match(k) for k in qp + body_keys) or SEARCH_PATH_RE.search(path) or re.search(r"search|buscar", ops, re.I):
        return "SEARCH"
    segs = [x for x in path.split("/") if x]
    paginated = bool(final.get("pagination_params") or final.get("body_pagination_params"))
    if segs and segs[-1].startswith("{id}") and not paginated:
        return "DETAIL"  # /things/{id}: one resource (nested arrays in it are sub-records)
    many = (recs.get("length") or 0) >= 2 or ep.get("response_is_array")
    if many or paginated or re.search(r"^(list|get\w*s)$|list", ops, re.I):
        return "LIST"
    if segs and (segs[-1].startswith("{date}")) or "{id}" in path:
        return "DETAIL"
    if final.get("response_schema") and (final["response_schema"].get("type") == "object"):
        return "DETAIL" if (final.get("method") or "GET").upper() == "GET" else "ACTION"
    return "ACTION" if (final.get("method") or "GET").upper() not in ("GET", "HEAD") else "OTHER"


def confirm_pagination(obs) -> tuple[bool, str | None]:
    """Two captured calls that differ only in ONE numeric/cursor param, with different record arrays,
    confirm that param as the paginator. Returns (confirmed, param_name) (body params as 'body:<path>')."""
    def is_pagish(k, a, b):
        leaf = k.split(":")[-1].split(".")[-1]
        numeric = all(re.fullmatch(r"-?\d+", str(x)) for x in (a, b) if x not in (None, ""))
        cursorish = all(isinstance(x, str) and len(x) >= 4 for x in (a, b) if x not in (None, ""))
        return bool(PAGINATION_PARAM_RE.match(leaf)) or numeric or (cursorish and CURSOR_PARAM_RE.match(leaf))
    for i in range(len(obs)):
        for j in range(i + 1, len(obs)):
            a, b = obs[i], obs[j]
            if a.get("rfp") is None or b.get("rfp") is None or a["rfp"] == b["rfp"]:
                continue
            da, db = dict(a["q"]), dict(b["q"])
            da.update(a["b"])
            db.update(b["b"])
            keys = set(da) | set(db)
            diff = [k for k in keys if da.get(k) != db.get(k)]
            if len(diff) == 1 and is_pagish(diff[0], da.get(diff[0]), db.get(diff[0])):
                return True, diff[0]
    return False, None


def build_anti_bot(run_dir: Path, recs) -> list[dict]:
    """Aggregate anti-bot vendor detections over all captured requests (headers, cookies, bodies, URLs)."""
    agg: "OrderedDict[str, dict]" = OrderedDict()
    for rec in recs:
        try:
            url = rec.get("url") or ""
            hdrs = dict(rec.get("response_headers") or {})
            cookies = _req_cookie_names(rec) + _set_cookie_names(rec)
            hdrs.pop("set-cookie", None)
            hdrs.pop("cookie", None)
            body = ""
            t = rec.get("resource_type")
            if rec.get("body_file") and t in ("Document", "XHR", "Fetch", "Script", "Other") and (rec.get("body_size") or 0) < 3_000_000:
                body = read_body_text(run_dir, rec) or ""
            st = rec.get("status") if t == "Document" else None
            found = detect_anti_bot(hdrs, body, cookies, status=st, url=url)
        except Exception:
            continue
        for d in found:
            a = agg.setdefault(d["vendor"], {"vendor": d["vendor"], "evidence": [], "active": False, "strategy": d["strategy"],
                                             "requests": 0, "example_urls": []})
            a["requests"] += 1
            for ev in d["evidence"]:
                if ev not in a["evidence"] and len(a["evidence"]) < 12:
                    a["evidence"].append(ev)
            if d.get("active") and not a["active"]:
                a["active"] = True
                a["strategy"] = d["strategy"]
            if url and len(a["example_urls"]) < 3 and url not in a["example_urls"]:
                a["example_urls"].append(url[:200])
    return sorted(agg.values(), key=lambda a: (not a["active"], -a["requests"]))


# ------------------------------------------------------------------ OpenAPI export

def _oa_schema(s, depth=0):
    """Convert an inferred schema (infer/merge format) to an OpenAPI 3.0 schema object."""
    if not isinstance(s, dict) or depth > 12:
        return {}
    t = s.get("type")
    types = t if isinstance(t, list) else [t]
    nullable = "null" in types
    types = [x for x in types if x and x != "null"]
    if len(types) > 1:
        out = {"oneOf": [_oa_schema(dict(s, type=x), depth + 1) for x in types]}
        if nullable:
            out["nullable"] = True
        return out
    tt = types[0] if types else None
    out: dict = {}
    if tt is None:
        out = {"nullable": True}
        return out
    out["type"] = tt
    if nullable:
        out["nullable"] = True
    if tt == "object":
        if s.get("properties"):
            out["properties"] = {str(k): _oa_schema(v, depth + 1) for k, v in s["properties"].items()}
        if s.get("additionalProperties"):
            out["additionalProperties"] = _oa_schema(s["additionalProperties"], depth + 1)
    elif tt == "array":
        out["items"] = _oa_schema(s["items"], depth + 1) if s.get("items") else {}
    elif "example" in s and s["example"] != REDACTED:
        out["example"] = s["example"]
    return out


def _oa_param_schema(values):
    vals = [v for v in values if v not in ("", None, REDACTED)]
    if vals and all(re.fullmatch(r"-?\d+", v) for v in vals):
        return {"type": "integer", "example": int(vals[0])}
    if vals and all(v.lower() in ("true", "false") for v in vals):
        return {"type": "boolean"}
    sch = {"type": "string"}
    if vals:
        sch["example"] = vals[0]
    return sch


def build_openapi(api_map) -> dict:
    """OpenAPI 3.0 document from discovered endpoints (skips tracking / third-party)."""
    eps = [e for e in api_map.get("endpoints", []) if not e.get("likely_tracking") and not e.get("third_party")]
    servers = []
    for e in eps:
        srv = f"{e.get('scheme') or 'https'}://{e['host']}"
        if srv not in servers:
            servers.append(srv)
    paths: "OrderedDict[str, dict]" = OrderedDict()
    components: "OrderedDict[str, dict]" = OrderedDict()
    used_ids = set()
    for e in eps:
        # unique path parameter names: {id}, {id2}, {date} ...
        counts = Counter()

        def _pp(m):
            nm = m.group(1)
            counts[nm] += 1
            return "{" + (nm if counts[nm] == 1 else f"{nm}{counts[nm]}") + "}"
        path = re.sub(r"\{(id|date|slug)\}", _pp, e.get("path_template") or "/")
        path_params = re.findall(r"\{([A-Za-z0-9_]+)\}", path)
        if len(servers) > 1 and servers[0] != f"{e.get('scheme') or 'https'}://{e['host']}":
            pass  # still keyed by path; x-host records the real host
        method = (e.get("method") or "GET").lower()
        if method not in ("get", "put", "post", "delete", "options", "head", "patch", "trace"):
            continue
        op_name = "_".join(e.get("graphql_operations") or []) or ""
        base_id = re.sub(r"[^A-Za-z0-9]+", "_", f"{method}_{path}_{op_name}").strip("_") or f"op_{e.get('index')}"
        oid, n = base_id, 2
        while oid in used_ids:
            oid, n = f"{base_id}_{n}", n + 1
        used_ids.add(oid)
        op: dict = {"operationId": oid, "summary": e.get("key"),
                    "tags": [e.get("role") or "OTHER"],
                    "x-wnm-flags": e.get("flags") or [], "x-wnm-index": e.get("index"), "x-host": e.get("host")}
        params = [{"name": p, "in": "path", "required": True, "schema": {"type": "string"}} for p in path_params]
        for k, qp in (e.get("query_params") or {}).items():
            prm = {"name": k, "in": "query", "required": qp.get("count", 0) >= e.get("calls", 1),
                   "schema": _oa_param_schema(qp.get("values") or [])}
            if k in (e.get("pagination_params") or []):
                prm["description"] = "paginación" + (" (confirmada)" if e.get("confirmed_paginator") == k else "")
            params.append(prm)
        if params:
            op["parameters"] = params
        rb = e.get("request_body")
        if rb and method not in ("get", "head"):
            ct = next(iter(e.get("request_content_types") or {}), None)
            if rb.get("kind") == "json":
                sch = _oa_schema(rb.get("schema"))
                cname = re.sub(r"[^A-Za-z0-9]+", "", oid.title()) + "Request"
                components[cname] = sch
                op["requestBody"] = {"content": {ct or "application/json": {"schema": {"$ref": f"#/components/schemas/{cname}"}}}}
            elif rb.get("kind") in ("form", "multipart"):
                fields = rb.get("fields") or {}
                props = {str(f): {"type": "string"} for f in (fields.keys() if isinstance(fields, dict) else fields)}
                op["requestBody"] = {"content": {ct or ("multipart/form-data" if rb["kind"] == "multipart"
                                                        else "application/x-www-form-urlencoded"):
                                                 {"schema": {"type": "object", "properties": props}}}}
            else:
                op["requestBody"] = {"content": {ct or "text/plain": {"schema": {"type": "string"}}}}
        if e.get("persisted_query"):
            op["x-persisted-query"] = e["persisted_query"]
        responses: dict = {}
        statuses = [s for s in (e.get("statuses") or {}) if re.fullmatch(r"\d{3}", str(s))]
        rct = next(iter(e.get("response_content_types") or {}), None)
        for st in sorted(set(statuses)) or ["default"]:
            r = {"description": f"HTTP {st}" if st != "default" else "respuesta observada"}
            if st.startswith("2") or st == "default":
                if e.get("response_schema"):
                    cname = re.sub(r"[^A-Za-z0-9]+", "", oid.title()) + "Response"
                    components[cname] = _oa_schema(e["response_schema"])
                    r["content"] = {"application/json" if not rct or "json" not in rct else rct:
                                    {"schema": {"$ref": f"#/components/schemas/{cname}"}}}
                elif any(f in (e.get("flags") or []) for f in ("GRPC", "PROTOBUF")):
                    r["content"] = {rct or "application/grpc-web+proto": {"schema": {"type": "string", "format": "binary"}}}
                elif rct:
                    r["content"] = {rct: {"schema": {"type": "string"}}}
            responses[str(st)] = r
        op["responses"] = responses
        if e.get("auth_headers"):
            op["x-auth-headers"] = e["auth_headers"]
        paths.setdefault(path, OrderedDict())
        if method in paths[path]:
            # same path+method seen with another GraphQL op / host: keep first, list the rest
            paths[path][method].setdefault("x-also", []).append(e.get("key"))
        else:
            paths[path][method] = op
    return OrderedDict([
        ("openapi", "3.0.3"),
        ("info", {"title": f"API descubierta: {api_map.get('start_url')}", "version": "0.1.0-capturada",
                  "description": "Generado automáticamente por web-network-mapper (analyze.py) a partir del tráfico capturado. "
                                 "Best-effort: esquemas inferidos de las respuestas observadas."}),
        ("servers", [{"url": s} for s in servers]),
        ("paths", paths),
        ("components", {"schemas": components}),
    ])


def get_path_simple(obj, path):
    try:
        return get_path(obj, path)
    except Exception:
        return None


def _enrich_cookie_names(run_dir: Path, recs):
    """Cookie *names* (never values) per request from network.har, used when requests.jsonl headers
    are redacted ([REDACTED] Cookie / Set-Cookie). Stored in-memory as _har_req_cookies/_har_set_cookies."""
    need = [r for r in recs if (r.get("request_headers") or {}).get("cookie") == REDACTED
            or (r.get("response_headers") or {}).get("set-cookie") == REDACTED]
    if not need:
        return
    idx = _har_cookie_index(run_dir)
    if not idx:
        return
    used: Counter = Counter()
    for r in sorted(recs, key=lambda x: x.get("seq", 0)):
        k = (r.get("method"), r.get("url"))
        lst = idx.get(k)
        if not lst:
            continue
        i = min(used[k], len(lst) - 1)
        used[k] += 1
        rc, sc = lst[i]
        r["_har_req_cookies"] = rc
        r["_har_set_cookies"] = sc


def annotate_flow_tokens(run_dir: Path, flow, recs):
    """Mark on each flow step which tokens it issues and which earlier step's tokens it consumes."""
    last_issuer: dict = {}   # (kind,name) -> {"step", "path"}
    for s in flow:
        rec = s.get("_rec") or {}
        consumes = []
        for c in _consumed_tokens(rec):
            if c["kind"] == "authorization":
                hv = str((rec.get("request_headers") or {}).get("authorization") or "")
                cands = [v for k, v in reversed(list(last_issuer.items())) if k[0] == "bearer"]
                if hv and REDACTED not in hv:
                    cands = [v for v in cands if v.get("value") and v["value"] in hv]
                src = cands[0] if cands else None
                if src:
                    consumes.append({"kind": "bearer", "name": src["name"], "from_step": src["step"], "path": src.get("path"),
                                     "header": "Authorization", "verified": bool(hv and REDACTED not in hv)})
            else:
                kk = ("cookie" if c["kind"] == "cookie" else "hidden-field" if c["kind"] == "hidden-field"
                      else "header", c["name"] if c["kind"] != "header" else c["name"].lower())
                src = last_issuer.get(kk)
                if src and src["step"] != s["step"]:
                    consumes.append({"kind": kk[0], "name": c["name"], "from_step": src["step"], "path": src.get("path")})
        issues = []
        for iss in token_issues(run_dir, rec):
            if iss["kind"] in ("json", "jwt-in-body"):
                key = ("bearer", iss.get("path") or iss["name"])
            elif iss["kind"] == "header":
                key = ("header", iss["name"].lower())
            else:
                key = (iss["kind"], iss["name"])
            last_issuer[key] = {"step": s["step"], "path": iss.get("path"), "name": iss["name"],
                                "value": _token_value(run_dir, rec, iss)}
            issues.append({"kind": key[0], "name": iss["name"], "path": iss.get("path")})
        s["issues_tokens"] = issues
        s["consumes_tokens"] = consumes
    # only keep issues that somebody later consumes (plus session cookies), to keep flow.md readable
    used = {(c["from_step"], c["name"]) for s in flow for c in s.get("consumes_tokens", [])}
    for s in flow:
        s["issues_tokens"] = [i for i in s.get("issues_tokens", []) if (s["step"], i["name"]) in used]


def suggest_pagination(pag_params, body_pag, ep):
    """Return (paginate_value_or_None, replay CLI args string) for an endpoint."""
    cands = [(p, p) for p in pag_params] + [("body:" + p, p.split(".")[-1]) for p in body_pag]
    resp_keys = sorted(ep["response_pagination_keys"])
    cursor_resp = next((k for k in resp_keys if CURSOR_RESP_RE.search(k.split(".")[-1])), None)
    for full, leaf in cands:
        if PAGE_PARAM_RE.match(leaf):
            return full, f"--paginate {full}"
    for full, leaf in cands:
        if OFFSET_PARAM_RE.match(leaf):
            return full, f"--paginate {full}"
    for full, leaf in cands:
        if CURSOR_PARAM_RE.match(leaf) and cursor_resp:
            return None, f"--cursor-param {full} --cursor-path {cursor_resp}"
    nxt = next((k for k in resp_keys if k.split(".")[-1].lower() in ("next", "next_page", "nextpage", "next_url")), None)
    if nxt:
        return None, f"--next-url-path {nxt}"
    return None, ""


def page_template(url: str) -> str:
    u = urlsplit(url)
    segs = []
    for sgm in (u.path or "/").split("/"):
        n = norm_segment(sgm)
        if n == sgm and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9-]*[_-]\d+", sgm):
            n = "{slug}_{id}"
        segs.append(n)
    path = "/".join(segs) or "/"
    if path in ("", "/", "/index.html", "/index.htm", "/index.php"):
        path = "/"
    q = sorted({k for k, _ in parse_qsl(u.query, keep_blank_values=True)})
    return f"{u.netloc}{path}" + (("?" + "&".join(f"{k}=" for k in q)) if q else "")


def page_templates(pages):
    groups: "OrderedDict[str, dict]" = OrderedDict()
    for p in pages:
        if p.get("skipped") or not p.get("url"):
            continue
        t = page_template(p["url"])
        g = groups.setdefault(t, {"template": t, "count": 0, "examples": [], "titles": []})
        g["count"] += 1
        if len(g["examples"]) < 3:
            g["examples"].append(p["url"])
        if p.get("title") and len(g["titles"]) < 3 and p["title"] not in g["titles"]:
            g["titles"].append(p["title"])
    return sorted(groups.values(), key=lambda g: -g["count"])


EMBED_PATTERNS = [
    ("json-ld", re.compile(r'<script[^>]+type=["\']application/ld\+json', re.I)),
    ("__NEXT_DATA__", re.compile(r"__NEXT_DATA__")),
    ("__NUXT__", re.compile(r"__NUXT__|__NUXT_DATA__")),
    ("__APOLLO_STATE__", re.compile(r"__APOLLO_STATE__")),
    ("__INITIAL_STATE__", re.compile(r"__INITIAL_STATE__|__PRELOADED_STATE__|__INITIAL_DATA__")),
    ("inline-json-script", re.compile(r'<script[^>]+type=["\']application/json', re.I)),
    ("js-array-literal", re.compile(r"var\s+data\s*=\s*\[")),
]


def embedded_data(run_dir: Path, page, recs):
    """Detect server-embedded JSON (JSON-LD, Next.js/Nuxt state ...) in the page's main document body."""
    target = page.get("url")
    doc = next((r for r in recs if r.get("resource_type") == "Document" and r.get("page") == target
                and r.get("body_file") and r.get("url") in (target, page.get("final_url"))), None)
    if not doc:
        return []
    html = read_body_text(run_dir, doc)
    if html is None:
        return []
    return [name for name, rx in EMBED_PATTERNS if rx.search(html)]


# ------------------------------------------------------------------ markdown

def _fmt_counter(d):
    return ", ".join(f"{k}×{v}" for k, v in d.items()) or "-"



CAPTCHA_URL_RE = re.compile(r"captcha|recaptcha|hcaptcha|turnstile|challenge|\bcapt\b", re.I)
CAPTCHA_FIELD_RE = re.compile(r"captcha|recaptcha|g-recaptcha|h-captcha|cf-turnstile|challenge|otp|codigo.?seguridad|cod.?verif", re.I)
HUMAN_HINT_RE = re.compile(r"captcha|challenge|otp|two.?factor|2fa|verification code|codigo", re.I)


def _form_fields(rec):
    """Return list of form field names in a request's post_data (form or multipart), else []."""
    pd = rec.get("post_data") or ""
    ct = ((rec.get("request_headers") or {}).get("content-type") or "").lower()
    names = []
    if "application/x-www-form-urlencoded" in ct or ("=" in pd and "{" not in pd[:1]):
        try:
            names = [k for k, _ in parse_qsl(pd, keep_blank_values=True)]
        except Exception:
            names = []
    return names


def build_flow(run_dir: Path, recs, curl_red: bool, start_host: str):
    """Reconstruct the ordered, end-to-end request chain a user goes through, from the first
    page load to the final data response, keeping documents, XHR/fetch/API, form POSTs, redirects
    and captcha/challenge fetches, and flagging every step that needs a human (captcha to solve,
    one-time token to carry forward). Returns a list of step dicts."""
    STATIC = re.compile(r"\.(css|js|mjs|map|png|jpe?g|gif|webp|svg|ico|bmp|woff2?|ttf|otf|eot)(\?|$)", re.I)
    steps = []
    ordered = sorted(recs, key=lambda r: r.get("seq", 0))
    carried = set()  # one-time tokens seen in a response that later requests must echo
    for rec in ordered:
        url = rec.get("url") or ""
        if not url:
            continue
        t = rec.get("resource_type") or ""
        method = (rec.get("method") or "GET").upper()
        path = urlsplit(url).path
        is_captcha = bool(CAPTCHA_URL_RE.search(url))
        is_doc = t == "Document"
        is_apiish = is_api(rec, include_documents=False)
        is_form_post = method not in ("GET", "HEAD") and bool(rec.get("has_post_data") or rec.get("post_data"))
        # keep: documents, api/xhr, form posts, captcha assets, and 3xx redirects on documents
        status = rec.get("status")
        is_redirect = isinstance(status, int) and 300 <= status < 400
        if not (is_doc or is_apiish or is_form_post or is_captcha or (is_redirect and not STATIC.search(url))):
            continue
        if is_captcha is False and STATIC.search(url) and not is_apiish and not is_doc and not is_form_post:
            continue
        fields = _form_fields(rec) if is_form_post else []
        captcha_fields = [f for f in fields if CAPTCHA_FIELD_RE.search(f)]
        human = None
        if is_captcha and STATIC.search(url) and not (isinstance(status, int) and status >= 400):
            human = "El servidor entrega una imagen/desafío de captcha. Un humano debe resolverlo (verlo y teclear el texto)."
        elif captcha_fields:
            human = ("Este envío incluye el/los campo(s) de captcha resueltos por un humano: "
                     + ", ".join(f"`{f}`" for f in captcha_fields) + ". No se puede automatizar sin esa entrada humana.")
        rh = {k: v for k, v in (rec.get("request_headers") or {}).items() if not k.startswith(":")}
        rloc = None
        resp_h = rec.get("response_headers") or {}
        for hk, hv in resp_h.items():
            if hk.lower() == "location":
                rloc = hv
        curl = None
        env = None
        if not (is_captcha and STATIC.search(url)):  # a curl for the captcha image is just a download; still useful but keep simple
            c = build_curl(method, url, rh, rec.get("post_data") if method not in ("GET", "HEAD") else None, redact=curl_red)
            curl = c["multiline"]
            env = c["env"]
        else:
            c = build_curl("GET", url, rh, None, redact=curl_red)
            curl = c["multiline"]
            env = c["env"]
        steps.append({
            "seq": rec.get("seq"),
            "method": method,
            "url": url,
            "resource_type": t,
            "status": status,
            "status_text": rec.get("status_text"),
            "redirect_to": rloc or rec.get("redirected_to"),
            "is_document": is_doc,
            "is_captcha_asset": bool(is_captcha and STATIC.search(url) and not (isinstance(status, int) and status >= 400)),
            "is_form_submit": is_form_post,
            "form_fields": fields,
            "captcha_fields": captcha_fields,
            "needs_human": bool(human),
            "human_note": human,
            "page": rec.get("page"),
            "curl": curl,
            "curl_env": env,
            "_post_data": rec.get("post_data") if is_form_post else None,
            "_rec": rec,
        })
    # collapse consecutive identical GET static/captcha noise is already excluded; keep as-is
    for i, s in enumerate(steps, 1):
        s["step"] = i
    return steps



def render_flow_md(flow, start_url, curl_red) -> str:
    L = [f"# Flujo completo de inicio a fin: {start_url}\n"]
    L.append("Cada paso es una request real que hizo el navegador, **en el orden en que ocurrió**, desde la primera "
             "carga de página hasta la respuesta final con los datos. Replicar la consulta significa ejecutar estos "
             "pasos en orden y **en la misma sesión** (mismo cookie jar), llevando hacia adelante los valores de un "
             "solo uso (cookies de sesión, tokens CSRF, ViewState, etc.).\n")
    human = [s for s in flow if s["needs_human"]]
    if human:
        L.append("> **Requiere intervención humana.** Los pasos marcados con 🧑 necesitan que una persona resuelva un "
                 "captcha u otro desafío. La skill no los evita ni los resuelve sola: hay que pausar, que un humano "
                 "vea el captcha y escriba la respuesta, y continuar con el resto del flujo.\n")
    L.append(f"- Secretos en los curl: {'como $VARIABLES (exportar antes)' if curl_red else 'valores reales'}")
    L.append("- Script ejecutable del flujo: `flow.sh` (mismo directorio)\n")
    L.append("| Paso | Método | URL | Status | Tipo | Humano |")
    L.append("|---|---|---|---|---|---|")
    for s in flow:
        kind = "captcha" if s["is_captcha_asset"] else ("form POST" if s["is_form_submit"] else ("página" if s["is_document"] else s["resource_type"] or "-"))
        red = f" → {s['redirect_to']}" if s.get("redirect_to") else ""
        L.append(f"| {s['step']} | {s['method']} | `{s['url'][:110]}`{red} | {s['status']} | {kind} | {'🧑' if s['needs_human'] else ''} |")
    L.append("")
    for s in flow:
        L.append(f"## Paso {s['step']}: {s['method']} {s['url']}\n")
        L.append(f"- Status: {s['status']} {s.get('status_text') or ''}".rstrip())
        if s.get("redirect_to"):
            L.append(f"- Redirige a: `{s['redirect_to']}`")
        if s["form_fields"]:
            L.append("- Campos enviados: " + ", ".join(f"`{f}`" for f in s["form_fields"]))
        if s["needs_human"]:
            L.append(f"- 🧑 **Paso humano:** {s['human_note']}")
        for t in s.get("issues_tokens") or []:
            L.append(f"- 🔑 Emite token `{t['name']}` ({t['kind']}{', ' + t['path'] if t.get('path') else ''}) usado más adelante")
        for t in s.get("consumes_tokens") or []:
            L.append(f"- 🔑 Usa token `{t['name']}` ({t['kind']}) emitido en el paso {t['from_step']}"
                     + (" — probable (valores redactados en la captura)" if t.get("verified") is False and t["kind"] == "bearer" else ""))
        if s.get("curl"):
            L.append("\n```bash")
            if s.get("curl_env"):
                L.append("# exportar primero:")
                L.append(env_comment(s["curl_env"]))
            L.append(s["curl"])
            L.append("```")
        L.append("")
    return "\n".join(L)


_FLOW_SH_HELPERS = r'''# --- helpers para llevar tokens de una respuesta al siguiente paso (best-effort) ---
wnm_json() {  # wnm_json FILE ruta.en.json -> imprime el valor (usa jq si existe; si no, python3)
  if command -v jq >/dev/null 2>&1; then jq -r ".${2}" "$1" 2>/dev/null | head -1
  else python3 - "$1" "$2" <<'PYX' 2>/dev/null
import json, re, sys
v = json.load(open(sys.argv[1]))
for p in [x for x in re.split(r"[.\[\]]+", sys.argv[2]) if x]:
    v = v[int(p)] if p.isdigit() else v.get(p)
print("" if v is None else v)
PYX
  fi
}
wnm_hidden() {  # wnm_hidden FILE nombre_campo -> valor de <input type=hidden> o <update id=...ViewState> (JSF)
  python3 - "$1" "$2" <<'PYX' 2>/dev/null
import html, re, sys
t = open(sys.argv[1], encoding="utf-8", errors="replace").read(); n = re.escape(sys.argv[2])
m = re.search(r'<update id="[^"]*' + n + r'[^"]*"><!\[CDATA\[(.*?)\]\]>', t, re.S)
m = m or re.search(r'<input[^>]*name=["\']' + n + r'["\'][^>]*value=["\']([^"\']*)', t, re.I)
m = m or re.search(r'<input[^>]*value=["\']([^"\']*)["\'][^>]*name=["\']' + n + r'["\']', t, re.I)
print(html.unescape(m.group(1)) if m else "")
PYX
}
wnm_urlenc() { python3 -c 'import sys, urllib.parse; print(urllib.parse.quote_plus(sys.argv[1]))' "$1"; }
'''.splitlines() + [""]


def _shvar(name: str) -> str:
    v = re.sub(r"[^A-Za-z0-9]+", "_", str(name)).strip("_").upper() or "TOKEN"
    return ("T_" + v) if v[0].isdigit() else v


def _flow_token_forward(s):
    """Shell lines that capture tokens issued by earlier steps (from $OUT/step_N.out) and the curl
    command rewritten to use them. Returns (lines, rewritten_curl_or_None)."""
    from urllib.parse import quote_plus
    lines, curl = [], s.get("curl") or ""
    cons = s.get("consumes_tokens") or []
    if not cons or not curl:
        return lines, None
    changed = False
    sep = " \\\n  "
    cookie_names = [c["name"] for c in cons if c["kind"] == "cookie"]
    all_req_cookies = _req_cookie_names(s.get("_rec") or {})
    if cookie_names:
        srcs = sorted({c["from_step"] for c in cons if c["kind"] == "cookie"})
        lines.append(f"# Token: cookie(s) {', '.join(cookie_names)} emitida(s) en paso(s) {', '.join(map(str, srcs))}; "
                     "las lleva el cookie jar ($JAR) automaticamente.")
        if all_req_cookies and set(all_req_cookies) <= set(cookie_names):
            parts = curl.split(sep)
            kept = [p for p in parts if not re.match(r"""-H ['"]Cookie:""", p)]
            if len(kept) != len(parts):
                curl = sep.join(kept)
                changed = True
                lines.append("# (se quito el header Cookie fijo: el valor vigente sale del jar)")
    for c in cons:
        step = c["from_step"]
        src = f'"$OUT/step_{step}.out"'
        if c["kind"] == "bearer":
            var = f"TOKEN_PASO_{step}"
            path = c.get("path") or c["name"]
            lines.append(f"# Token: '{c['name']}' emitido por el paso {step} (JSON `{path}`) se usa aqui como Authorization: Bearer")
            lines.append(f'{var}="$(wnm_json {src} {shlex_quote(path)})"  # TODO: verificar la ruta JSON')
            lines.append(f'[ -n "${var}" ] || echo "AVISO: no se encontro el token en $OUT/step_{step}.out" >&2')
            if c.get("verified"):
                # capture had real values and the header carried exactly this token: wire it directly
                lines.append(f'AUTHORIZATION="Bearer ${var}"; export AUTHORIZATION')
                new = re.sub(r"""-H (['"])Authorization: [^'"]*\1""", lambda _m: f'-H "Authorization: Bearer ${{{var}}}"', curl, count=1)
            else:
                # values were redacted at capture: the link is only probable. An exported $AUTHORIZATION wins;
                # otherwise use the token extracted from the previous response.
                lines.append("# TODO: vinculo probable (valores redactados en la captura). Si ya exportaste AUTHORIZATION se usa esa;")
                lines.append("#       si no, se usa el token extraido del paso anterior.")
                lines.append(f'if [ -n "${var}" ]; then AUTHORIZATION="${{AUTHORIZATION:-Bearer ${var}}}"; fi; export AUTHORIZATION')
                new = re.sub(r"""-H (['"])Authorization: [^'"]*\1""", lambda _m: '-H "Authorization: ${AUTHORIZATION}"', curl, count=1)
            if new != curl:
                curl, changed = new, True
        elif c["kind"] == "hidden-field":
            var = _shvar(c["name"]) + f"_PASO_{step}"
            lines.append(f"# Token: campo oculto '{c['name']}' emitido en la respuesta del paso {step}; se reenvia en este POST")
            lines.append(f'{var}="$(wnm_hidden {src} {shlex_quote(c["name"])})"')
            lines.append(f'[ -n "${var}" ] || echo "AVISO: {c["name"]} no encontrado en $OUT/step_{step}.out (TODO: extraer a mano)" >&2')
            lines.append(f'{var}_ENC="$(wnm_urlenc "${var}")"')
            done = False
            for enc_name in (quote_plus(c["name"]), c["name"]):
                m = re.search(r"(?:^|[&'\"])" + re.escape(enc_name) + r"=([^&'\"\s]*)", curl)
                if m:
                    # inside a single-quoted --data-raw: close quote, expand var in double quotes, reopen
                    in_dq = curl.rfind('"', 0, m.start(1)) > curl.rfind("'", 0, m.start(1))
                    rep_val = f"${{{var}_ENC}}" if in_dq else f"'\"${{{var}_ENC}}\"'"
                    curl = curl[:m.start(1)] + rep_val + curl[m.end(1):]
                    changed = done = True
                    break
            if not done:
                lines.append(f"# TODO: reemplaza a mano el valor de {c['name']} en el cuerpo por ${{{var}_ENC}}")
        elif c["kind"] == "header":
            lines.append(f"# Token: header {c['name']} emitido por el paso {step}; TODO: extraerlo de la respuesta "
                         "(curl -D) y enviarlo aqui")
    return lines, (curl if changed else None)


def shlex_quote(x):
    import shlex
    return shlex.quote(str(x))


def render_flow_sh(flow, start_url) -> str:
    """A bash script that replays the whole chain in one cookie jar and pauses for a human at captcha steps."""
    import shlex
    L = ["#!/usr/bin/env bash",
         f"# Flujo completo capturado desde {start_url}",
         "# Ejecuta los pasos en orden en una sola sesion (cookie jar) y se detiene en los pasos de captcha",
         "# para que un humano lo resuelva. Los valores de un solo uso (ViewState, CSRF, captcha) caducan:",
         "# edita las lineas marcadas con TODO para extraerlos de la respuesta anterior en cada ejecucion.",
         "set -euo pipefail",
         'JAR="${JAR:-$(mktemp)}"',
         'OUT="${OUT:-./flow_out}"; mkdir -p "$OUT"',
         ""]
    try:
        if any(s.get("consumes_tokens") for s in flow):
            L += _FLOW_SH_HELPERS
    except Exception:
        pass
    for s in flow:
        L.append(f"# --- Paso {s['step']}: {s['method']} {s['url']}")
        tok_lines, c_override = [], None
        try:
            tok_lines, c_override = _flow_token_forward(s)
        except Exception:
            tok_lines, c_override = ["# TODO: no se pudo generar la extraccion automatica de tokens para este paso"], None
        L += tok_lines
        if s["is_captcha_asset"]:
            L.append(f"curl -sS -b \"$JAR\" -c \"$JAR\" {shlex.quote(s['url'])} -o \"$OUT/captcha_{s['step']}.png\"")
            L.append(f"echo 'Captcha guardado en '$OUT'/captcha_{s['step']}.png'")
            L.append(f"read -r -p 'Escribe el texto del captcha (paso {s['step']}): ' CAPTCHA")
            L.append("")
            continue
        c = (c_override if c_override is not None else (s.get("curl") or "")).replace("curl ", 'curl -sS -b "$JAR" -c "$JAR" ', 1)
        if s["needs_human"] and s["captcha_fields"]:
            from urllib.parse import quote_plus
            cap_vals = [v for k, v in parse_qsl(s.get("_post_data") or "", keep_blank_values=True) if k in s["captcha_fields"]]
            for fld in s["captcha_fields"]:
                for v in cap_vals:
                    if v:
                        for enc in (quote_plus(fld), fld):
                            c = c.replace(f"{enc}={v}", f"{enc}='\"$CAPTCHA\"'")
            L.append("# Captcha: el valor capturado se reemplaza por $CAPTCHA (lo que escribiste arriba)")
        L.append("# NOTA: tokens de un solo uso (ViewState, CSRF, JSESSIONID) salen de la respuesta anterior; si el"
                 " servidor los rechaza, extraelos de $OUT/step_<n>.out y reemplazalos aqui.") if s["is_form_submit"] else None
        L.append(c + f" \\\n  -o \"$OUT/step_{s['step']}.out\"")
        L.append("")
    L.append('echo "Listo. Respuestas en $OUT/"')
    return "\n".join(L) + "\n"


def _render_endpoint_extras(e) -> list[str]:
    L = []
    if e.get("role"):
        L.append(f"- Rol: **{e['role']}**")
    if e.get("pagination_confirmed"):
        L.append(f"- Paginación CONFIRMADA por `{e.get('confirmed_paginator')}` (dos llamadas que solo difieren en ese "
                 "parámetro devolvieron registros distintos)")
    elif e.get("pagination_params") or e.get("body_pagination_params"):
        L.append("- Paginación: sugerida por el nombre del parámetro (no confirmada con dos llamadas distintas)")
    if e.get("rate_limit_note"):
        L.append(f"- Rate limit: {e['rate_limit_note']}")
    if any(f in e.get("flags", []) for f in ("GRPC", "PROTOBUF")):
        bb = e.get("binary_body") or {}
        _pdq = e.get("protobuf_decoded") or {}
        _st = ("decodificado con esquema, ver abajo" if _pdq.get("schema_based") else
               "solo decodificación genérica sin esquema, ver abajo" if _pdq else "no decodificado")
        L.append(f"- Cuerpo binario {'gRPC-web' if 'GRPC' in e['flags'] else 'protobuf'} ({_st}): "
                 f"content-type {', '.join(bb.get('content_types') or []) or '-'}; tamaños {bb.get('sizes') or '-'} bytes. "
                 + ("Para decodificar con nombres de campo reales pasa `--proto <archivo|dir>` o `--descriptor <fds>`."
                    if not _pdq.get("schema_based") else ""))
    pq = e.get("persisted_query")
    if pq:
        L.append(f"- GraphQL persisted query: operationName `{pq.get('operationName') or '-'}`, sha256Hash "
                 f"`{pq.get('sha256Hash')}` (versión {pq.get('version')}, vía {pq.get('transport')}). El curl reenvía el hash; "
                 "si el servidor responde PersistedQueryNotFound hay que enviar también el texto `query`.")
    if e.get("issues_token"):
        L.append("- Emite token(s): " + ", ".join(f"`{t['name']}` ({t['kind']})" for t in e["issues_token"][:6]))
    if e.get("consumes_token"):
        L.append("- Consume token(s): " + ", ".join(f"`{t['name']}` ({t['kind']})" for t in e["consumes_token"][:6]))
    return L


def _render_extra_sections(m) -> list[str]:
    L = []
    af = m.get("auth_flow") or {}
    toks = af.get("tokens") or []
    L.append("## Autenticación / tokens\n")
    if not toks:
        L.append("_No se detectaron endpoints que emitan o consuman tokens (cookies de sesión, Bearer/JWT, CSRF/ViewState)._\n")
    else:
        L.append("Qué request **emite** cada token y qué requests lo **usan** después. En `flow.sh` los pasos que "
                 "consumen un token lo toman automáticamente de la respuesta anterior (best-effort, con TODO donde la "
                 "extracción es incierta).\n")
        L.append("| Token | Tipo | Emitido por | Usado por | Cómo se transporta |")
        L.append("|---|---|---|---|---|")
        for t in toks[:30]:
            iss = "<br>".join(f"`{i['endpoint'][:70]}` (seq {i['seq']}, {i['via']})" for i in t["issued_by"][:2]) or "_(previo a la captura)_"
            con = "<br>".join(f"`{c['endpoint'][:70]}` ×{c['count']}"
                              + (" (probable: valores redactados)" if c.get("verified") is None and t["kind"] == "bearer" else "")
                              for c in t["consumed_by"][:4]) or "-"
            if len(t["consumed_by"]) > 4:
                con += f"<br>… {len(t['consumed_by']) - 4} más"
            if t.get("static_consumers"):
                con += f"<br>(+{t['static_consumers']} recursos estáticos)"
            L.append(f"| `{t['name']}` | {t['kind']}{' (sesión)' if t.get('session_like') else ''} | {iss} | {con} | {t['carried_by']} |")
        L.append("")
        notes = []
        if af.get("has_session_cookie"):
            notes.append("Hay cookie de sesión: reutilizar el mismo cookie jar en todas las requests (`curl -b jar -c jar`).")
        if af.get("has_bearer"):
            notes.append("Hay token Bearer/JWT: obtenerlo del endpoint emisor y enviarlo como `Authorization: Bearer <token>`.")
        if af.get("has_csrf"):
            notes.append("Hay tokens CSRF/ViewState de un solo uso: extraerlos de la respuesta inmediatamente anterior en cada ejecución.")
        for n in notes:
            L.append(f"- {n}")
        if notes:
            L.append("")
    ab = m.get("anti_bot") or []
    L.append("## Protección anti-bot detectada\n")
    if not ab:
        L.append("_No se detectaron proveedores anti-bot conocidos (Cloudflare, hCaptcha, reCAPTCHA, Akamai, PerimeterX, "
                 "DataDome, Imperva) ni desafíos JS genéricos en el tráfico capturado._\n")
    else:
        for a in ab:
            L.append(f"- **{a['vendor']}** — {'desafío ACTIVO' if a.get('active') else 'solo señales pasivas'} "
                     f"({a['requests']} request(s))")
            L.append(f"  - Evidencia: {', '.join('`' + x + '`' for x in a['evidence'][:8])}")
            if a.get("example_urls"):
                L.append(f"  - Ejemplo: {a['example_urls'][0]}")
            L.append(f"  - Estrategia sugerida: {a['strategy']}")
        L.append("")
    rls = m.get("rate_limit_summary") or {}
    if rls.get("endpoints_with_rate_limit"):
        L.append("## Rate limit\n")
        L.append(f"{rls['endpoints_with_rate_limit']} endpoint(s) con señales de rate limit; {rls.get('status_429_total', 0)} "
                 "respuesta(s) 429. Respetar `retry-after` / `x-ratelimit-reset` y usar `--delay` en replay.\n")
        for n in rls.get("notes") or []:
            L.append(f"- `{n['endpoint']}`: {n['note']}")
        L.append("")
    return L


def _render_md_new_files(m) -> list[str]:
    """Líneas de cabecera de api_map.md para los archivos nuevos (JSON Schema, Postman, HTML, replay.sh)."""
    L = []
    if m.get("json_schema_file"):
        L.append(f"- JSON Schema (draft 2020-12): `{m['json_schema_file']}` (consolidado) + "
                 f"`{m.get('json_schema_dir')}/` ({m.get('json_schema_count', 0)} endpoint(s))")
    elif m.get("json_schema_error"):
        L.append(f"- JSON Schema: no se pudo generar ({m['json_schema_error']})")
    if m.get("postman_file"):
        L.append(f"- Colección Postman v2.1.0: `{m['postman_file']}` ({m.get('postman_requests', 0)} request(s); "
                 "variables `{{host}}` y `{{token}}`)")
    elif m.get("postman_error"):
        L.append(f"- Postman: no se pudo generar ({m['postman_error']})")
    if m.get("replay_script"):
        L.append(f"- Script de extracción con paginación: `{m['replay_script']}` (un `wnm-replay` por endpoint de datos)")
    if m.get("html_file"):
        L.append(f"- Reporte HTML navegable (offline): `{m['html_file']}`")
    pd = m.get("protobuf_decoder")
    if pd:
        L.append(f"- Decodificador protobuf: {'activo, tipos: ' + ', '.join(pd.get('types') or []) if pd.get('enabled') else 'NO disponible (' + str(pd.get('error')) + ')'}"
                 + (f" — aviso: {pd['error']}" if pd.get("enabled") and pd.get("error") else ""))
    return L


def _render_endpoint_new(e, rd=None) -> list[str]:
    L = []
    dp = e.get("data_param")
    if dp:
        ex = f" (ej. `{dp['example']}`)" if dp.get("example") not in (None, "") else ""
        L.append(f"- Dato de entrada (data_param): **{dp['in']} `{dp['name']}`**{ex} — {dp.get('note')}. "
                 "Es el valor a variar para extracción masiva.")
        cmd = _data_param_replay_cmd(e, rd)
        if cmd:
            L.append(f"- Extracción sugerida: `{cmd}`")
    if e.get("json_schema_file"):
        L.append(f"- JSON Schema: `{e['json_schema_file']}`")
    return L


def _data_param_replay_cmd(e, rd=None) -> str | None:
    dp = e.get("data_param") or {}
    if not dp:
        return None
    base = f"{TOOL_DIR}/wnm-replay {(str(rd) + '/') if rd else ''}api_map.json {e['index']}"
    var = "$" + _data_var_name(dp.get("name") or "DATO")
    if dp.get("in") == "query":
        base += f" --param {shlex_quote(dp['name'])}=\"{var}\""
    elif dp.get("in") == "body" and (e.get("request_body") or {}).get("kind") == "json":
        base += f" --body-set {shlex_quote(dp['name'])}=\"{var}\""
    elif dp.get("in") == "path":
        ex_url = (e.get("replay") or {}).get("url") or (e.get("example_urls") or [None])[0]
        ex = dp.get("example")
        if ex_url and ex and str(ex) in urlsplit(ex_url).path:
            u, _env = _replay_url_with_vars(ex_url)
            base += " --url " + _dq(u.replace(str(ex), "${" + var[1:] + "}", 1))
        else:
            base += f" --url <URL con {var} en la ruta>"
    else:
        base += f" --data <cuerpo con {dp['name']}={var}> (comando completo en replay.sh)"
    if e.get("suggested_replay_args"):
        base += " " + e["suggested_replay_args"]
    return base + " --max-pages 5"


def _render_protobuf_md(e) -> list[str]:
    pdq = e.get("protobuf_decoded")
    if not pdq:
        return []
    L = []
    if pdq.get("schema_based"):
        L.append("\n<details><summary>Cuerpo protobuf/gRPC decodificado con el esquema (.proto / descriptor)</summary>\n")
    else:
        L.append("\n<details><summary>Protobuf: decodificación genérica sin esquema (número de campo + wire type + valor crudo)</summary>\n")
        L.append("> Decodificación genérica sin esquema: los nombres de campo son desconocidos; aporta `--proto` o "
                 "`--descriptor` para obtener JSON con nombres reales.\n")
    for fr in (pdq.get("frames") or [])[:3]:
        hdr = f"{fr.get('body_file')} ({fr.get('bytes')} bytes)"
        if fr.get("schema"):
            hdr += f" → mensaje `{fr.get('message_type')}`"
            if fr.get("unknown_fields"):
                hdr += f" ({fr['unknown_fields']} campo(s) desconocido(s))"
        L.append(f"- {hdr}")
        L.append("```json")
        body = fr.get("json") if fr.get("schema") else fr.get("generic")
        L.append(json.dumps(body, indent=2, ensure_ascii=False, default=str)[:3000])
        L.append("```")
    L.append("</details>")
    return L


def _render_ws_sse_md(m) -> list[str]:
    wss = m.get("ws_sse") or []
    if not wss:
        return []
    L = ["## WebSocket / SSE (capturas adicionales)\n"]
    for w in wss:
        L.append(f"- {(w.get('kind') or 'stream').upper()} `{w.get('url')}` enviados={w.get('frames_sent', 0)} "
                 f"recibidos={w.get('frames_received', 0)} mensajes={w.get('messages', 0)}"
                 + (f" estado={w['state']}" if w.get("state") else "")
                 + (f" (página {w['page']})" if w.get("page") else ""))
        for smp in (w.get("samples") or [])[:3]:
            L.append(f"  - {smp.get('dir')}: `{str(smp.get('payload'))[:150]}`")
    L.append("")
    return L


def render_md(m, pages, failed, run_dir: Path) -> str:
    L = []
    rd = m["run_dir"]
    L.append(f"# API map: {m['start_url']}\n")
    L.append(f"- Run dir: `{rd}`")
    L.append(f"- Pages visited: {m['pages_visited']} · Requests captured: {m['total_requests']} · "
             f"Endpoints: {m['endpoint_count']} ({m['data_endpoint_count']} likely data endpoints)")
    L.append(f"- Requests by type: {_fmt_counter(m['requests_by_type'])}")
    L.append(f"- Hosts: {_fmt_counter(dict(list(m['requests_by_host'].items())[:10]))}")
    L.append(f"- Secrets redacted: {'yes' if m['redacted'] else 'NO (--keep-secrets)'}"
             f" · curl commands: {'secrets as $VARIABLES' if m.get('curl_redacted', True) else 'REAL secret values'}")
    if m.get("curls_file"):
        L.append(f"- All requests as curl: `{m['curls_file']}`")
    try:
        if m.get("openapi_file"):
            L.append(f"- Especificación OpenAPI 3.0: `{m['openapi_file']}` ({m.get('openapi_paths', 0)} paths)")
        elif m.get("openapi_error"):
            L.append(f"- OpenAPI: no se pudo generar ({m['openapi_error']})")
        else:
            L.append("- OpenAPI: no generado (sin endpoints de API propios: sitio renderizado en servidor o --no-openapi)")
        try:
            L.extend(_render_md_new_files(m))
        except Exception:
            pass
        if m.get("endpoint_roles"):
            L.append(f"- Roles de endpoints: {_fmt_counter(m['endpoint_roles'])}")
        rls = m.get("rate_limit_summary") or {}
        if rls.get("endpoints_with_rate_limit"):
            L.append(f"- Rate limit: {rls['endpoints_with_rate_limit']} endpoint(s) con límites detectados, "
                     f"{rls.get('status_429_total', 0)} respuesta(s) 429 — ver sección de rate limit")
        else:
            L.append("- Rate limit: no se observaron respuestas 429 ni headers x-ratelimit-*/retry-after")
        ab = m.get("anti_bot") or []
        if ab:
            L.append("- Anti-bot: " + ", ".join(f"{a['vendor']}{' (desafío activo)' if a.get('active') else ''}" for a in ab))
    except Exception:
        pass
    L.append("")
    try:
        L.extend(_render_extra_sections(m))
    except Exception as e:
        L.append(f"_(no se pudieron generar las secciones de auth/anti-bot: {e})_\n")

    main = [e for e in m["endpoints"] if not e["likely_tracking"]]
    track = [e for e in m["endpoints"] if e["likely_tracking"]]
    if m.get("flow"):
        L.append("## Flujo completo (inicio a fin)\n")
        L.append(f"Secuencia ordenada de las {len(m['flow'])} requests que llevan a los datos. Detalle con curl de cada paso en `flow.md`; script en `flow.sh`.\n")
        if m.get("flow_needs_human"):
            L.append("> 🧑 El flujo tiene pasos que requieren un humano (captcha u otro desafío).\n")
        for s in m["flow"]:
            tag = " 🧑" if s["needs_human"] else ""
            red = f" → `{s['redirect_to']}`" if s.get("redirect_to") else ""
            L.append(f"{s['step']}. {s['method']} `{s['url'][:120]}` ({s['status']}){red}{tag}")
        L.append("")
    L.append("## Endpoints\n")
    if not main:
        L.append("_No XHR/fetch/JSON endpoints captured. The site may be fully server-rendered: scrape the HTML "
                 "pages listed below (bodies/ has the documents), or try --scroll / --actions to trigger requests._\n")
    else:
        L.append("| # | Endpoint | Calls | Status | Response | Flags |")
        L.append("|---|---|---|---|---|---|")
        for e in main:
            L.append(f"| {e['index']} | `{e['key']}` | {e['calls']} | {_fmt_counter(e['statuses'])} | "
                     f"{', '.join(e['response_content_types']) or '-'} | {' '.join(e['flags']) or '-'} |")
        L.append("")
    for e in main:
        L.append(f"### {e['index']}. `{e['key']}`\n")
        L.append(f"- Flags: **{' '.join(e['flags']) or 'none'}**")
        try:
            L.extend(_render_endpoint_extras(e))
        except Exception:
            pass
        try:
            L.extend(_render_endpoint_new(e, rd))
        except Exception:
            pass
        L.append(f"- Example: {e['example_urls'][0] if e['example_urls'] else '-'}")
        L.append(f"- Calls: {e['calls']} · Status: {_fmt_counter(e['statuses'])} · Types: {_fmt_counter(e['resource_types'])}"
                 f" · Avg: {e['avg_duration_ms']} ms, {e['avg_body_bytes']} bytes")
        if e["query_params"]:
            qp = []
            for k, v in e["query_params"].items():
                tag = " *(pagination)*" if k in e["pagination_params"] else (" *(varies)*" if v.get("varies") else "")
                qp.append(f"`{k}` = {', '.join(repr(x) for x in v['values'][:6])}{tag}")
            L.append("- Query params: " + "; ".join(qp))
        rb = e["request_body"]
        if rb:
            if rb["kind"] == "json":
                L.append(f"- Request body (JSON) keys: {', '.join(rb.get('keys', [])) or '(array)'}")
            elif rb["kind"] == "form":
                L.append(f"- Request body (form) fields: {', '.join(rb['fields'])}")
            else:
                L.append(f"- Request body ({rb['kind']}): {rb.get('length', '')}")
        if e["body_pagination_params"]:
            L.append(f"- Pagination in body: {', '.join(e['body_pagination_params'])}")
        if e["graphql_operations"]:
            L.append(f"- GraphQL operations: {', '.join(e['graphql_operations'])}")
        L.append(f"- Auth-related headers (names only): {', '.join(e['auth_headers']) or 'none'}")
        L.append(f"- Response content type: {', '.join(e['response_content_types']) or '-'}")
        if e["response_records"]:
            r = e["response_records"]
            L.append(f"- Records: `{r['jsonpath']}` ({r['length']} items) keys: {', '.join(r['item_keys'][:15])}")
        if e["response_top_keys"]:
            L.append(f"- Top-level keys: {', '.join(e['response_top_keys'][:25])}")
        if e["response_pagination_keys"]:
            L.append(f"- Pagination keys in response: {', '.join(e['response_pagination_keys'][:12])}")
        L.append(f"- Called from pages: {', '.join(e['pages'][:5])}{' …' if len(e['pages']) > 5 else ''}")
        if e["sample_bodies"]:
            L.append(f"- Sample bodies: {', '.join('`' + s + '`' for s in e['sample_bodies'])}")
        cmd = f"{TOOL_DIR}/wnm-replay {rd}/api_map.json {e['index']}"
        if e.get("suggested_replay_args"):
            cmd += " " + e["suggested_replay_args"] + " --max-pages 5"
        L.append(f"- Replay: `{cmd}`")
        if e.get("curl"):
            L.append("- curl (representative captured call, headers as the browser sent them):\n")
            L.append("```bash")
            if e.get("curl_env"):
                L.append("# set first:")
                L.append(env_comment(e["curl_env"]))
            L.append(e["curl"])
            L.append("```")
        if e["response_schema"]:
            L.append("\n<details><summary>Response schema (inferred)</summary>\n")
            L.append("```")
            L.extend(schema_outline(e["response_schema"], max_lines=35))
            L.append("```\n</details>")
        try:
            L.extend(_render_protobuf_md(e))
        except Exception:
            pass
        L.append("")
    if track:
        L.append("## Tracking / analytics endpoints (ignored)\n")
        for e in track:
            L.append(f"- `{e['key']}` ×{e['calls']}")
        L.append("")
    if m["websockets"]:
        L.append("## WebSockets\n")
        for w in m["websockets"]:
            L.append(f"- `{w['url']}` sent={w['frames_sent']} received={w['frames_received']} (page {w['page']})")
            for s in w["samples"]:
                L.append(f"  - {s['dir']}: `{s['payload'][:150]}`")
        L.append("")
    try:
        L.extend(_render_ws_sse_md(m))
    except Exception:
        pass
    if m.get("page_templates"):
        L.append("## Page templates (HTML URL patterns)\n")
        for g in m["page_templates"][:25]:
            L.append(f"- `{g['template']}` ×{g['count']} e.g. {g['examples'][0]}")
        L.append("")
    if m.get("pages_with_embedded_data"):
        L.append("## Embedded data in HTML (scrape without API)\n")
        for u, kinds in list(m["pages_with_embedded_data"].items())[:20]:
            L.append(f"- {u}: {', '.join(kinds)}")
        L.append("")
    L.append("## Pages\n")
    L.append("| # | URL | Status | Title | Links | API calls |")
    L.append("|---|---|---|---|---|---|")
    for i, p in enumerate(pages[:60], 1):
        title = (p.get("title") or p.get("error") or p.get("skipped") or "").replace("|", "/")[:60]
        L.append(f"| {i} | {p.get('url')} | {p.get('status', '-')} | {title} | {p.get('links_in_scope', '-')} | "
                 f"{len(p.get('api_calls', []))} |")
    if len(pages) > 60:
        L.append(f"\n… {len(pages) - 60} more pages in pages.json")
    L.append("")
    if failed:
        L.append("## Failed requests\n")
        agg: "OrderedDict[tuple, int]" = OrderedDict()
        for r in failed:
            why = r.get("error_text") or ""
            if r.get("blocked_reason"):
                why = (why + " blocked:" + r["blocked_reason"]).strip()
            k = (r.get("method"), (r.get("url") or "")[:150], why or "unknown")
            agg[k] = agg.get(k, 0) + 1
        for (mth, u, why), n in list(agg.items())[:25]:
            L.append(f"- {mth} {u} — {why}" + (f" (×{n})" if n > 1 else ""))
        if len(agg) > 25:
            L.append(f"- … {len(agg) - 25} more")
        L.append("")
    return "\n".join(L)


# ================================================================== ADDITIVE FEATURES (improvements)
# Todo lo de abajo es aditivo y defensivo: no reescribe el comportamiento existente.

# ------------------------------------------------------------------ 1) JSON Schema (draft 2020-12)

def _js_types(s):
    t = s.get("type")
    types = t if isinstance(t, list) else [t]
    return [x for x in types if x]


def infer_to_jsonschema(s, depth=0):
    """Convierte un esquema inferido (formato infer/merge) a JSON Schema draft 2020-12."""
    if not isinstance(s, dict) or depth > 15:
        return {}
    types = _js_types(s)
    out: dict = {}
    if len(types) == 1:
        out["type"] = types[0]
    elif types:
        out["type"] = types
    non_null = [x for x in types if x != "null"]
    tt = non_null[0] if non_null else None
    if tt == "object":
        if s.get("properties"):
            out["properties"] = {str(k): infer_to_jsonschema(v, depth + 1) for k, v in s["properties"].items()}
        if s.get("additionalProperties"):
            out["additionalProperties"] = infer_to_jsonschema(s["additionalProperties"], depth + 1)
    elif tt == "array":
        out["items"] = infer_to_jsonschema(s["items"], depth + 1) if s.get("items") else {}
    if "example" in s and s["example"] != REDACTED and tt not in ("object", "array") \
            and not (isinstance(s["example"], str) and len(s["example"]) == 80 and s["example"].endswith("...")):
        out["examples"] = [s["example"]]
        if tt == "string":
            fmt = _string_format(s["example"])
            if fmt:
                out["format"] = fmt
    return out


_FMT_DT_RE = re.compile(r"^\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}(:\d{2}(\.\d+)?)?(Z|[+-]\d{2}:?\d{2})?$")


def _string_format(v) -> str | None:
    if not isinstance(v, str) or v.endswith("..."):
        return None
    if _FMT_DT_RE.match(v):
        return "date-time"
    if re.fullmatch(r"\d{4}-\d{2}-\d{2}", v):
        return "date"
    if UUID_RE.match(v):
        return "uuid"
    if re.fullmatch(r"https?://\S+", v):
        return "uri"
    if re.fullmatch(r"[^@\s]+@[^@\s]+\.[A-Za-z]{2,}", v):
        return "email"
    return None


def _load_sample_jsons(run_dir: Path, e) -> list:
    out = []
    for bf in (e.get("sample_bodies") or [])[:5]:
        try:
            raw = (Path(run_dir) / bf).read_bytes()
            try:
                raw = decode_body_bytes(raw, None)
            except Exception:
                pass
            txt = raw.decode("utf-8", errors="replace")
            if txt.lstrip()[:1] not in "[{)fw":
                continue
            out.append(loads_lenient(txt))
        except Exception:
            continue
    return out


def _annotate_required(js, values, depth=0):
    """Marca `required` con las claves presentes en TODAS las muestras observadas (objetos) y recurre en
    propiedades / items. Con una sola muestra no se infiere `required` (sería engañoso)."""
    if not isinstance(js, dict) or depth > 12 or not values:
        return
    objs = [v for v in values if isinstance(v, dict)]
    if objs and js.get("properties"):
        if len(objs) >= 2:
            req = [k for k in js["properties"] if all(k in o for o in objs)]
            if req:
                js["required"] = req
        for k, sub in js["properties"].items():
            _annotate_required(sub, [o[k] for o in objs if k in o][:200], depth + 1)
    arrs = [v for v in values if isinstance(v, list)]
    if arrs and isinstance(js.get("items"), dict):
        items = [x for a in arrs for x in a[:50]][:300]
        _annotate_required(js["items"], items, depth + 1)


def build_json_schemas(run_dir: Path, eps, start_url) -> dict | None:
    """Escribe schemas/<endpoint>.schema.json por endpoint de datos con respuesta JSON y un
    schemas.json consolidado. Devuelve metadatos ({dir, file, count, per_endpoint}) o None."""
    data_eps = [e for e in eps if e.get("response_schema") and not e.get("likely_tracking")
                and (e.get("likely_data_endpoint") or e.get("role") in ("SEARCH", "LIST", "DETAIL"))]
    if not data_eps:
        return None
    schemas_dir = run_dir / "schemas"
    schemas_dir.mkdir(exist_ok=True)
    consolidated = OrderedDict([
        ("$schema", "https://json-schema.org/draft/2020-12/schema"),
        ("title", f"Esquemas de respuesta inferidos: {start_url}"),
        ("description", "Generado por web-network-mapper (analyze.py). Best-effort: tipos inferidos de las "
                        "respuestas JSON observadas (varias muestras determinan nullabilidad y arrays anidados)."),
        ("$defs", OrderedDict()),
    ])
    per_endpoint = {}
    used = set()
    for e in data_eps:
        slug = slugify(e["key"], 70) or f"endpoint_{e.get('index')}"
        base, n = slug, 2
        while slug in used:
            slug = f"{base}_{n}"
            n += 1
        used.add(slug)
        body = infer_to_jsonschema(e["response_schema"])
        try:
            samples = _load_sample_jsons(run_dir, e)
            if samples:
                _annotate_required(body, samples)
                body.setdefault("x-samples", len(samples))
        except Exception:
            pass
        doc = OrderedDict([
            ("$schema", "https://json-schema.org/draft/2020-12/schema"),
            ("$id", f"{slug}.schema.json"),
            ("title", e["key"]),
            ("description", f"Esquema inferido de la respuesta de `{e['key']}` (rol {e.get('role') or 'OTHER'})."),
        ])
        doc.update(body)
        rec = e.get("response_records") or {}
        if rec.get("jsonpath"):
            doc["x-record-array"] = rec["jsonpath"]
        (schemas_dir / f"{slug}.schema.json").write_text(json.dumps(doc, indent=2, ensure_ascii=False, default=list))
        consolidated["$defs"][slug] = body
        per_endpoint[e["key"]] = f"schemas/{slug}.schema.json"
        e["json_schema_file"] = f"schemas/{slug}.schema.json"
    try:  # limpiar esquemas propios obsoletos de un análisis anterior (solo *.schema.json generados aquí)
        keep = {Path(v).name for v in per_endpoint.values()}
        for old in schemas_dir.glob("*.schema.json"):
            if old.name not in keep:
                old.unlink()
    except Exception:
        pass
    cpath = run_dir / "schemas.json"
    cpath.write_text(json.dumps(consolidated, indent=2, ensure_ascii=False, default=list))
    return {"dir": str(schemas_dir.resolve()), "file": str(cpath.resolve()),
            "count": len(per_endpoint), "per_endpoint": per_endpoint}


# ------------------------------------------------------------------ 2) data param (dato de entrada)

DATA_PARAM_SKIP_RE = re.compile(r"^(javax\.faces\.|jsf|__|_|g-recaptcha|h-captcha|cf-turnstile)", re.I)
PLATE_RE = re.compile(r"^[A-Za-z0-9\-]{3,12}$")


def _looks_like_data_value(v) -> int:
    """Puntaje heurístico: ¿parece un dato de entrada (placa, id, término de búsqueda)?"""
    if v is None:
        return 0
    s = str(v).strip()
    if not s or s == REDACTED:
        return 0
    if re.fullmatch(r"true|false|@all|@none", s, re.I):
        return 0
    if UUID_RE.match(s):
        return 5
    if PLATE_RE.match(s) and re.search(r"[A-Za-z]", s) and re.search(r"\d", s):
        return 4  # placa / id alfanumérico corto
    if re.fullmatch(r"\d{1,12}", s):
        return 2
    if re.search(r"[A-Za-z]", s) and re.search(r"\d", s) and len(s) <= 24 and " " not in s:
        return 3
    if HEX_RE.match(s):
        return 3
    if " " in s or (s.replace(" ", "").isalpha() and 2 <= len(s) <= 40):
        return 2  # término de búsqueda
    return 1


def _schema_scalar_examples(s, pre="", out=None, depth=0):
    if out is None:
        out = {}
    if not isinstance(s, dict) or depth > 6:
        return out
    if s.get("properties"):
        for k, v in s["properties"].items():
            _schema_scalar_examples(v, f"{pre}.{k}" if pre else str(k), out, depth + 1)
    elif "example" in s:
        out[pre or "value"] = s["example"]
    return out


def detect_data_param(e) -> dict | None:
    """Identifica el parámetro que el usuario variaría para extracción masiva (placa, id, búsqueda).
    Devuelve {in, name, example, is_search, note} o None."""
    role = e.get("role")
    path = e.get("path_template") or ""
    if role not in ("SEARCH", "DETAIL", "LIST"):
        return None  # ACTION (login, mutaciones) / OTHER: no es un dato de extracción
    if role == "DETAIL" and ("{id}" in path or "{date}" in path):
        ex = (e.get("example_urls") or [None])[0]
        val = None
        if ex:
            tsegs = path.split("/")
            psegs = urlsplit(ex).path.split("/")
            for a, b in zip(tsegs, psegs):
                if a in ("{id}", "{date}"):
                    val = b
        segs = [x for x in path.split("/") if x]
        prev = next((segs[i - 1] for i in range(len(segs) - 1, 0, -1) if segs[i].startswith(("{id}", "{date}"))), "")
        pname = (re.sub(r"[^A-Za-z0-9]+", "_", prev).strip("_").rstrip("s") + "_id") if prev and not prev.startswith("{") else "id"
        return {"in": "path", "name": pname, "example": val, "is_search": False,
                "note": "identificador en la ruta del recurso"}
    cands = []  # (score, in, name, example, is_search)
    qp = e.get("query_params") or {}
    pag = set(e.get("pagination_params") or [])
    for k, info in qp.items():
        leaf = k.split(".")[-1]
        if k in pag or PAGINATION_PARAM_RE.match(leaf) or is_sensitive_field(k):
            continue
        vals = info.get("values") or []
        best = max((_looks_like_data_value(v) for v in vals), default=0)
        is_search = bool(SEARCH_PARAM_RE.match(leaf))
        score = best + (4 if is_search else 0) + (2 if info.get("varies") else 0)
        if score > 0:
            ex = next((v for v in vals if v not in (REDACTED, "")), None)
            cands.append((score, "query", k, ex, is_search or bool(info.get("varies"))))
    rb = e.get("request_body") or {}
    fields = {}
    is_gql = bool(e.get("graphql_operations")) or "GRAPHQL" in (e.get("flags") or [])
    if rb.get("kind") == "form":
        fields = rb.get("fields") or {}
    elif rb.get("kind") == "json":
        fields = _schema_scalar_examples(rb.get("schema"))
        if is_gql:  # el sobre GraphQL (query/operationName/extensions) no es dato: solo variables.*
            fields = {k: v for k, v in fields.items() if k.startswith("variables.")}
    if is_gql:
        cands = [c for c in cands if c[2] not in ("query", "operationName", "extensions", "variables")]
    for k, v in (fields.items() if isinstance(fields, dict) else []):
        leaf = str(k).split(".")[-1]
        if PAGINATION_PARAM_RE.match(leaf) or DATA_PARAM_SKIP_RE.search(str(k)):
            continue
        if is_sensitive_field(leaf) or CAPTCHA_FIELD_RE.search(str(k)):
            continue
        if str(v) == str(k) or str(v) in ("", "@all", "@none"):
            continue  # campos estructurales JSF (nombre==valor)
        is_search = bool(SEARCH_PARAM_RE.match(leaf))
        score = _looks_like_data_value(v) + (4 if is_search else 0)
        if score > 0:
            cands.append((score, "body", k, (v if v != REDACTED else None), is_search))
    if role == "LIST":
        cands = [c for c in cands if c[4] or c[0] >= 5]  # en listados solo si es claramente búsqueda/id variable
    if not cands:
        return None
    cands.sort(key=lambda c: (c[0], c[4]), reverse=True)
    b = cands[0]
    is_search = bool(SEARCH_PARAM_RE.match(str(b[2]).split(".")[-1]))
    varies = b[1] == "query" and bool((qp.get(b[2]) or {}).get("varies"))
    note = ("término de búsqueda" if is_search else
            "filtro que varía entre llamadas" if varies and role == "LIST" else "dato de entrada (id/identificador)")
    return {"in": b[1], "name": b[2], "example": b[3], "is_search": is_search, "note": note}


# ------------------------------------------------------------------ 3) replay.sh (extracción cableada)

def _replay_url_with_vars(url: str) -> tuple[str, dict]:
    """URL con los valores redactados/sensibles de la query como $VARIABLES (misma regla que los curl)."""
    try:
        c = build_curl("GET", url, {}, None, redact=True)
        u = next((a for a in c["args"] if a.startswith(("http://", "https://"))), url)
        return u, c["env"]
    except Exception:
        return url, {}


_GENERIC_SEG_RE = re.compile(r"^(j_?idt\d+|j_id\d*|ruat\w*|input(text)?|\w*_input|\w*_focus|value|field|txt|campo|form|frm\w*|pnl\w*|"
                             r"variables|data|params?|filter|busqueda|datosbusqueda|panel\w*|\d+)$", re.I)


def _data_var_name(name: str) -> str:
    """Nombre corto de variable de shell para el data_param (p.ej. 'a:frm:identificador-placapta:ruatInputText'
    -> IDENTIFICADOR_PLACAPTA)."""
    segs = [x for x in re.split(r"[:.\[\]]+", str(name or "")) if x]
    pick = next((x for x in reversed(segs) if not _GENERIC_SEG_RE.match(x)), segs[-1] if segs else "DATO")
    v = _shvar(pick)
    return v[:40] or "DATO"


def _dq(s: str) -> str:
    """Comillas dobles para bash dejando expandir ${VAR} (escapa \\ \" y `)."""
    return '"' + re.sub(r'([\\"`])', r"\\\1", s) + '"'


def build_replay_script(run_dir: Path, eps, start_url) -> str | None:
    """Genera replay.sh: un comando wnm-replay por endpoint de datos, con la paginación ya cableada
    (usa suggested_replay_args / confirmed_paginator) y el data_param como variable a completar. No
    duplica la lógica de paginación de replay.py: la invoca."""
    from urllib.parse import quote_plus
    data_eps = [e for e in eps if e.get("likely_data_endpoint") and not e.get("third_party")
                and not e.get("likely_tracking")]
    # también endpoints SEARCH/DETAIL propios con dato de entrada aunque no tengan flag DATA (p.ej. JSF)
    for e in eps:
        if e not in data_eps and e.get("data_param") and e.get("role") in ("SEARCH", "DETAIL") \
                and not e.get("third_party") and not e.get("likely_tracking"):
            data_eps.append(e)
    map_path = str((run_dir / "api_map.json").resolve())
    replay = f"{TOOL_DIR}/wnm-replay"
    L = ["#!/usr/bin/env bash",
         f"# Script de extracción generado por web-network-mapper para: {start_url}",
         "# Un comando wnm-replay por endpoint de datos, con la paginación ya cableada.",
         "# La lógica de paginación NO se duplica aquí: la aporta replay.py (wnm-replay).",
         "# Uso: completa las variables marcadas (el 'dato de entrada' de cada endpoint) y ejecuta:",
         "#   ./replay.sh            -> corre todos los endpoints",
         "#   ./replay.sh 2          -> corre solo el endpoint #2",
         "# Los resultados se guardan en $OUT_DIR como CSV + JSON (--format both).",
         "# Si la captura redactó secretos, exporta antes las variables indicadas (AUTHORIZATION, COOKIE, ...).",
         "set -euo pipefail",
         f'MAP="${{MAP:-{map_path}}}"',
         'OUT_DIR="${OUT_DIR:-./extracts}"; mkdir -p "$OUT_DIR"',
         'MAX_PAGES="${MAX_PAGES:-5}"   # 0 = hasta agotar la paginación (tope duro de replay.py)',
         'DELAY="${DELAY:-1}"           # segundos entre requests (respeta el rate limit)',
         'ONLY="${1:-}"                 # número de endpoint a ejecutar (vacío = todos)',
         ""]
    if not data_eps:
        L.append("# (no se detectaron endpoints de datos aptos para extracción automática)")
        return "\n".join(L) + "\n"
    used_vars = set()
    for e in data_eps:
        idx = e.get("index")
        rp = e.get("replay") or {}
        L.append(f"# ---- Endpoint {idx}: {e['key']}  (rol {e.get('role') or 'OTHER'})")
        dp = e.get("data_param")
        pag_args = e.get("suggested_replay_args") or ""
        if e.get("pagination_confirmed"):
            L.append(f"#   Paginación CONFIRMADA por `{e.get('confirmed_paginator')}`.")
        elif pag_args:
            L.append("#   Paginación sugerida por nombre de parámetro (no confirmada con dos llamadas distintas).")
        else:
            L.append("#   Sin paginación detectada: una sola request por valor del dato de entrada.")
        if e.get("rate_limit_note"):
            L.append(f"#   Rate limit observado: {e['rate_limit_note']} -> sube DELAY si ves 429.")
        if "PROTOBUF" in (e.get("flags") or []) or "GRPC" in (e.get("flags") or []):
            L.append("#   AVISO: cuerpo protobuf/gRPC; replay.py espera JSON en la respuesta, puede no extraer registros.")
        L.append(f'if [ -z "$ONLY" ] || [ "$ONLY" = "{idx}" ]; then')
        cmd = [replay, '"$MAP"', str(idx)]
        env = {}
        if dp:
            var = _data_var_name(dp.get("name") or "DATO")
            if var in ("MAP", "OUT_DIR", "MAX_PAGES", "DELAY", "ONLY", "EXTRA"):
                var = "DATO_" + var
            if var in used_vars:
                var = f"{var}_{idx}"  # otro endpoint ya usa ese nombre: evitar que un valor se filtre al siguiente
            used_vars.add(var)
            ex = dp.get("example")
            default = str(ex) if ex not in (None, "", REDACTED) else "CAMBIAME"
            L.append(f"  # Dato de entrada ({dp.get('note')}): {dp.get('in')} `{dp.get('name')}`. Edita ${var}")
            L.append(f"  {var}=\"${{{var}:-{re.sub(r'([\\"`$])', r'\\\1', default)}}}\"")
            if dp["in"] == "query":
                cmd += ["--param", _dq(f"{dp['name']}=${{{var}}}")]
            elif dp["in"] == "body" and (e.get("request_body") or {}).get("kind") == "json":
                cmd += ["--body-set", _dq(f"{dp['name']}=${{{var}}}")]
            elif dp["in"] == "path":
                ex_url = rp.get("url") or (e.get("example_urls") or [None])[0]
                if ex_url and ex and str(ex) in urlsplit(ex_url).path:
                    u, env_u = _replay_url_with_vars(ex_url)
                    env.update(env_u)
                    cmd += ["--url", _dq(u.replace(str(ex), f"${{{var}}}", 1))]
                else:
                    L.append(f"  # TODO: agrega --url con ${var} insertado en la ruta")
            else:  # cuerpo form: se reenvía el POST capturado con el campo sustituido
                pd = rp.get("post_data") or ""
                if pd and REDACTED not in pd and "%5BREDACTED%5D" not in pd:
                    pairs = parse_qsl(pd, keep_blank_values=True)
                    parts = []
                    for k, v in pairs:
                        if k == dp["name"]:
                            parts.append(f"{quote_plus(k)}=${{{var}}}")
                        else:
                            parts.append(f"{quote_plus(k)}={quote_plus(v)}")
                    cmd += ["--data", _dq("&".join(parts))]
                    if any(HIDDEN_TOKEN_FIELDS and (k in HIDDEN_TOKEN_FIELDS or CAPTCHA_FIELD_RE.search(k)) for k, _ in pairs):
                        L.append("  # AVISO: el POST lleva tokens de un solo uso (ViewState/CSRF) y/o captcha: caducan.")
                        L.append("  #        Sigue el flujo completo (flow.sh) para obtener valores frescos antes de este paso.")
                else:
                    L.append(f"  # TODO (cuerpo form redactado): pasa --data con `{dp['name']}=${var}` y el resto de campos.")
        else:
            L.append("  # (sin dato de entrada variable detectado: extrae la lista/paginación completa)")
        # headers que la captura redactó -> se pasan desde variables de entorno si están exportadas
        red_hdrs = [k for k, v in (rp.get("headers") or {}).items()
                    if isinstance(v, str) and REDACTED in v and not k.startswith(":")]
        L.append("  EXTRA=()")
        for h in red_hdrs:
            ev = _shvar(h)
            L.append(f'  [ -n "${{{ev}:-}}" ] && EXTRA+=(--header "{_canon_hdr(h)}: ${{{ev}}}")  # redactado en la captura')
        for ev, desc in env.items():
            L.append(f"  : \"${{{ev}:?exporta {ev} ({desc})}}\"")
        if pag_args:
            cmd.append(pag_args)
        cmd += ["--max-pages", '"$MAX_PAGES"', "--delay", '"$DELAY"', "--format", "both",
                "--out", f'"$OUT_DIR/endpoint_{idx}"', '${EXTRA[@]+"${EXTRA[@]}"}']
        L.append("  " + " ".join(cmd))
        L.append("fi")
        L.append("")
    L.append('echo "Extracción lista. Revisa $OUT_DIR/" >&2')
    return "\n".join(L) + "\n"


# ------------------------------------------------------------------ 4) protobuf / gRPC decode

def _read_varint(b, i):
    shift = 0
    result = 0
    while i < len(b):
        byte = b[i]
        i += 1
        result |= (byte & 0x7F) << shift
        if not (byte & 0x80):
            return result, i
        shift += 7
        if shift > 63:
            return None, i
    return None, i


def _printable_text(chunk: bytes):
    if len(chunk) < 2:
        return None
    try:
        t = chunk.decode("utf-8")
    except UnicodeDecodeError:
        return None
    if any((ord(c) < 32 and c not in "\t\n\r") for c in t):
        return None
    letters = sum(c.isalnum() or c.isspace() or c in "-_.:/@" for c in t)
    if letters / max(1, len(t)) < 0.7:
        return None
    return t


def _pb_scan(raw: bytes, depth=0):
    """Escáner genérico de wire-format protobuf. Devuelve (campos, fully_parsed)."""
    out = []
    i, n = 0, len(raw)
    ok = True
    while i < n:
        tag, i = _read_varint(raw, i)
        if tag is None:
            ok = False
            break
        field = tag >> 3
        wt = tag & 7
        if field == 0:
            ok = False
            break
        if wt == 0:
            v, i = _read_varint(raw, i)
            if v is None:
                ok = False
                break
            out.append({"field": field, "wire_type": 0, "type": "varint", "value": v})
        elif wt == 1:
            if i + 8 > n:
                ok = False
                break
            out.append({"field": field, "wire_type": 1, "type": "fixed64", "value_hex": raw[i:i + 8].hex()})
            i += 8
        elif wt == 2:
            ln, i = _read_varint(raw, i)
            if ln is None or i + ln > n:
                ok = False
                break
            chunk = raw[i:i + ln]
            i += ln
            entry = {"field": field, "wire_type": 2, "type": "bytes", "len": ln}
            txt = _printable_text(chunk)
            sub, subok = (_pb_scan(chunk, depth + 1) if (depth < 5 and ln > 0) else ([], False))
            if txt is not None:
                # texto legible: string (si además parsea como mensaje se deja la alternativa)
                entry = {"field": field, "wire_type": 2, "type": "string", "value": txt[:300]}
                if subok and sub and len(sub) > 1:
                    entry["alt_message"] = sub
            elif subok and sub:
                entry = {"field": field, "wire_type": 2, "type": "message", "fields": sub}
            else:
                entry["value_hex"] = chunk[:80].hex()
            out.append(entry)
        elif wt == 5:
            if i + 4 > n:
                ok = False
                break
            out.append({"field": field, "wire_type": 5, "type": "fixed32", "value_hex": raw[i:i + 4].hex()})
            i += 4
        else:
            ok = False
            break
    return out, (ok and i == n)


def protobuf_generic_decode(raw: bytes):
    """Volcado genérico sin esquema (número de campo + wire type + valor crudo)."""
    if not raw:
        return None
    fields, ok = _pb_scan(raw)
    if not fields:
        return None
    return {"fully_parsed": ok, "fields": fields}


def _iter_grpc_web_frames(raw: bytes):
    """Separa el framing gRPC-web (prefijo de 5 bytes: 1 flag + 4 longitud big-endian). Los frames
    con el bit 0x80 (trailers) se omiten. Si no hay framing válido, devuelve el cuerpo tal cual."""
    if len(raw) >= 5:
        i, n = 0, len(raw)
        frames = []
        valid = True
        while i + 5 <= n:
            flag = raw[i]
            ln = int.from_bytes(raw[i + 1:i + 5], "big")
            if i + 5 + ln > n:
                valid = False
                break
            payload = raw[i + 5:i + 5 + ln]
            if not (flag & 0x80):  # 0x80 = trailers, no es un mensaje
                frames.append(payload)
            i += 5 + ln
        if valid and i == n and frames:
            return frames
    return [raw]


class ProtoDecoder:
    """Decodifica protobuf/gRPC a JSON cuando el usuario aporta un .proto o un FileDescriptorSet."""

    def __init__(self, proto=None, descriptor=None):
        self.enabled = False
        self.error = None
        self.msg_classes = []
        self.type_names = []
        try:
            from google.protobuf import descriptor_pb2, descriptor_pool, message_factory  # noqa: F401
        except Exception as e:  # protobuf no instalado
            self.error = f"librería protobuf no disponible: {e}"
            return
        fds_bytes = []
        try:
            if descriptor:
                fds_bytes.append(Path(descriptor).read_bytes())
            if proto:
                fb = self._compile_proto(proto)
                if fb:
                    fds_bytes.append(fb)
        except SystemExit as e:
            self.error = str(e)[:200]
        except Exception as e:
            self.error = str(e)[:200]
        if not fds_bytes:
            if not self.error:
                self.error = "sin --proto ni --descriptor válidos"
            return
        try:
            from google.protobuf import descriptor_pb2, descriptor_pool, message_factory
            pool = descriptor_pool.DescriptorPool()
            seen = set()
            files = []
            for fb in fds_bytes:
                fs = descriptor_pb2.FileDescriptorSet()
                fs.ParseFromString(fb)
                for f in fs.file:
                    if f.name in seen:
                        continue
                    seen.add(f.name)
                    files.append(f)
            for f in files:
                try:
                    pool.Add(f)
                except Exception:
                    pass
            for f in files:
                for mt in f.message_type:
                    full = (f.package + "." if f.package else "") + mt.name
                    try:
                        md = pool.FindMessageTypeByName(full)
                        self.msg_classes.append((full, message_factory.GetMessageClass(md)))
                        self.type_names.append(full)
                    except Exception:
                        pass
            self.enabled = bool(self.msg_classes)
            if not self.enabled and not self.error:
                self.error = "no se encontraron mensajes en el esquema aportado"
        except Exception as e:
            self.error = str(e)[:200]

    def _compile_proto(self, proto):
        from grpc_tools import protoc
        import grpc_tools
        import os as _osx
        import tempfile
        p = Path(proto)
        if p.is_dir():
            protos = [str(x) for x in p.rglob("*.proto")]
            includes = {str(p)}
        elif p.is_file():
            protos = [str(p)]
            includes = {str(p.parent)}
        else:
            raise SystemExit(f"--proto no existe: {proto}")
        if not protos:
            raise SystemExit("no se encontraron archivos .proto")
        wk = _osx.path.join(_osx.path.dirname(grpc_tools.__file__), "_proto")
        tf = tempfile.NamedTemporaryFile(suffix=".fds", delete=False)
        tf.close()
        args = ["protoc"] + [f"-I{i}" for i in includes] + [f"-I{wk}",
                "--include_imports", f"--descriptor_set_out={tf.name}"] + protos
        rc = protoc.main(args)
        if rc == 0:
            return Path(tf.name).read_bytes()
        if len(protos) > 1:
            # degradar: compilar archivo por archivo y juntar los que compilan
            from google.protobuf import descriptor_pb2
            merged = descriptor_pb2.FileDescriptorSet()
            names, failed = set(), []
            for one in protos:
                rc1 = protoc.main(["protoc"] + [f"-I{i}" for i in includes] + [f"-I{wk}", "--include_imports",
                                  f"--descriptor_set_out={tf.name}", one])
                if rc1 != 0:
                    failed.append(Path(one).name)
                    continue
                part = descriptor_pb2.FileDescriptorSet()
                part.ParseFromString(Path(tf.name).read_bytes())
                for f in part.file:
                    if f.name not in names:
                        names.add(f.name)
                        merged.file.append(f)
            if merged.file:
                if failed:
                    self.error = f"se omitieron .proto que no compilan: {', '.join(failed[:10])}"
                return merged.SerializeToString()
        raise SystemExit(f"protoc falló al compilar el .proto (rc={rc})")

    def decode(self, raw: bytes, prefer: str | None = None, direction: str = "response"):
        """Prueba cada mensaje del esquema; elige el que deja menos campos desconocidos y más campos conocidos."""
        from google.protobuf import json_format
        try:
            from google.protobuf import unknown_fields as _uf
        except Exception:
            _uf = None
        classes = self.msg_classes
        if prefer:
            classes = [c for c in classes if c[0] == prefer or c[0].endswith("." + prefer)] or classes
        best = None
        for name, Cls in classes:
            try:
                m = Cls()
                m.ParseFromString(raw)
            except Exception:
                continue
            try:
                d = json_format.MessageToDict(m)
            except Exception:
                continue
            if not d:
                continue
            unknown = 0
            if _uf is not None:
                try:
                    unknown = len(_uf.UnknownFieldSet(m))
                except Exception:
                    unknown = 0
            is_req_name = bool(re.search(r"(Request|Req|Params|Query|Input)$", name))
            dir_ok = is_req_name if direction == "request" else not is_req_name
            score = (-unknown, len(m.ListFields()), dir_ok, len(json.dumps(d, default=str)))
            if best is None or score > best[0]:
                best = (score, name, d, unknown)
        if best:
            out = {"message_type": best[1], "json": best[2]}
            if best[3]:
                out["unknown_fields"] = best[3]
            return out
        return None


_PROTO_DECODER_CACHE: dict = {}


def get_proto_decoder(proto=None, descriptor=None):
    """ProtoDecoder cacheado por (proto, descriptor) para no compilar el .proto dos veces."""
    if not (proto or descriptor):
        return None
    k = (str(proto or ""), str(descriptor or ""))
    if k not in _PROTO_DECODER_CACHE:
        _PROTO_DECODER_CACHE[k] = ProtoDecoder(proto, descriptor)
    return _PROTO_DECODER_CACHE[k]


def _decode_protobuf_endpoints(run_dir: Path, eps, proto=None, descriptor=None, api_map=None, proto_message=None):
    """Decodifica bodies protobuf/gRPC-web de los endpoints marcados. Con --proto/--descriptor intenta
    mapear el mensaje real; si no, hace un volcado genérico sin esquema. Degrada limpio."""
    targets = [e for e in eps if (e.get("body_kind") in ("grpc", "protobuf"))
               or any(f in (e.get("flags") or []) for f in ("GRPC", "PROTOBUF"))]
    if not targets:
        return
    dec = None
    if proto or descriptor:
        dec = get_proto_decoder(proto, descriptor)
        if api_map is not None:
            api_map["protobuf_decoder"] = {"enabled": dec.enabled, "error": dec.error, "types": dec.type_names[:50]}
    for e in targets:
        results = []
        for bf in (e.get("sample_bodies") or [])[:3]:
            try:
                raw = (Path(run_dir) / bf).read_bytes()
            except Exception:
                continue
            for frame in _iter_grpc_web_frames(raw):
                item = {"body_file": bf, "bytes": len(frame)}
                done = False
                if dec and dec.enabled:
                    try:
                        d = dec.decode(frame, proto_message)
                    except Exception:
                        d = None
                    if d:
                        item["schema"] = True
                        item.update(d)
                        done = True
                if not done:
                    try:
                        g = protobuf_generic_decode(frame)
                    except Exception:
                        g = None
                    if g:
                        item["schema"] = False
                        item["generic"] = g
                if item.get("schema") is not None:
                    results.append(item)
        try:
            pd = (e.get("replay") or {}).get("post_data")
            if pd and REDACTED not in pd:
                try:
                    raw_req = pd.encode("latin-1")
                except UnicodeEncodeError:
                    raw_req = pd.encode("utf-8")
                for frame in _iter_grpc_web_frames(raw_req)[:2]:
                    item = {"body_file": "(request body)", "direction": "request", "bytes": len(frame)}
                    d = dec.decode(frame, None, "request") if (dec and dec.enabled) else None
                    if d:
                        item["schema"] = True
                        item.update(d)
                    else:
                        g = protobuf_generic_decode(frame)
                        if g:
                            item["schema"] = False
                            item["generic"] = g
                    if item.get("schema") is not None:
                        results.append(item)
        except Exception:
            pass
        if results:
            e["protobuf_decoded"] = {"schema_based": any(r.get("schema") for r in results), "frames": results[:6]}


# ------------------------------------------------------------------ 5) Postman collection (v2.1.0)

def _postman_url_obj(raw_url: str, e) -> dict:
    """URL de Postman con {{host}} como variable de colección (ruta/query separadas)."""
    u = urlsplit(raw_url)
    base = f"{u.scheme}://{u.netloc}"
    var = "host" if base == e.get("_pm_host0") else "host_" + re.sub(r"[^A-Za-z0-9]+", "_", u.netloc).strip("_")
    e["_pm_hostvar"] = (var, base)
    path_segs = [x for x in (u.path or "/").split("/") if x != ""]
    raw = "{{" + var + "}}" + (u.path or "/") + (("?" + u.query) if u.query else "")
    obj = {"raw": raw, "host": ["{{" + var + "}}"], "path": path_segs}
    if u.query:
        obj["query"] = [{"key": k, "value": v} for k, v in parse_qsl(u.query, keep_blank_values=True)]
    return obj


def build_postman(api_map, redact: bool = True) -> dict:
    """Colección Postman v2.1.0 con los endpoints first-party (mismos que van a OpenAPI).
    Carpetas por rol (SEARCH/LIST/DETAIL/...). Variables de colección: {{host}} y {{token}}
    (más una por cada secreto redactado, igual que los curl)."""
    from wnm_curl import build_postman_parts
    eps = [e for e in api_map.get("endpoints", []) if not e.get("likely_tracking") and not e.get("third_party")]
    host0 = f"{eps[0].get('scheme') or 'https'}://{eps[0]['host']}" if eps else ""
    folders: "OrderedDict[str, list]" = OrderedDict()
    variables: "OrderedDict[str, dict]" = OrderedDict()
    variables["host"] = {"key": "host", "value": host0, "description": "Origen (esquema + host) del sitio"}
    variables["token"] = {"key": "token", "value": "", "description": "Valor completo del header Authorization (p.ej. 'Bearer ...')"}
    for e in eps:
        rp = e.get("replay") or {}
        method = (rp.get("method") or e.get("method") or "GET").upper()
        url = rp.get("url") or (e.get("example_urls") or [f"{host0}{e.get('path_template') or '/'}"])[0]
        body = rp.get("post_data") if method not in ("GET", "HEAD") else None
        parts = build_postman_parts(method, url, rp.get("headers") or {}, body, redact=redact)
        for var, desc in (parts.get("vars") or {}).items():
            variables.setdefault(var, {"key": var, "value": "", "description": desc})
        e_ctx = dict(e)
        e_ctx["_pm_host0"] = host0
        url_obj = _postman_url_obj(parts["url"], e_ctx)
        hv, hbase = e_ctx.get("_pm_hostvar", ("host", host0))
        if hv not in variables:
            variables[hv] = {"key": hv, "value": hbase, "description": "Origen adicional"}
        req = {"method": method, "header": parts["headers"], "url": url_obj}
        rb = e.get("request_body") or {}
        if parts.get("binary_body"):
            req["body"] = {"mode": "file", "file": {}}
            req["description"] = "Cuerpo binario (protobuf/gRPC): adjunta el archivo del cuerpo capturado en bodies/."
        elif parts.get("body") is not None:
            if rb.get("kind") == "form" or "form-urlencoded" in (parts.get("content_type") or ""):
                req["body"] = {"mode": "urlencoded", "urlencoded": [
                    {"key": k, "value": v, "type": "text"} for k, v in parse_qsl(parts["body"], keep_blank_values=True)]}
            else:
                lang = "json" if (parts["body"].strip()[:1] in "[{") else "text"
                req["body"] = {"mode": "raw", "raw": parts["body"], "options": {"raw": {"language": lang}}}
        desc = [f"Rol: {e.get('role') or 'OTHER'} · Flags: {' '.join(e.get('flags') or []) or '-'}"]
        if e.get("data_param"):
            desc.append(f"Dato de entrada sugerido: {e['data_param'].get('in')} `{e['data_param'].get('name')}`.")
        if e.get("suggested_replay_args"):
            desc.append(f"Paginación: `{e['suggested_replay_args']}`")
        req["description"] = ((req.get("description") + "\n") if req.get("description") else "") + "\n".join(desc)
        folders.setdefault(e.get("role") or "OTHER", []).append({"name": e["key"], "request": req})
    items = [{"name": role, "item": lst} for role, lst in folders.items()]
    import uuid as _uuid
    return OrderedDict([
        ("info", {
            "_postman_id": str(_uuid.uuid4()),
            "name": f"API descubierta: {api_map.get('start_url')}",
            "description": "Generado automáticamente por web-network-mapper (analyze.py) a partir del tráfico "
                           "capturado. Completa las variables de colección {{host}} y {{token}} (y las de secretos).",
            "schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json",
        }),
        ("item", items),
        ("variable", list(variables.values())),
    ])


def _canon_hdr(h: str) -> str:
    return "-".join(p[:1].upper() + p[1:] for p in str(h).split("-"))


def _schema_sample(s, depth=0):
    """Genera un ejemplo mínimo desde un esquema inferido (para el body de Postman)."""
    if not isinstance(s, dict) or depth > 8:
        return None
    types = _js_types(s)
    non_null = [x for x in types if x != "null"]
    tt = non_null[0] if non_null else (types[0] if types else None)
    if tt == "object":
        return {str(k): _schema_sample(v, depth + 1) for k, v in (s.get("properties") or {}).items()}
    if tt == "array":
        return [_schema_sample(s["items"], depth + 1)] if s.get("items") else []
    if "example" in s and s["example"] != REDACTED:
        return s["example"]
    return {"integer": 0, "number": 0, "boolean": False, "string": ""}.get(tt, None)


# ------------------------------------------------------------------ WS / SSE (defensivo, opcional)

def _is_stream_entry(r) -> bool:
    """True para entradas WebSocket/SSE marcadas con kind (las HTTP no traen kind o traen 'http')."""
    return isinstance(r, dict) and str(r.get("kind") or "http").lower() in ("websocket", "sse", "ws", "eventsource")


def load_ws_sse(run_dir: Path, recs) -> list:
    """Lee de forma DEFENSIVA las entradas WebSocket/SSE que otro worker puede añadir:
    - un archivo opcional ws_sse.jsonl en el run dir, y/o
    - entradas en requests.jsonl con kind == 'websocket' | 'sse' (las HTTP no traen kind o traen 'http').
    Nunca rompe si no existen."""
    streams: "OrderedDict[tuple, dict]" = OrderedDict()

    def _norm(w):
        kind = str(w.get("kind") or w.get("type") or "").lower()
        if kind in ("ws", "eventsource"):
            kind = "websocket" if kind == "ws" else "sse"
        url = w.get("url") or w.get("request_url") or ""
        if not url:
            return None  # entrada sin URL: no se puede agrupar, se ignora
        key = (kind or "stream", url)
        s = streams.get(key)
        if s is None:
            s = streams[key] = {"kind": kind or "stream", "url": url, "page": w.get("page"),
                                "frames_sent": 0, "frames_received": 0, "messages": 0, "samples": []}
        if not s.get("page") and w.get("page"):
            s["page"] = w.get("page")
        # formato consolidado (mapper.py): una línea por conexión con frames[] (WS) o events[] (SSE)
        if isinstance(w.get("frames"), list) or isinstance(w.get("events"), list):
            for fld in ("frames_sent", "frames_received"):
                if isinstance(w.get(fld), int):
                    s[fld] = max(s.get(fld, 0), w[fld])
            if isinstance(w.get("events_total"), int):
                s["messages"] = max(s.get("messages", 0), w["events_total"])
            elif isinstance(w.get("events"), list):
                s["messages"] = max(s.get("messages", 0), len(w["events"]))
            for key_extra in ("state", "status", "source", "frames_dropped", "events_dropped", "bytes_sent",
                              "bytes_received", "bytes"):
                if w.get(key_extra) is not None:
                    s[key_extra] = w[key_extra]
            for fr in (w.get("frames") or [])[:50]:
                if isinstance(fr, dict) and len(s["samples"]) < 5 and fr.get("payload") is not None:
                    s["samples"].append({"dir": fr.get("dir") or fr.get("direction") or "?",
                                         "payload": str(fr.get("payload"))[:300]})
            for ev in (w.get("events") or [])[:50]:
                if isinstance(ev, dict) and len(s["samples"]) < 5 and ev.get("data") is not None:
                    s["samples"].append({"dir": ev.get("event") or "message", "payload": str(ev.get("data"))[:300]})
            return s
        # contadores tolerantes a distintos formatos (una línea por frame/evento)
        for fld in ("frames_sent", "frames_received", "messages", "events"):
            v = w.get(fld)
            if isinstance(v, int):
                if fld == "events":
                    s["messages"] += v
                else:
                    s[fld] = max(s.get(fld, 0), v) if fld.startswith("frames") else s.get(fld, 0) + v
        ev = str(w.get("event") or "").lower()
        direction = w.get("direction") or w.get("dir")
        payload = w.get("payload") or w.get("data") or w.get("message")
        if ev == "frame" or payload is not None or ev in ("message", "event"):
            if direction == "sent":
                s["frames_sent"] += 1
            elif direction in ("received", "recv"):
                s["frames_received"] += 1
            else:
                s["messages"] += 1
            if payload is not None and len(s["samples"]) < 5:
                s["samples"].append({"dir": direction or (ev or "event"), "payload": str(payload)[:300]})
        return s

    try:
        for w in read_jsonl(run_dir / "ws_sse.jsonl"):
            if isinstance(w, dict):
                _norm(w)
    except Exception:
        pass
    try:
        for r in recs:
            if not isinstance(r, dict):
                continue
            k = str(r.get("kind") or "").lower()
            if k in ("websocket", "sse", "ws", "eventsource"):
                _norm(r)
    except Exception:
        pass
    return list(streams.values())


# ------------------------------------------------------------------ 6) Reporte HTML navegable

def _h(x) -> str:
    import html as _html
    return _html.escape("" if x is None else str(x), quote=True)


_HTML_CSS = """
:root{--bg:#0f1115;--card:#1a1d24;--fg:#e6e6e6;--muted:#9aa4b2;--acc:#5aa9e6;--warn:#e6a45a;--bad:#e65a5a;--ok:#5ae68b;--line:#2a2e37}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);font:14px/1.5 system-ui,Segoe UI,Roboto,Helvetica,Arial,sans-serif}
a{color:var(--acc)}
header{padding:20px 24px;border-bottom:1px solid var(--line);background:var(--card)}
h1{margin:0 0 6px;font-size:20px}
h2{margin:26px 0 10px;font-size:17px;border-left:3px solid var(--acc);padding-left:10px}
h3{margin:16px 0 6px;font-size:15px}
.wrap{max-width:1200px;margin:0 auto;padding:0 24px 60px}
.meta{color:var(--muted);font-size:13px}
.chips{display:flex;flex-wrap:wrap;gap:8px;margin:14px 0}
.chip{background:var(--card);border:1px solid var(--line);border-radius:20px;padding:4px 12px;font-size:12px}
table{border-collapse:collapse;width:100%;margin:8px 0;font-size:13px}
th,td{border:1px solid var(--line);padding:6px 9px;text-align:left;vertical-align:top}
th{background:var(--card);position:sticky;top:0}
tr:nth-child(even) td{background:rgba(255,255,255,.02)}
code,pre{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}
pre{background:#0b0d11;border:1px solid var(--line);border-radius:8px;padding:12px;overflow:auto;font-size:12px}
.flag{display:inline-block;background:#22303f;color:var(--acc);border-radius:4px;padding:1px 6px;margin:1px;font-size:11px}
.flag.DATA{background:#1e3a2a;color:var(--ok)}
.flag.TRACKING,.flag.THIRD_PARTY{background:#3a2a1e;color:var(--warn)}
.flag.AUTH_HEADER,.flag.ISSUES_TOKEN,.flag.RATE_LIMIT{background:#3a1e2a;color:var(--bad)}
details{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:8px 12px;margin:8px 0}
summary{cursor:pointer;font-weight:600}
input#filter{width:100%;max-width:420px;padding:8px 10px;border-radius:8px;border:1px solid var(--line);background:#0b0d11;color:var(--fg);margin:8px 0}
.tag{color:var(--muted);font-size:12px}
.human{color:var(--warn)}
.note{color:var(--muted);font-size:12px;margin:4px 0}
.kbd{background:#0b0d11;border:1px solid var(--line);border-radius:4px;padding:1px 5px;font-size:12px}
.fd{display:flex;flex-direction:column;align-items:flex-start;margin:10px 0}
.fd-box{display:flex;gap:10px;align-items:flex-start;background:var(--card);border:1px solid var(--line);border-left:4px solid var(--acc);border-radius:8px;padding:6px 12px;min-width:420px;max-width:100%}
.fd-box.doc-box{border-left-color:var(--muted)}
.fd-box.form-box{border-left-color:var(--warn)}
.fd-box.human-box{border-left-color:var(--bad);background:#2a1a1a}
.fd-n{font-weight:700;color:var(--acc);min-width:22px}
.fd-arrow{color:var(--muted);margin:0 0 0 18px;line-height:1.1}
.fd-tok{font-size:11px;color:var(--warn)}
"""

_HTML_JS = """
function wnmFilter(){
  var q=document.getElementById('filter').value.toLowerCase();
  var rows=document.querySelectorAll('#ep-table tbody tr');
  rows.forEach(function(r){
    r.style.display = r.innerText.toLowerCase().indexOf(q)>=0 ? '' : 'none';
  });
}
"""


def _flags_html(flags):
    return "".join(f'<span class="flag {_h(f)}">{_h(f)}</span>' for f in (flags or [])) or '<span class="tag">-</span>'


def render_html(m, pages, failed, run_dir: Path) -> str:
    P = []
    P.append("<!doctype html><html lang='es'><head><meta charset='utf-8'>")
    P.append("<meta name='viewport' content='width=device-width,initial-scale=1'>")
    P.append(f"<title>Reporte web-network-mapper: {_h(m.get('start_url'))}</title>")
    P.append("<style>" + _HTML_CSS + "</style></head><body>")
    P.append("<header><div class='wrap'>")
    P.append(f"<h1>Reporte de red — {_h(m.get('start_url'))}</h1>")
    P.append("<div class='meta'>Generado por web-network-mapper (analyze.py). Autocontenido, sin dependencias externas.</div>")
    P.append(f"<div class='meta'>Run dir: <code>{_h(m.get('run_dir'))}</code></div>")
    P.append("</div></header><div class='wrap'>")

    # resumen
    P.append("<div class='chips'>")
    P.append(f"<span class='chip'>Páginas: {_h(m.get('pages_visited'))}</span>")
    P.append(f"<span class='chip'>Requests: {_h(m.get('total_requests'))}</span>")
    P.append(f"<span class='chip'>Endpoints: {_h(m.get('endpoint_count'))} ({_h(m.get('data_endpoint_count'))} de datos)</span>")
    P.append(f"<span class='chip'>Secretos: {'redactados' if m.get('redacted') else 'REALES (--keep-secrets)'}</span>")
    roles = m.get("endpoint_roles") or {}
    for r, c in roles.items():
        P.append(f"<span class='chip'>{_h(r)}: {_h(c)}</span>")
    ab = m.get("anti_bot") or []
    if ab:
        P.append(f"<span class='chip'>Anti-bot: {_h(', '.join(a['vendor'] for a in ab))}</span>")
    P.append("</div>")
    # archivos generados
    files = []
    for label, key in [("OpenAPI", "openapi_file"), ("JSON Schema", "json_schema_file"),
                       ("Postman", "postman_file"), ("replay.sh", "replay_script"),
                       ("flow.md", "flow_md"), ("curls.sh", "curls_file")]:
        if m.get(key):
            files.append(f"<code>{_h(Path(m[key]).name)}</code>")
    if files:
        P.append("<div class='note'>Archivos generados: " + " · ".join(files) + "</div>")

    main = [e for e in m["endpoints"] if not e["likely_tracking"]]

    # diagrama del flujo (mermaid como texto, offline)
    flow = m.get("flow") or []
    if flow:
        P.append("<h2>Diagrama del flujo</h2>")
        P.append("<div class='note'>Diagrama del flujo dibujado en HTML/CSS (sin JS remoto). Rojo = paso humano "
                 "(captcha), naranja = envío de formulario, gris = página. Abajo, el mismo diagrama en sintaxis Mermaid "
                 "(bloque de texto) para pegarlo en un visor Mermaid o Markdown compatible.</div>")
        lines = ["flowchart TD"]
        prev = None
        for s in flow[:40]:
            nid = f"s{s['step']}"
            lbl = f"{s['step']}. {s['method']} {urlsplit(s['url']).path or '/'}"[:60]
            lbl = lbl.replace('"', "'")
            mark = " 🧑" if s.get("needs_human") else ""
            lines.append(f'  {nid}["{lbl}{mark}"]')
            if prev:
                lines.append(f"  {prev} --> {nid}")
            prev = nid
        # diagrama visual simple en HTML/CSS (sin JS)
        P.append("<div class='fd'>")
        for s in flow[:60]:
            cls = "fd-box"
            if s.get("needs_human"):
                cls += " human-box"
            elif s.get("is_form_submit"):
                cls += " form-box"
            elif s.get("is_document"):
                cls += " doc-box"
            toks = ""
            if s.get("issues_tokens"):
                toks += "<div class='fd-tok'>🔑 emite: " + _h(", ".join(t["name"] for t in s["issues_tokens"][:3])) + "</div>"
            if s.get("consumes_tokens"):
                toks += "<div class='fd-tok'>↳ usa: " + _h(", ".join(f"{t['name']} (paso {t['from_step']})" for t in s["consumes_tokens"][:3])) + "</div>"
            P.append(f"<div class='{cls}'><div class='fd-n'>{_h(s['step'])}</div>"
                     f"<div><b>{_h(s['method'])}</b> <code>{_h((urlsplit(s['url']).path or '/')[:70])}</code> "
                     f"<span class='tag'>{_h(s['status'])}</span>{' 🧑' if s.get('needs_human') else ''}{toks}</div></div>")
            P.append("<div class='fd-arrow'>↓</div>")
        if P and P[-1] == "<div class='fd-arrow'>↓</div>":
            P.pop()
        P.append("</div>")
        P.append("<details><summary>Mismo diagrama en sintaxis Mermaid</summary>")
        P.append("<pre>```mermaid\n" + _h("\n".join(lines)) + "\n```</pre></details>")

    # endpoints
    P.append("<h2>Endpoints</h2>")
    if not main:
        P.append("<div class='note'>No se capturaron endpoints XHR/fetch/JSON. El sitio puede ser renderizado en "
                 "servidor: revisa las páginas HTML y los datos embebidos.</div>")
    else:
        P.append("<input id='filter' onkeyup='wnmFilter()' placeholder='Filtrar endpoints (texto, flag, rol, host)…'>")
        P.append("<table id='ep-table'><thead><tr><th>#</th><th>Endpoint</th><th>Rol</th><th>Llamadas</th>"
                 "<th>Status</th><th>Respuesta</th><th>Dato entrada</th><th>Flags</th></tr></thead><tbody>")
        for e in main:
            dp = e.get("data_param")
            dp_txt = (f"{_h(dp['in'])}:{_h(dp['name'])}" if dp else "-")
            P.append("<tr>")
            P.append(f"<td>{_h(e['index'])}</td>")
            P.append(f"<td><code>{_h(e['key'])}</code></td>")
            P.append(f"<td>{_h(e.get('role') or '-')}</td>")
            P.append(f"<td>{_h(e['calls'])}</td>")
            P.append(f"<td>{_h(_fmt_counter(e['statuses']))}</td>")
            P.append(f"<td>{_h(', '.join(e['response_content_types']) or '-')}</td>")
            P.append(f"<td>{dp_txt}</td>")
            P.append(f"<td>{_flags_html(e['flags'])}</td>")
            P.append("</tr>")
        P.append("</tbody></table>")
        # detalle colapsable por endpoint
        for e in main:
            P.append(f"<details><summary>{_h(e['index'])}. {_h(e['key'])}</summary>")
            P.append(f"<div class='note'>Rol: <b>{_h(e.get('role') or 'OTHER')}</b> · Flags: {_flags_html(e['flags'])}</div>")
            if e.get("example_urls"):
                P.append(f"<div class='note'>Ejemplo: <code>{_h(e['example_urls'][0])}</code></div>")
            dp = e.get("data_param")
            if dp:
                P.append(f"<div class='note'>Dato de entrada sugerido ({_h(dp.get('note'))}): "
                         f"<span class='kbd'>{_h(dp.get('in'))} {_h(dp.get('name'))}</span>"
                         + (f" — ej. <code>{_h(dp.get('example'))}</code>" if dp.get('example') else "") + "</div>")
            if e.get("query_params"):
                qp = "; ".join(f"<code>{_h(k)}</code>=" + ", ".join(_h(x) for x in (v.get('values') or [])[:5])
                               for k, v in e["query_params"].items())
                P.append(f"<div class='note'>Query params: {qp}</div>")
            rec = e.get("response_records")
            if rec:
                P.append(f"<div class='note'>Registros: <code>{_h(rec['jsonpath'])}</code> "
                         f"({_h(rec['length'])} items) — claves: {_h(', '.join(rec['item_keys'][:15]))}</div>")
            if e.get("suggested_replay_args") is not None:
                P.append(f"<div class='note'>Replay: <code>wnm-replay api_map.json {_h(e['index'])} "
                         f"{_h(e.get('suggested_replay_args') or '')} --max-pages 5</code></div>")
            pdq = e.get("protobuf_decoded")
            if pdq:
                P.append(f"<div class='note'>Protobuf {'(con esquema)' if pdq.get('schema_based') else '(genérico sin esquema)'} — "
                         f"{len(pdq.get('frames') or [])} frame(s) decodificado(s).</div>")
                fr = (pdq.get("frames") or [])[:1]
                if fr:
                    body = fr[0].get("json") or fr[0].get("generic")
                    P.append("<pre>" + _h(json.dumps(body, indent=2, ensure_ascii=False, default=str)[:2000]) + "</pre>")
            if e.get("response_schema"):
                P.append("<b>Esquema de respuesta (inferido)</b>")
                P.append("<pre>" + _h("\n".join(schema_outline(e["response_schema"], max_lines=35))) + "</pre>")
            if e.get("curl"):
                P.append("<b>curl (llamada representativa)</b>")
                P.append("<pre>" + _h(e["curl"]) + "</pre>")
            P.append("</details>")

    # flujo
    if flow:
        P.append("<h2>Flujo completo (inicio a fin)</h2>")
        if m.get("flow_needs_human"):
            P.append("<div class='note human'>🧑 El flujo tiene pasos que requieren un humano (captcha u otro desafío).</div>")
        P.append("<table><thead><tr><th>Paso</th><th>Método</th><th>URL</th><th>Status</th><th>Tipo</th><th>Humano</th></tr></thead><tbody>")
        for s in flow:
            kind = "captcha" if s.get("is_captcha_asset") else ("form POST" if s.get("is_form_submit")
                   else ("página" if s.get("is_document") else s.get("resource_type") or "-"))
            P.append("<tr>")
            P.append(f"<td>{_h(s['step'])}</td><td>{_h(s['method'])}</td>"
                     f"<td><code>{_h(s['url'][:120])}</code></td><td>{_h(s['status'])}</td>"
                     f"<td>{_h(kind)}</td><td>{'🧑' if s.get('needs_human') else ''}</td>")
            P.append("</tr>")
        P.append("</tbody></table>")

    # auth / tokens
    af = m.get("auth_flow") or {}
    toks = af.get("tokens") or []
    P.append("<h2>Autenticación / tokens</h2>")
    if not toks:
        P.append("<div class='note'>No se detectaron tokens (cookies de sesión, Bearer/JWT, CSRF/ViewState).</div>")
    else:
        P.append("<table><thead><tr><th>Token</th><th>Tipo</th><th>Emitido por</th><th>Usado por</th><th>Transporte</th></tr></thead><tbody>")
        for t in toks[:40]:
            iss = "<br>".join(_h(f"{i['endpoint'][:60]} (seq {i['seq']})") for i in t["issued_by"][:2]) or "<span class='tag'>(previo a la captura)</span>"
            con = "<br>".join(_h(f"{c['endpoint'][:60]} ×{c['count']}") for c in t["consumed_by"][:4]) or "-"
            P.append(f"<tr><td><code>{_h(t['name'])}</code></td><td>{_h(t['kind'])}"
                     f"{' (sesión)' if t.get('session_like') else ''}</td><td>{iss}</td><td>{con}</td>"
                     f"<td>{_h(t['carried_by'])}</td></tr>")
        P.append("</tbody></table>")

    # anti-bot
    P.append("<h2>Protección anti-bot</h2>")
    if not ab:
        P.append("<div class='note'>No se detectaron proveedores anti-bot conocidos ni desafíos JS genéricos.</div>")
    else:
        for a in ab:
            P.append(f"<h3>{_h(a['vendor'])} — {'desafío ACTIVO' if a.get('active') else 'señales pasivas'} "
                     f"({_h(a['requests'])} request(s))</h3>")
            P.append(f"<div class='note'>Evidencia: {_h(', '.join(a['evidence'][:8]))}</div>")
            P.append(f"<div class='note'>Estrategia: {_h(a['strategy'])}</div>")

    # rate limit
    rls = m.get("rate_limit_summary") or {}
    if rls.get("endpoints_with_rate_limit"):
        P.append("<h2>Rate limit</h2>")
        P.append(f"<div class='note'>{_h(rls['endpoints_with_rate_limit'])} endpoint(s) con señales de rate limit; "
                 f"{_h(rls.get('status_429_total', 0))} respuesta(s) 429.</div>")
        P.append("<ul>")
        for n in rls.get("notes") or []:
            P.append(f"<li><code>{_h(n['endpoint'])}</code>: {_h(n['note'])}</li>")
        P.append("</ul>")

    # ws / sse
    wss = m.get("ws_sse") or []
    legacy_ws = m.get("websockets") or []
    if wss or legacy_ws:
        P.append("<h2>WebSocket / SSE</h2>")
        for w in legacy_ws:
            P.append(f"<div class='note'>WS <code>{_h(w['url'])}</code> — enviados {_h(w['frames_sent'])}, "
                     f"recibidos {_h(w['frames_received'])}</div>")
            for s in w.get("samples", [])[:3]:
                P.append(f"<div class='note'>&nbsp;&nbsp;{_h(s['dir'])}: <code>{_h(s['payload'][:150])}</code></div>")
        for w in wss:
            P.append(f"<div class='note'>{_h((w.get('kind') or 'stream').upper())} <code>{_h(w.get('url'))}</code> — "
                     f"enviados {_h(w.get('frames_sent', 0))}, recibidos {_h(w.get('frames_received', 0))}, "
                     f"mensajes {_h(w.get('messages', 0))}</div>")
            for s in (w.get("samples") or [])[:3]:
                P.append(f"<div class='note'>&nbsp;&nbsp;{_h(s.get('dir'))}: <code>{_h(str(s.get('payload'))[:150])}</code></div>")

    P.append("<script>" + _HTML_JS + "</script>")
    P.append("</div></body></html>")
    return "\n".join(P)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("run_dir")
    ap.add_argument("--map-documents", action="store_true", help="include HTML document requests as endpoints")
    ap.add_argument("--emit-curl", nargs="?", const="all", choices=["all", "api", "nonstatic"],
                    help="also write curls.sh: every captured request as one curl line, deduplicated (default scope: all)")
    g = ap.add_mutually_exclusive_group()
    g.add_argument("--curl-secrets", action="store_true",
                   help="put real secret values in curl output (only possible if the run used --keep-secrets)")
    g.add_argument("--curl-redact", action="store_true",
                   help="force $VARIABLE placeholders in curl output even for a --keep-secrets run")
    g2 = ap.add_mutually_exclusive_group()
    g2.add_argument("--openapi", dest="openapi", action="store_true", default=True,
                    help="write openapi.json (OpenAPI 3.0) when endpoints were found (default: on)")
    g2.add_argument("--no-openapi", dest="openapi", action="store_false", help="do not write openapi.json")
    ap.add_argument("--json", action="store_true",
                    help="machine-readable output: print only the JSON summary on stdout (notes go to stderr)")
    g3 = ap.add_mutually_exclusive_group()
    g3.add_argument("--json-schema", dest="json_schema", action="store_true", default=True,
                    help="write schemas/<endpoint>.schema.json + schemas.json (JSON Schema 2020-12) (default: on)")
    g3.add_argument("--no-json-schema", dest="json_schema", action="store_false", help="do not write JSON Schemas")
    g4 = ap.add_mutually_exclusive_group()
    g4.add_argument("--postman", dest="postman", action="store_true", default=True,
                    help="write postman_collection.json (Postman v2.1.0) (default: on)")
    g4.add_argument("--no-postman", dest="postman", action="store_false", help="do not write postman_collection.json")
    g5 = ap.add_mutually_exclusive_group()
    g5.add_argument("--html", dest="html", action="store_true", default=True,
                    help="write report.html, a self-contained offline report (default: on)")
    g5.add_argument("--no-html", dest="html", action="store_false", help="do not write report.html")
    g6 = ap.add_mutually_exclusive_group()
    g6.add_argument("--replay-script", dest="replay_script", action="store_true", default=True,
                    help="write replay.sh with one wnm-replay command per data endpoint (default: on)")
    g6.add_argument("--no-replay-script", dest="replay_script", action="store_false", help="do not write replay.sh")
    ap.add_argument("--proto", metavar="FILE|DIR",
                    help="a .proto file or a directory of .proto files, used to decode protobuf/gRPC-web bodies to JSON")
    ap.add_argument("--descriptor", metavar="FDS",
                    help="a FileDescriptorSet (protoc --descriptor_set_out --include_imports) to decode protobuf bodies")
    ap.add_argument("--proto-message", metavar="TYPE",
                    help="with --proto/--descriptor: force this message type (e.g. pkg.Response) instead of auto-detect")
    a = ap.parse_args()
    s = build(a.run_dir, a.map_documents, a.emit_curl, a.curl_secrets, a.curl_redact, write_openapi=a.openapi,
              write_json_schema=a.json_schema, write_postman=a.postman, write_html=a.html,
              write_replay=a.replay_script, proto=a.proto, descriptor=a.descriptor, proto_message=a.proto_message)
    if a.json:
        print(json.dumps(s, ensure_ascii=False, sort_keys=False, default=list))
    else:
        print(json.dumps(s, default=list))


if __name__ == "__main__":
    main()
