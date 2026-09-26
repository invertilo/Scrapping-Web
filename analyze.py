#!/usr/bin/env python3
"""Build api_map.json / api_map.md (and enrich pages.json) from a mapper run directory.

Usage: analyze.py RUN_DIR [--map-documents] [--emit-curl [all|api|nonstatic]] [--curl-secrets | --curl-redact]
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
from wnm_common import REDACTED, is_sensitive_field, is_sensitive_header, loads_lenient  # noqa: E402
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


def load_body_json(run_dir: Path, rec):
    bf = rec.get("body_file")
    if not bf or rec.get("body_truncated"):
        return None
    try:
        text = (run_dir / bf).read_text(encoding="utf-8", errors="replace")
    except OSError:
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
          curl_redact: bool = False) -> dict:
    run_dir = Path(run_dir)
    recs = read_jsonl(run_dir / "requests.jsonl")
    pages_path = run_dir / "pages.json"
    pages = json.loads(pages_path.read_text()) if pages_path.exists() else []
    meta = json.loads((run_dir / "run_meta.json").read_text()) if (run_dir / "run_meta.json").exists() else {}
    start_url = meta.get("start_url") or (pages[0]["url"] if pages else "")
    start_host = (urlsplit(start_url).hostname or "").lower()
    redacted = meta.get("redacted", True)
    global REDACT_EXAMPLES
    REDACT_EXAMPLES = redacted
    curl_red = resolve_curl_redact(redacted, curl_secrets, curl_redact)

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
    flow = build_flow(run_dir, recs, curl_red, start_host)
    (run_dir / "flow.sh").write_text(render_flow_sh(flow, start_url))
    for st in flow:
        st.pop("_post_data", None)
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
            "flow_needs_human": api_map["flow_needs_human"], "flow_md": api_map["flow_md"]}


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
    try:
        html = (run_dir / doc["body_file"]).read_text(encoding="utf-8", errors="replace")
    except OSError:
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
        if s.get("curl"):
            L.append("\n```bash")
            if s.get("curl_env"):
                L.append("# exportar primero:")
                L.append(env_comment(s["curl_env"]))
            L.append(s["curl"])
            L.append("```")
        L.append("")
    return "\n".join(L)


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
    for s in flow:
        L.append(f"# --- Paso {s['step']}: {s['method']} {s['url']}")
        if s["is_captcha_asset"]:
            L.append(f"curl -sS -b \"$JAR\" -c \"$JAR\" {shlex.quote(s['url'])} -o \"$OUT/captcha_{s['step']}.png\"")
            L.append(f"echo 'Captcha guardado en '$OUT'/captcha_{s['step']}.png'")
            L.append(f"read -r -p 'Escribe el texto del captcha (paso {s['step']}): ' CAPTCHA")
            L.append("")
            continue
        c = (s.get("curl") or "").replace("curl ", 'curl -sS -b "$JAR" -c "$JAR" ', 1)
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
    L.append("")

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
    a = ap.parse_args()
    s = build(a.run_dir, a.map_documents, a.emit_curl, a.curl_secrets, a.curl_redact)
    print(json.dumps(s))


if __name__ == "__main__":
    main()
