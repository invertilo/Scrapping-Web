#!/usr/bin/env python3
"""Replay / extract: turn an endpoint from api_map.json into actual scraped data.

Examples
  replay.py RUN/api_map.json --list
  replay.py RUN/api_map.json 1 --paginate page --start 1 --max-pages 5
  replay.py RUN/api_map.json "GET quotes.toscrape.com/api/quotes" --paginate page --max-pages 0   # until has_next=false
  replay.py RUN/api_map.json 3 --paginate offset --step 20 --records-path data.items --format csv
  replay.py RUN/api_map.json 2 --paginate body:variables.page         # JSON body field (GraphQL/POST)
  replay.py RUN/api_map.json 2 --cursor-param after --cursor-path data.search.pageInfo.endCursor
  replay.py RUN/api_map.json 4 --next-url-path next                   # follow 'next' URLs in the response
"""
from __future__ import annotations

import argparse
import csv
import json
import random
import re
import sys
import time
from datetime import datetime
from pathlib import Path
from urllib.parse import parse_qsl, urlencode, urljoin, urlsplit, urlunsplit

sys.path.insert(0, str(Path(__file__).resolve().parent))
import httpx  # noqa: E402

from wnm_curl import build_curl, env_comment  # noqa: E402
from wnm_common import (  # noqa: E402
    HOP_HEADERS, REDACTED, get_path, load_cookies_file, loads_lenient, parse_header_args, set_path, slugify,
)

OFFSET_LIKE = re.compile(r"^(offset|start|skip|from|startindex|start_index)$", re.I)
LIMIT_LIKE = re.compile(r"^(limit|per_?page|page_?size|size|count|take|rows|first)$", re.I)
STOP_KEYS = ("has_next", "hasNext", "has_more", "hasMore", "hasNextPage", "more")
# Hard cap on any single rate-limit wait so a bogus Retry-After can never hang the run.
RL_WAIT_CAP = 300.0


def log(*a):
    print(*a, file=sys.stderr, flush=True)


def load_map(p: str) -> tuple[dict, Path]:
    path = Path(p)
    if path.is_dir():
        path = path / "api_map.json"
    return json.loads(path.read_text()), path.parent


def pick_endpoint(m: dict, sel: str) -> dict:
    eps = m["endpoints"]
    if sel.isdigit():
        for e in eps:
            if e.get("index") == int(sel):
                return e
        raise SystemExit(f"no endpoint with index {sel}")
    for e in eps:
        if e["key"] == sel:
            return e
    hits = [e for e in eps if sel.lower() in e["key"].lower()]
    if len(hits) == 1:
        return hits[0]
    if not hits:
        raise SystemExit(f"no endpoint matches {sel!r}; use --list")
    raise SystemExit("ambiguous endpoint, matches:\n  " + "\n  ".join(f"{e['index']}: {e['key']}" for e in hits))


def set_query(url: str, updates: dict, drop=()) -> str:
    p = urlsplit(url)
    q = [(k, v) for k, v in parse_qsl(p.query, keep_blank_values=True) if k not in updates and k not in drop]
    q += [(k, str(v)) for k, v in updates.items()]
    return urlunsplit((p.scheme, p.netloc, p.path, urlencode(q), p.fragment))


def get_query(url: str, name: str):
    for k, v in parse_qsl(urlsplit(url).query, keep_blank_values=True):
        if k == name:
            return v
    return None


def parse_value(v: str):
    try:
        return json.loads(v)
    except ValueError:
        return v


def find_key_path(obj, names, prefix="", depth=0):
    if isinstance(obj, dict) and depth <= 4:
        for k, v in obj.items():
            if k in names and isinstance(v, (bool, type(None))):
                return prefix + k
        for k, v in obj.items():
            if isinstance(v, dict):
                r = find_key_path(v, names, prefix + k + ".", depth + 1)
                if r:
                    return r
    return None


def flatten(obj, prefix="", out=None):
    if out is None:
        out = {}
    if isinstance(obj, dict):
        for k, v in obj.items():
            flatten(v, f"{prefix}{k}.", out)
    elif isinstance(obj, list):
        if all(not isinstance(x, (dict, list)) for x in obj):
            out[prefix[:-1]] = "|".join("" if x is None else str(x) for x in obj)
        else:
            out[prefix[:-1]] = json.dumps(obj, ensure_ascii=False)
    else:
        out[prefix[:-1] if prefix else "value"] = obj
    return out


def build_client(args, ep) -> httpx.Client:
    cookies = httpx.Cookies()
    for f in (args.storage_state, args.cookies):
        if f:
            for c in load_cookies_file(f):
                dom = c.get("domain") or urlsplit(c.get("url", "")).hostname or ""
                cookies.set(c["name"], c["value"], domain=dom, path=c.get("path", "/"))
    return httpx.Client(cookies=cookies, follow_redirects=True, timeout=args.timeout, verify=not args.insecure,
                        http2=False)


def build_headers(ep, args) -> dict:
    tmpl = (ep.get("replay") or {}).get("headers") or {}
    h = {}
    dropped = []
    for k, v in tmpl.items():
        kl = k.lower()
        if kl.startswith(":") or kl in HOP_HEADERS:
            continue
        if v == REDACTED or (isinstance(v, str) and REDACTED in v):
            dropped.append(k)
            continue
        if kl == "cookie" and (args.cookies or args.storage_state):
            continue  # let the cookie jar handle it
        h[k] = v
    if args.cookies or args.storage_state:
        dropped = [d for d in dropped if d.lower() != "cookie"]
    if dropped:
        log(f"note: captured headers {dropped} were redacted at capture time; supply them with --header/--cookies/"
            f"--storage-state, or re-run mapper.py with --keep-secrets")
    if args.no_captured_headers:
        h = {k: v for k, v in h.items() if k.lower() in ("user-agent", "accept", "content-type")}
    if args.user_agent:
        h["user-agent"] = args.user_agent
    h.update(parse_header_args(args.header))
    h.setdefault("accept-encoding", "gzip, deflate")
    return h


def _to_float(v):
    try:
        return float(str(v).strip())
    except (TypeError, ValueError):
        return None


def parse_retry_after(value):
    """Parse a Retry-After header value: delta-seconds or an HTTP-date. Returns seconds or None."""
    if not value:
        return None
    f = _to_float(value)
    if f is not None:
        return max(0.0, f)
    try:  # HTTP-date form
        from email.utils import parsedate_to_datetime
        dt = parsedate_to_datetime(value.strip())
        if dt is not None:
            now = datetime.now(dt.tzinfo) if dt.tzinfo else datetime.now()
            return max(0.0, (dt - now).total_seconds())
    except Exception:  # noqa: BLE001
        pass
    return None


def rate_limit_delay(resp):
    """Inspect a response for rate-limit signals. Returns (seconds:float|None, reason:str).

    Honours Retry-After first, then X-RateLimit-Remaining==0 + X-RateLimit-Reset (epoch or delta).
    None means no wait is indicated. Never raises."""
    try:
        h = resp.headers
    except Exception:  # noqa: BLE001
        return None, ""
    ra = parse_retry_after(h.get("retry-after"))
    if ra is not None:
        return ra, "retry-after"
    remaining = _to_float(h.get("x-ratelimit-remaining") or h.get("x-rate-limit-remaining")
                          or h.get("ratelimit-remaining"))
    reset = h.get("x-ratelimit-reset") or h.get("x-rate-limit-reset") or h.get("ratelimit-reset")
    if remaining is not None and remaining <= 0 and reset is not None:
        rf = _to_float(reset)
        if rf is not None:
            wait = (rf - time.time()) if rf > 1e6 else rf  # large value => epoch seconds
            return max(0.0, wait), "x-ratelimit-reset"
    return None, ""


def request_with_retry(client, method, url, headers, content, args, stats=None):
    """Send a request with resilient retries.

    - Transport errors and 5xx use exponential backoff with jitter (base=--backoff, cap=--max-backoff).
    - Unless --ignore-rate-limit, 429 and Retry-After / X-RateLimit-* headers are honoured: we wait the
      indicated time before retrying, and slow down proactively when the quota is exhausted.
    Records how many rate-limit waits happened in `stats`. --retries still bounds the retry count and
    everything degrades cleanly when the new flags are absent."""
    if stats is None:
        stats = {}
    base = getattr(args, "backoff", 0.5)
    base = 0.5 if base is None else max(0.0, base)
    max_backoff = getattr(args, "max_backoff", 60.0) or 60.0
    respect_rl = getattr(args, "respect_rate_limit", True)

    def _backoff(attempt):
        return min(max_backoff, base * (2 ** attempt)) + random.uniform(0, base)

    def _record_rl(wait, reason):
        stats["rate_limit_waits"] = stats.get("rate_limit_waits", 0) + 1
        stats["rate_limit_wait_s"] = stats.get("rate_limit_wait_s", 0.0) + wait
        log(f"  rate-limit ({reason}): esperando {wait:.1f}s antes de continuar")

    r = None
    for attempt in range(args.retries + 1):
        try:
            r = client.request(method, url, headers=headers, content=content)
        except httpx.HTTPError as e:
            if attempt >= args.retries:
                raise
            wait = _backoff(attempt)
            stats["retries"] = stats.get("retries", 0) + 1
            log(f"  transport error {e!r}; retry {attempt + 1}/{args.retries} in {wait:.1f}s")
            time.sleep(wait)
            continue
        rl_wait, rl_reason = rate_limit_delay(r) if respect_rl else (None, "")
        if r.status_code == 429 and attempt < args.retries:
            wait = rl_wait if (rl_wait is not None) else _backoff(attempt + 1)
            wait = min(wait, RL_WAIT_CAP) + random.uniform(0, base)
            _record_rl(wait, rl_reason or "429")
            time.sleep(wait)
            continue
        if r.status_code in (500, 502, 503, 504) and attempt < args.retries:
            if rl_wait is not None and rl_reason == "retry-after":
                wait = min(rl_wait, RL_WAIT_CAP) + random.uniform(0, base)
                _record_rl(wait, rl_reason)
            else:
                wait = _backoff(attempt + 1)
                stats["retries"] = stats.get("retries", 0) + 1
                log(f"  HTTP {r.status_code}; retry {attempt + 1}/{args.retries} in {wait:.1f}s")
            time.sleep(wait)
            continue
        # success / non-retryable: if the quota is exhausted, pause to be polite before the next page
        if respect_rl and r.status_code < 400 and rl_wait is not None and rl_wait > 0:
            wait = min(rl_wait, RL_WAIT_CAP) + random.uniform(0, base)
            _record_rl(wait, (rl_reason or "cuota agotada") + ", bajando el ritmo")
            time.sleep(wait)
        return r
    return r


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("api_map", help="path to api_map.json (or the run directory)")
    ap.add_argument("endpoint", nargs="?", help="endpoint index (#), exact key, or unique substring")
    ap.add_argument("--list", action="store_true", help="list endpoints and exit")
    ap.add_argument("--all", action="store_true", help="with --list, include tracking endpoints")
    g = ap.add_argument_group("request")
    g.add_argument("--url", help="override the template URL")
    g.add_argument("--method", help="override HTTP method")
    g.add_argument("--param", action="append", metavar="K=V", help="set/override a query param (repeatable)")
    g.add_argument("--drop-param", action="append", default=[], metavar="K", help="remove a query param")
    g.add_argument("--data", help="override request body (raw string / JSON)")
    g.add_argument("--data-file", help="read request body from file")
    g.add_argument("--body-set", action="append", metavar="PATH=VALUE", help="set a JSON body field, e.g. variables.first=50")
    g.add_argument("--header", action="append", metavar="'Name: value'", help="add/override header (repeatable)")
    g.add_argument("--no-captured-headers", action="store_true", help="send only minimal headers instead of the captured set")
    g.add_argument("--cookies", metavar="FILE", help="cookies JSON / cookies.txt")
    g.add_argument("--storage-state", metavar="FILE", help="Playwright storage_state JSON")
    g.add_argument("--user-agent")
    g.add_argument("--timeout", type=float, default=30)
    g.add_argument("--retries", type=int, default=3)
    g.add_argument("--backoff", type=float, default=0.5,
                   help="base for exponential backoff with jitter on network errors / 5xx (seconds)")
    g.add_argument("--max-backoff", type=float, default=60.0, help="cap for a single backoff wait (seconds)")
    g.add_argument("--respect-rate-limit", dest="respect_rate_limit", action="store_true", default=True,
                   help="honour 429 / Retry-After / X-RateLimit-* by waiting (default on)")
    g.add_argument("--ignore-rate-limit", dest="respect_rate_limit", action="store_false",
                   help="do not wait on rate-limit signals")
    g.add_argument("--insecure", action="store_true", help="skip TLS verification")
    g = ap.add_argument_group("pagination")
    g.add_argument("--paginate", metavar="PARAM", help="query param to iterate (or body:<json.path>)")
    g.add_argument("--start", type=int, help="first value (default 1, or 0 for offset-like params)")
    g.add_argument("--step", type=int, help="increment (default 1; offset-like: page size)")
    g.add_argument("--end", type=int, help="last value (inclusive)")
    g.add_argument("--values", help="with --paginate: explicit comma-separated values to iterate (e.g. 2010,2012 or books,travel)")
    g.add_argument("--max-pages", type=int, default=5, help="max requests (0 = until a stop condition, hard cap 10000)")
    g.add_argument("--cursor-param", help="cursor pagination: param (or body:<path>) to receive the next cursor")
    g.add_argument("--cursor-path", help="dot path in response holding the next cursor")
    g.add_argument("--next-url-path", help="dot path in response holding the next page URL")
    g.add_argument("--stop-key", help="dot path of a boolean in the response; stop when false (auto: has_next/hasMore/...)")
    g.add_argument("--no-stop-on-empty", action="store_true", help="keep going when a page returns 0 records")
    g.add_argument("--delay", type=float, default=1.0, help="seconds between requests")
    g = ap.add_argument_group("output")
    g.add_argument("--records-path", help="dot path to the record list (default: auto from api_map; '' = root)")
    g.add_argument("--out", help="output path without extension (default: <run>/extracts/<endpoint>-<ts>)")
    g.add_argument("--format", choices=["csv", "json", "both"], default="both")
    g.add_argument("--save-raw", action="store_true", help="also save each raw response")
    g.add_argument("--dry-run", action="store_true", help="print the first request and exit")
    g.add_argument("--curl", action="store_true",
                   help="print the first request (with your --param/--paginate/--header overrides) as a curl command and exit")
    g.add_argument("--curl-secrets", action="store_true", help="with --curl: print real secret values instead of $VARIABLES")
    args = ap.parse_args(argv)

    m, run_dir = load_map(args.api_map)
    if args.list or not args.endpoint:
        for e in m["endpoints"]:
            if e.get("likely_tracking") and not args.all:
                continue
            rec = e.get("response_records") or {}
            print(f"{e['index']:>3}  {e['key']}\n     flags={','.join(e['flags']) or '-'} calls={e['calls']} "
                  f"records={rec.get('path', '-')}({rec.get('length', 0)}) paginate={e.get('suggested_paginate') or '-'}")
        return 0

    ep = pick_endpoint(m, args.endpoint)
    rp = ep.get("replay") or {}
    url = args.url or rp.get("url") or ep["example_urls"][0]
    try:
        from wnm_common import guard_target
        guard_target(url, "url")
    except Exception as _e:
        raise
    from wnm_common import guard_target
    guard_target(url, "url")
    method = (args.method or rp.get("method") or ep["method"] or "GET").upper()
    body = None
    if args.data_file:
        body = Path(args.data_file).read_text()
    elif args.data is not None:
        body = args.data
    elif rp.get("post_data") and method not in ("GET", "HEAD"):
        body = rp["post_data"]
        if REDACTED in body:
            log("note: captured request body contains redacted fields; override with --data/--body-set")
    body_json = None
    if body and body.strip()[:1] in "[{":
        try:
            body_json = json.loads(body)
        except ValueError:
            pass
    for bs in args.body_set or []:
        k, v = bs.split("=", 1)
        if body_json is None:
            body_json = {}
        set_path(body_json, k, parse_value(v))
    if args.param:
        url = set_query(url, dict(p.split("=", 1) for p in args.param), args.drop_param)
    elif args.drop_param:
        url = set_query(url, {}, args.drop_param)

    headers = build_headers(ep, args)
    if body_json is not None:
        headers = {k: v for k, v in headers.items() if k.lower() != "content-type"}
        headers["content-type"] = next((v for k, v in (rp.get("headers") or {}).items() if k.lower() == "content-type"),
                                       "application/json")

    records_path = args.records_path
    if records_path is None:
        records_path = (ep.get("response_records") or {}).get("path")

    pag = args.paginate
    pag_in_body = bool(pag and pag.startswith("body:"))
    pag_name = pag[5:] if pag_in_body else pag
    offset_like = bool(pag_name and OFFSET_LIKE.match(pag_name.split(".")[-1]))
    value = args.start if args.start is not None else (0 if offset_like else 1)
    step = args.step
    if step is None and offset_like:
        lim = next((get_query(url, k) for k in (ep.get("query_params") or {}) if LIMIT_LIKE.match(k)), None)
        step = int(lim) if lim and lim.isdigit() else None  # else: derived from first page size
    if step is None and not offset_like:
        step = 1

    values = [parse_value(v.strip()) for v in args.values.split(",")] if args.values else None
    if values:
        if not pag:
            raise SystemExit("--values requires --paginate PARAM")
        value = values[0]
    max_pages = args.max_pages if args.max_pages > 0 else 10000
    if values and args.max_pages == 5:
        max_pages = len(values)
    stop_key = args.stop_key
    cursor = None
    all_records, pages_done = [], 0
    raw_dir = None
    ts = datetime.now().strftime("%Y%m%d-%H%M%S")
    out_base = Path(args.out) if args.out else run_dir / "extracts" / f"{slugify(ep['key'], 70)}-{ts}"
    if not args.out:
        n = 1
        while any(Path(str(out_base) + ext).exists() for ext in (".csv", ".json")):
            n += 1
            out_base = run_dir / "extracts" / f"{slugify(ep['key'], 70)}-{ts}-{n}"
    out_base.parent.mkdir(parents=True, exist_ok=True)
    if args.save_raw:
        raw_dir = Path(str(out_base) + "_raw")
        raw_dir.mkdir(parents=True, exist_ok=True)

    client = build_client(args, ep)
    cur_url = url
    stop_reason = "max-pages reached"
    net_stats = {"rate_limit_waits": 0, "rate_limit_wait_s": 0.0, "retries": 0}
    try:
        while pages_done < max_pages:
            req_url, req_body = cur_url, body_json
            if pag and not args.next_url_path:
                if pag_in_body:
                    req_body = json.loads(json.dumps(body_json or {}))
                    set_path(req_body, pag_name, value)
                else:
                    req_url = set_query(cur_url, {pag_name: value})
            if args.cursor_param and cursor is not None:
                cp = args.cursor_param
                if cp.startswith("body:"):
                    req_body = json.loads(json.dumps(req_body or {}))
                    set_path(req_body, cp[5:], cursor)
                else:
                    req_url = set_query(req_url, {cp: cursor})
            content = json.dumps(req_body) if req_body is not None else (body.encode() if body else None)
            if args.curl:
                h = dict(headers)
                host = urlsplit(req_url).hostname or ""
                jar = [c for c in client.cookies.jar if host == c.domain.lstrip(".") or host.endswith("." + c.domain.lstrip("."))]
                if jar:
                    h["cookie"] = "; ".join(f"{c.name}={c.value}" for c in jar)
                c = build_curl(method, req_url, h, content if isinstance(content, str) else (content or b"").decode() or None,
                               redact=not args.curl_secrets)
                if c["env"]:
                    print(env_comment(c["env"]))
                print(c["multiline"])
                return 0
            if args.dry_run:
                print(json.dumps({"method": method, "url": req_url, "headers": headers,
                                  "body": content if isinstance(content, str) else (content or b"").decode()}, indent=2))
                return 0
            r = request_with_retry(client, method, req_url, headers, content, args, net_stats)
            pages_done += 1
            data = None
            try:
                data = loads_lenient(r.text)
            except ValueError:
                pass
            if raw_dir:
                (raw_dir / f"{pages_done:04d}.{'json' if data is not None else 'txt'}").write_text(r.text)
            if r.status_code >= 400:
                log(f"[{pages_done}] {r.status_code} {req_url} -> stopping (body: {r.text[:200]!r})")
                stop_reason = f"HTTP {r.status_code}"
                break
            if data is None:
                log(f"[{pages_done}] {r.status_code} {req_url}: response is not JSON ({r.headers.get('content-type')}); "
                    f"saved as a single text record")
                all_records.append({"url": req_url, "status": r.status_code, "text": r.text})
                stop_reason = "non-JSON response"
                break
            recs = get_path(data, records_path) if records_path is not None else data
            if isinstance(recs, dict):
                recs = [recs]
            elif not isinstance(recs, list):
                recs = [] if recs is None else [{"value": recs}]
            all_records.extend(recs)
            log(f"[{pages_done}] {r.status_code} {req_url} -> {len(recs)} records (total {len(all_records)})")
            if not recs and not args.no_stop_on_empty and not values:
                stop_reason = "empty page"
                break
            if stop_key is None and not args.next_url_path:
                stop_key = find_key_path(data, STOP_KEYS) or ""
                if stop_key:
                    log(f"  (auto stop-key: {stop_key})")
            if stop_key and not values and get_path(data, stop_key) in (False, None, 0, "false"):
                stop_reason = f"{stop_key} is false"
                break
            if args.next_url_path:
                nxt = get_path(data, args.next_url_path)
                if not nxt:
                    stop_reason = "no next URL"
                    break
                cur_url = urljoin(req_url, str(nxt))
            elif args.cursor_param:
                cursor = get_path(data, args.cursor_path) if args.cursor_path else None
                if cursor in (None, "", False):
                    stop_reason = "no next cursor"
                    break
            elif values:
                if pages_done >= len(values):
                    stop_reason = "all --values done"
                    break
                value = values[pages_done]
            elif pag:
                if step is None:
                    step = len(recs) or 1
                    log(f"  (offset step = page size {step})")
                value += step
                if args.end is not None and value > args.end:
                    stop_reason = "end reached"
                    break
            else:
                stop_reason = "single request (no pagination)"
                break
            if pages_done < max_pages:
                time.sleep(args.delay)
    finally:
        client.close()

    outputs = []
    if args.format in ("json", "both"):
        p = Path(str(out_base) + ".json")
        p.write_text(json.dumps(all_records, indent=2, ensure_ascii=False))
        outputs.append(p)
    if args.format in ("csv", "both"):
        p = Path(str(out_base) + ".csv")
        rows = [flatten(r) if isinstance(r, (dict, list)) else {"value": r} for r in all_records]
        cols = []
        for row in rows:
            for k in row:
                if k not in cols:
                    cols.append(k)
        with open(p, "w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=cols or ["value"], extrasaction="ignore")
            w.writeheader()
            for row in rows:
                w.writerow(row)
        outputs.append(p)
    summary = {"endpoint": ep["key"], "requests": pages_done, "records": len(all_records), "stop_reason": stop_reason,
               "rate_limit_waits": net_stats.get("rate_limit_waits", 0),
               "rate_limit_wait_s": round(net_stats.get("rate_limit_wait_s", 0.0), 2),
               "retries": net_stats.get("retries", 0),
               "outputs": [str(p.resolve()) for p in outputs]}
    _rl = net_stats.get("rate_limit_waits", 0)
    log(f"done: {len(all_records)} records from {pages_done} requests ({stop_reason})"
        + (f"; {_rl} espera(s) por rate-limit (~{net_stats.get('rate_limit_wait_s', 0.0):.1f}s)" if _rl else ""))
    print(json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
