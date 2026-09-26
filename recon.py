#!/usr/bin/env python3
"""wnm-recon: passive-first OSINT reconnaissance for a single domain.

Given ANY domain, it enumerates subdomains (crt.sh Certificate Transparency + a best-effort
read of an existing c99 subdomainfinder scan), resolves A/AAAA with dig, detects Cloudflare per
host against Cloudflare's published ranges, surfaces non-Cloudflare A records as candidate origin
IPs, and (optionally) verifies those candidates by ping + Host-header HTTP(S) probing and TLS-cert
inspection, comparing against the Cloudflare edge to judge whether the IP serves the real site
directly (bypassing Cloudflare).

Nothing is hardcoded to any specific domain. See --help for the authorization/ethics banner.
"""
from __future__ import annotations

import argparse
import html
import ipaddress
import json
import re
import shutil
import subprocess
import sys
import time
from datetime import date, datetime, timedelta
from pathlib import Path

TOOL_DIR = Path(__file__).resolve().parent
CACHE_DIR = TOOL_DIR / ".cache"
DEFAULT_UA = "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0"

BANNER = """\
================================ wnm-recon: authorized use only ================================
This tool performs OSINT + light active probing. Subdomain enumeration and DNS are passive, but
ICMP ping, HTTP(S) requests with a spoofed Host header, and TLS handshakes to candidate origin
IPs are ACTIVE traffic (not fully passive). Origin-bypass probing can be intrusive and may violate
a target's policy. Only run this against domains and hosts you are explicitly authorized to test.
It is read-only: no brute force, no login/auth attempts, no exploitation. Keep delays polite.
================================================================================================"""

# Fallback Cloudflare ranges (used only if the live lists can't be fetched/cached).
CF_V4_FALLBACK = [
    "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
    "141.101.64.0/18", "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20",
    "197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
    "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
]
CF_V6_FALLBACK = [
    "2400:cb00::/32", "2606:4700::/32", "2803:f800::/32", "2405:b500::/32",
    "2405:8100::/32", "2a06:98c0::/29", "2c0f:f248::/32",
]


def log(*a):
    print(f"[{datetime.now().strftime('%H:%M:%S')}]", *a, file=sys.stderr, flush=True)


def now_iso():
    return datetime.now().astimezone().isoformat(timespec="seconds")


def run(cmd, timeout=20):
    """Run a command, return (rc, stdout, stderr). Never raises on non-zero/timeout."""
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return p.returncode, p.stdout, p.stderr
    except subprocess.TimeoutExpired:
        return 124, "", "timeout"
    except FileNotFoundError:
        return 127, "", f"not found: {cmd[0]}"
    except Exception as e:  # noqa: BLE001
        return 1, "", str(e)


# ------------------------------------------------------------------ HTTP fetch (passive reads)

def http_get(url, timeout, ua, binary=False):
    """GET a URL. Returns (status:int|None, text_or_bytes|None). Tries httpx then urllib then curl."""
    headers = {"User-Agent": ua, "Accept": "*/*"}
    try:
        import httpx  # available in the tool venv
        with httpx.Client(follow_redirects=True, timeout=timeout, headers=headers, verify=True) as c:
            r = c.get(url)
            return r.status_code, (r.content if binary else r.text)
    except Exception:  # noqa: BLE001
        pass
    try:
        import urllib.request
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310
            data = resp.read()
            return resp.status, (data if binary else data.decode("utf-8", "replace"))
    except Exception:  # noqa: BLE001
        pass
    if shutil.which("curl"):
        args = ["curl", "-sSL", "-A", ua, "--max-time", str(int(timeout)), url]
        rc, out, _ = run(args, timeout=timeout + 5)
        if rc == 0:
            return 200, out
    return None, None


def http_get_browser(url, timeout, ua):
    """Fallback: load a URL in headless Chromium (Playwright) and return (status, html)."""
    try:
        from playwright.sync_api import sync_playwright
    except Exception as e:  # noqa: BLE001
        log(f"  browser fallback unavailable: {e}")
        return None, None
    try:
        with sync_playwright() as p:
            b = p.chromium.launch(headless=True)
            ctx = b.new_context(user_agent=ua)
            page = ctx.new_page()
            resp = page.goto(url, wait_until="networkidle", timeout=int(timeout * 1000))
            try:
                page.wait_for_timeout(1500)
            except Exception:  # noqa: BLE001
                pass
            content = page.content()
            status = resp.status if resp else None
            b.close()
            return status, content
    except Exception as e:  # noqa: BLE001
        log(f"  browser fallback failed: {e}")
        return None, None


# ------------------------------------------------------------------ Cloudflare ranges

def load_cf_ranges(timeout, ua, ttl_hours=24):
    CACHE_DIR.mkdir(exist_ok=True)
    nets_v4, nets_v6 = [], []
    for ver, url, cache, fallback in (
        (4, "https://www.cloudflare.com/ips-v4", CACHE_DIR / "cloudflare-ips-v4.txt", CF_V4_FALLBACK),
        (6, "https://www.cloudflare.com/ips-v6", CACHE_DIR / "cloudflare-ips-v6.txt", CF_V6_FALLBACK),
    ):
        text = None
        if cache.exists() and (time.time() - cache.stat().st_mtime) < ttl_hours * 3600:
            text = cache.read_text(encoding="utf-8", errors="replace")
        if not text:
            st, body = http_get(url, timeout, ua)
            if st and body and "/" in body:
                text = body
                try:
                    cache.write_text(text, encoding="utf-8")
                except Exception:  # noqa: BLE001
                    pass
            elif cache.exists():
                text = cache.read_text(encoding="utf-8", errors="replace")
        cidrs = []
        if text:
            cidrs = [ln.strip() for ln in text.splitlines() if ln.strip() and "/" in ln]
        if not cidrs:
            cidrs = fallback
            log(f"  cloudflare ips-v{ver}: using built-in fallback list")
        target = nets_v4 if ver == 4 else nets_v6
        for c in cidrs:
            try:
                target.append(ipaddress.ip_network(c, strict=False))
            except ValueError:
                pass
    return nets_v4, nets_v6


def ip_in_cf(ip_str, nets_v4, nets_v6):
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    nets = nets_v6 if ip.version == 6 else nets_v4
    return any(ip in n for n in nets)


# ------------------------------------------------------------------ subdomain enumeration

def crtsh_subdomains(domain, timeout, ua):
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    st, body = http_get(url, timeout, ua)
    subs = set()
    if not body:
        log("  crt.sh: no response")
        return subs, {"ok": False, "url": url}
    try:
        data = json.loads(body)
    except ValueError:
        # crt.sh sometimes returns NDJSON-ish or an HTML error
        try:
            data = [json.loads(ln) for ln in body.splitlines() if ln.strip().startswith("{")]
        except ValueError:
            log("  crt.sh: could not parse JSON")
            return subs, {"ok": False, "url": url}
    for row in data:
        nv = str(row.get("name_value", "")) + "\n" + str(row.get("common_name", ""))
        for name in nv.splitlines():
            name = name.strip().lower().lstrip("*.")
            if name and (name == domain or name.endswith("." + domain)):
                subs.add(name)
    log(f"  crt.sh: {len(subs)} unique names")
    return subs, {"ok": True, "url": url, "count": len(subs)}


C99_ROW_RE = re.compile(r"<tr[^>]*>(.*?)</tr>", re.S | re.I)
C99_CELL_RE = re.compile(r"<td[^>]*>(.*?)</td>", re.S | re.I)
TAG_RE = re.compile(r"<[^>]+>")


def _parse_c99_table(page_html, domain):
    """Return dict host -> ip (or 'none') parsed from a c99 scan results table."""
    out = {}
    for row in C99_ROW_RE.findall(page_html):
        cells = C99_CELL_RE.findall(row)
        if not cells:
            continue
        texts = [html.unescape(re.sub(r"\s+", " ", TAG_RE.sub(" ", c))).strip() for c in cells]
        host = ip = None
        for t in texts:
            tl = t.lower()
            if tl == domain or tl.endswith("." + domain):
                host = tl
            elif re.fullmatch(r"(\d{1,3}\.){3}\d{1,3}", t) or ":" in t and re.search(r"[0-9a-f]:[0-9a-f]", t.lower()):
                ip = t
            elif tl == "none":
                ip = ip or "none"
        if host:
            out[host] = ip or "none"
    return out


def c99_subdomains(domain, timeout, ua, delay, allow_browser=True):
    """Best-effort read of an EXISTING c99 subdomainfinder scan (does not trigger a new scan)."""
    base = "https://subdomainfinder.c99.nl"
    meta = {"ok": False, "scan_url": None}
    # 1) Ask for today's scan URL; even a non-existent date page links to the latest real scan.
    probe_url = f"{base}/scans/{date.today().isoformat()}/{domain}"
    st, page = http_get(probe_url, timeout, ua)
    if (not page or "c99" not in (page or "").lower()) and allow_browser:
        log("  c99: plain fetch weak/blocked, trying box browser (Playwright)")
        st, page = http_get_browser(probe_url, timeout, ua)
    if not page:
        log("  c99: unreachable")
        return {}, meta
    # If the probe page already contains a results table for this domain, use it.
    results = _parse_c99_table(page, domain)
    scan_url = probe_url if len(results) >= 1 else None
    if not scan_url:
        # find the newest linked existing scan for this domain
        links = re.findall(r"scans/(\d{4}-\d{2}-\d{2})/" + re.escape(domain), page)
        if links:
            newest = sorted(set(links))[-1]
            scan_url = f"{base}/scans/{newest}/{domain}"
            time.sleep(delay)
            st, page = http_get(scan_url, timeout, ua)
            if (not page or not _parse_c99_table(page, domain)) and allow_browser:
                st, page = http_get_browser(scan_url, timeout, ua)
            results = _parse_c99_table(page or "", domain)
    if results:
        meta = {"ok": True, "scan_url": scan_url, "count": len(results)}
        log(f"  c99: {len(results)} hosts from {scan_url}")
    else:
        log("  c99: no existing scan found for this domain")
    return results, meta


# ------------------------------------------------------------------ DNS

def dig_short(name, rrtype, timeout, resolver=None):
    if not shutil.which("dig"):
        return []
    args = ["dig", "+short", f"+time={max(1, int(timeout))}", "+tries=2", rrtype, name]
    if resolver:
        args.append(f"@{resolver}")
    rc, out, _ = run(args, timeout=timeout + 3)
    vals = []
    for ln in out.splitlines():
        ln = ln.strip().rstrip(".")
        if ln and not ln.startswith(";"):
            vals.append(ln)
    return vals


def resolve_host(host, timeout, resolver=None):
    a = [x for x in dig_short(host, "A", timeout, resolver) if re.fullmatch(r"(\d{1,3}\.){3}\d{1,3}", x)]
    aaaa = [x for x in dig_short(host, "AAAA", timeout, resolver) if ":" in x]
    cname = dig_short(host, "CNAME", timeout, resolver)
    return {"a": a, "aaaa": aaaa, "cname": cname}


# ------------------------------------------------------------------ verification

def ping_ip(ip, count, timeout):
    if not shutil.which("ping"):
        return {"ran": False, "alive": None, "detail": "ping not installed"}
    v6 = ":" in ip
    args = ["ping"] + (["-6"] if v6 else ["-4"]) + ["-c", str(count), "-W", str(max(1, int(timeout))), ip]
    rc, out, _ = run(args, timeout=count * (timeout + 1) + 5)
    m = re.search(r"(\d+) received", out)
    recv = int(m.group(1)) if m else 0
    rtt = None
    mr = re.search(r"= [\d.]+/([\d.]+)/", out)
    if mr:
        rtt = float(mr.group(1))
    return {"ran": True, "alive": recv > 0, "received": recv, "rtt_avg_ms": rtt}


def cert_info(ip, servername, timeout):
    if not shutil.which("openssl"):
        return {}
    port = "443"
    cmd = ["openssl", "s_client", "-connect", f"[{ip}]:{port}" if ":" in ip else f"{ip}:{port}",
           "-servername", servername]
    try:
        p = subprocess.run(cmd, input="", capture_output=True, text=True, timeout=timeout + 5)
        pem_in = p.stdout
    except Exception:  # noqa: BLE001
        return {}
    px = subprocess.run(["openssl", "x509", "-noout", "-subject", "-issuer", "-dates"],
                        input=pem_in, capture_output=True, text=True)
    info = {}
    for ln in px.stdout.splitlines():
        if ln.startswith("subject="):
            info["subject"] = ln[len("subject="):].strip()
            mcn = re.search(r"CN\s*=\s*([^,/]+)", ln)
            mo = re.search(r"O\s*=\s*([^,/]+)", ln)
            if mcn:
                info["cn"] = mcn.group(1).strip()
            if mo:
                info["o"] = mo.group(1).strip()
        elif ln.startswith("issuer="):
            info["issuer"] = ln[len("issuer="):].strip()
        elif ln.startswith("notAfter="):
            info["not_after"] = ln[len("notAfter="):].strip()
    return info


def curl_probe(ip, vhost, scheme, timeout, ua):
    """curl -k --resolve vhost:port:ip scheme://vhost/  -> dict of response facts."""
    if not shutil.which("curl"):
        return {"ok": False, "error": "curl not installed"}
    port = "443" if scheme == "https" else "80"
    hdr = subprocess.run(["mktemp"], capture_output=True, text=True).stdout.strip() or "/tmp/wnm_hdr"
    body = hdr + ".body"
    fmt = "%{http_code}|%{size_download}|%{time_total}|%{remote_ip}"
    args = ["curl", "-s", "-k", "-m", str(int(timeout)), "-A", ua,
            "-o", body, "-D", hdr,
            "--resolve", f"{vhost}:{port}:{ip}", f"{scheme}://{vhost}/",
            "-w", fmt]
    rc, out, err = run(args, timeout=timeout + 5)
    res = {"ok": rc == 0, "scheme": scheme, "vhost": vhost, "ip": ip}
    if rc != 0:
        res["error"] = err.strip() or f"curl rc={rc}"
        return res
    parts = out.split("|")
    if len(parts) == 4:
        res["status"] = int(parts[0]) if parts[0].isdigit() else parts[0]
        res["size"] = int(parts[1]) if parts[1].isdigit() else 0
        res["time_s"] = float(parts[2]) if parts[2] else None
    try:
        htext = Path(hdr).read_text(errors="replace")
    except Exception:  # noqa: BLE001
        htext = ""
    try:
        btext = Path(body).read_text(errors="replace")
    except Exception:  # noqa: BLE001
        btext = ""
    for ln in htext.splitlines():
        low = ln.lower()
        if low.startswith("server:"):
            res["server"] = ln.split(":", 1)[1].strip()
        elif low.startswith("location:"):
            res["location"] = ln.split(":", 1)[1].strip()
        elif low.startswith("cf-ray:"):
            res["cf_ray"] = ln.split(":", 1)[1].strip()
    mt = re.search(r"<title[^>]*>(.*?)</title>", btext, re.S | re.I)
    if mt:
        res["title"] = html.unescape(re.sub(r"\s+", " ", mt.group(1))).strip()[:200]
    for f in (hdr, body):
        try:
            Path(f).unlink()
        except Exception:  # noqa: BLE001
            pass
    return res


def norm_title(t):
    return re.sub(r"[^a-z0-9]+", " ", (t or "").lower()).strip()


# ------------------------------------------------------------------ main pipeline

def main(argv=None):
    ap = argparse.ArgumentParser(
        prog="wnm-recon",
        description="Passive-first OSINT recon + origin-IP discovery for a domain.",
        epilog=BANNER, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("domain", help="target apex domain, e.g. example.com")
    ap.add_argument("--no-c99", action="store_true", help="skip the c99 subdomainfinder source")
    ap.add_argument("--no-crtsh", action="store_true", help="skip crt.sh certificate transparency")
    ap.add_argument("--no-ping", action="store_true", help="skip ICMP ping of candidate origins")
    ap.add_argument("--no-verify", action="store_true", help="skip active HTTP(S)/TLS origin verification")
    ap.add_argument("--resolve-only", action="store_true",
                    help="DNS + Cloudflare classification only; no active probing (implies --no-ping --no-verify)")
    ap.add_argument("--no-browser", action="store_true", help="do not fall back to the box browser for c99")
    ap.add_argument("--timeout", type=float, default=20, help="per-request timeout seconds (default 20)")
    ap.add_argument("--delay", type=float, default=0.5, help="polite delay between network requests (default 0.5s)")
    ap.add_argument("--ping-count", type=int, default=3, help="ICMP echo count per IP (default 3)")
    ap.add_argument("--resolver", default=None, help="DNS resolver to use with dig (default: system)")
    ap.add_argument("--user-agent", default=DEFAULT_UA, help="User-Agent for HTTP requests")
    ap.add_argument("--out", default=None, help="output run directory (default runs/recon-<domain>-<ts>)")
    args = ap.parse_args(argv)

    domain = args.domain.strip().lower().strip(".")
    if not re.fullmatch(r"[a-z0-9.-]+\.[a-z]{2,}", domain):
        ap.error(f"invalid domain: {args.domain!r}")
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from wnm_common import guard_target
    guard_target(domain, "domain")
    if args.resolve_only:
        args.no_ping = True
        args.no_verify = True

    ua = args.user_agent
    timeout = args.timeout
    delay = max(0.0, args.delay)

    print(BANNER, file=sys.stderr)
    log(f"target: {domain}")

    ts = datetime.now().strftime("%Y%m%d-%H%M%S")
    out_dir = Path(args.out) if args.out else (TOOL_DIR / "runs" / f"recon-{domain}-{ts}")
    out_dir.mkdir(parents=True, exist_ok=True)
    log(f"run dir: {out_dir}")

    # 0) Cloudflare ranges
    log("loading Cloudflare IP ranges")
    cf_v4, cf_v6 = load_cf_ranges(timeout, ua)

    # 1) subdomain enumeration
    hosts = {domain}
    c99_map = {}
    crt_meta = {"ok": False}
    c99_meta = {"ok": False}
    if not args.no_crtsh:
        log("enumerating via crt.sh")
        subs, crt_meta = crtsh_subdomains(domain, timeout, ua)
        hosts |= subs
        time.sleep(delay)
    if not args.no_c99:
        log("enumerating via c99 subdomainfinder (best-effort, existing scans only)")
        c99_map, c99_meta = c99_subdomains(domain, timeout, ua, delay, allow_browser=not args.no_browser)
        hosts |= set(c99_map.keys())
        time.sleep(delay)
    hosts = sorted(hosts)
    log(f"total unique hosts: {len(hosts)}")

    # 2) + 3) resolve & classify
    ns = dig_short(domain, "NS", timeout, args.resolver)
    zone_on_cf = any("cloudflare" in n.lower() for n in ns)
    records = []
    direct_ips = {}  # ip -> set(hosts)
    for h in hosts:
        rec = resolve_host(h, timeout, args.resolver)
        all_a = rec["a"] + rec["aaaa"]
        cname_cf = any("cloudflare" in c.lower() for c in rec["cname"])
        cf_hit = any(ip_in_cf(ip, cf_v4, cf_v6) for ip in all_a)
        if not all_a and not rec["cname"]:
            label = "no-record"
        elif cf_hit or cname_cf:
            label = "cloudflare"
        else:
            label = "direct"
        if label == "direct":
            for ip in all_a:
                direct_ips.setdefault(ip, set()).add(h)
        records.append({
            "host": h, "a": rec["a"], "aaaa": rec["aaaa"], "cname": rec["cname"],
            "label": label, "c99_ip": c99_map.get(h),
        })

    # 4) candidate origins = all current non-Cloudflare A/AAAA records
    candidates = sorted(direct_ips.keys())
    log(f"candidate origin IPs (non-Cloudflare A/AAAA in DNS): {candidates or 'none'}")

    # baseline: what the Cloudflare edge / public DNS serves
    edge = {}
    if not args.no_verify:
        for vhost in (domain, f"www.{domain}"):
            st, body = http_get(f"https://{vhost}/", timeout, ua)
            title = None
            if body:
                mt = re.search(r"<title[^>]*>(.*?)</title>", body, re.S | re.I)
                if mt:
                    title = html.unescape(re.sub(r"\s+", " ", mt.group(1))).strip()[:200]
            edge[vhost] = {"status": st, "title": title, "size": len(body) if body else 0}
            time.sleep(delay)

    # 5) verify candidates
    verify = {}
    edge_titles = {norm_title(v.get("title")) for v in edge.values() if v.get("title")}
    for ip in candidates:
        entry = {"ip": ip, "hosts": sorted(direct_ips[ip]), "serves_site": False, "probes": []}
        if not args.no_ping:
            entry["ping"] = ping_ip(ip, args.ping_count, min(timeout, 3))
            time.sleep(delay)
        if not args.no_verify:
            entry["cert"] = cert_info(ip, f"www.{domain}", timeout)
            best = None
            for vhost in (domain, f"www.{domain}"):
                for scheme in ("https", "http"):
                    pr = curl_probe(ip, vhost, scheme, timeout, ua)
                    entry["probes"].append(pr)
                    real = (pr.get("status") == 200 and pr.get("title")
                            and (not edge_titles or norm_title(pr.get("title")) in edge_titles
                                 or any(domain.split(".")[0] in norm_title(pr.get("title")) for _ in [0]))
                            and "cloudflare" not in (pr.get("server", "").lower()))
                    if real:
                        entry["serves_site"] = True
                        if best is None or scheme == "https":
                            best = pr
                    time.sleep(delay)
            if best:
                entry["best_probe"] = best
        verify[ip] = entry

    # verified origins that serve the apex/www site (for attributing to CF-fronted hosts)
    verified_serving = sorted([ip for ip, e in verify.items() if e.get("serves_site")])

    # ---------------------------------------------------------------- assemble output
    result = {
        "target": domain, "generated": now_iso(), "run_dir": str(out_dir),
        "authoritative_ns": ns, "zone_on_cloudflare": zone_on_cf,
        "sources": {"crtsh": crt_meta, "c99": c99_meta},
        "cloudflare_ranges": {"v4": len(cf_v4), "v6": len(cf_v6)},
        "hosts": records, "candidate_origins": candidates,
        "verified_serving_origins": verified_serving,
        "edge_baseline": edge, "verification": verify,
        "flags": {k: getattr(args, k) for k in
                  ("no_c99", "no_crtsh", "no_ping", "no_verify", "resolve_only", "no_browser")},
    }
    (out_dir / "recon.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
    (out_dir / "subdomains.txt").write_text("\n".join(hosts) + "\n", encoding="utf-8")

    write_report(out_dir / "report.md", result)
    print_summary(result)
    print(str(out_dir))  # last line = run dir (matches wnm-map convention)
    return 0


def _fmt_ips(rec):
    ips = rec["a"] + rec["aaaa"]
    return ",".join(ips) if ips else ("(cname)" if rec["cname"] else "-")


def print_summary(result):
    domain = result["target"]
    verify = result["verification"]
    verified = result["verified_serving_origins"]
    no_verify = result["flags"].get("no_verify")
    rows = []
    for rec in result["hosts"]:
        label = rec["label"]
        ips = _fmt_ips(rec)
        if label == "direct":
            own = [ip for ip in rec["a"] + rec["aaaa"]]
            cand = ",".join(own)
            if no_verify:
                serves = "?"
            else:
                serves = "-"
                for ip in own:
                    if verify.get(ip, {}).get("serves_site"):
                        serves = "yes"
                        break
                    if ip in verify:
                        serves = "no"
            cf = "no"
        elif label == "cloudflare":
            cf = "yes"
            cand = ",".join(verified) if verified else ("(not tested)" if no_verify else "(none found)")
            serves = "?" if no_verify else ("yes*" if verified else "-")
        else:
            cf = "-"
            cand = "-"
            serves = "-"
        rows.append((rec["host"], ips, cf, cand, serves))

    w0 = max(len("SUBDOMAIN"), max((len(r[0]) for r in rows), default=0))
    w1 = max(len("IP(S)"), min(40, max((len(r[1]) for r in rows), default=0)))
    w3 = max(len("CANDIDATE ORIGIN"), min(34, max((len(r[3]) for r in rows), default=0)))
    print()
    print(f"=== wnm-recon summary: {domain} ===")
    ns = result["authoritative_ns"]
    print(f"zone NS: {', '.join(ns) if ns else '(none)'}"
          f"   zone-on-cloudflare: {result['zone_on_cloudflare']}")
    src = result["sources"]
    print(f"sources: crt.sh={'ok' if src['crtsh'].get('ok') else 'off/none'}"
          f"  c99={'ok' if src['c99'].get('ok') else 'off/none'}"
          f"  ({len(result['hosts'])} hosts)")
    hdr = f"{'SUBDOMAIN':<{w0}}  {'IP(S)':<{w1}}  {'CF?':<4}  {'CANDIDATE ORIGIN':<{w3}}  SERVES?"
    print(hdr)
    print("-" * len(hdr))
    for host, ips, cf, cand, serves in rows:
        ips_s = ips if len(ips) <= w1 else ips[: w1 - 1] + "\u2026"
        cand_s = cand if len(cand) <= w3 else cand[: w3 - 1] + "\u2026"
        print(f"{host:<{w0}}  {ips_s:<{w1}}  {cf:<4}  {cand_s:<{w3}}  {serves}")
    if verified:
        print(f"\nVERIFIED origin(s) serving the real site directly (bypassing Cloudflare): {', '.join(verified)}")
        for ip in verified:
            c = verify[ip].get("cert", {})
            bp = verify[ip].get("best_probe", {})
            print(f"  - {ip}: server={bp.get('server','?')} title={bp.get('title','?')!r} "
                  f"cert CN={c.get('cn','?')} O={c.get('o','?')}")
    elif result["candidate_origins"]:
        print(f"\nCandidate origin IPs (unverified as site): {', '.join(result['candidate_origins'])}")
    print("* 'yes*' means a sibling direct IP serves the site; that IP is the likely origin behind Cloudflare.")


def write_report(path, r):
    domain = r["target"]
    verify = r["verification"]
    verified = r["verified_serving_origins"]
    L = []
    L.append(f"# OSINT Passive Recon — {domain}\n")
    L.append("> " + BANNER.replace("\n", "\n> ") + "\n")
    L.append(f"**Target:** `{domain}`  ")
    L.append(f"**Generated:** {r['generated']}  ")
    L.append(f"**Run dir:** `{r['run_dir']}`\n")
    L.append("## Method & scope\n")
    L.append("Subdomain enumeration (crt.sh CT + best-effort read of an existing c99 subdomainfinder "
             "scan) and DNS are **passive**. ICMP ping, HTTP(S) requests with a spoofed `Host` header, "
             "and TLS handshakes to candidate origin IPs are **active** traffic. Read-only: no brute "
             "force, no auth attempts, no exploitation.\n")

    L.append("## Infrastructure\n")
    ns = r["authoritative_ns"]
    L.append(f"- **Authoritative NS:** {', '.join(ns) if ns else '(none found)'}")
    L.append(f"- **Zone hosted on Cloudflare:** {r['zone_on_cloudflare']}")
    src = r["sources"]
    L.append(f"- **crt.sh:** {'ok, ' + str(src['crtsh'].get('count','?')) + ' names' if src['crtsh'].get('ok') else 'not used / no data'}")
    c99s = src["c99"]
    L.append(f"- **c99:** {'ok — ' + str(c99s.get('scan_url')) if c99s.get('ok') else 'not used / no existing scan'}")
    L.append(f"- **Cloudflare ranges loaded:** {r['cloudflare_ranges']['v4']} v4, {r['cloudflare_ranges']['v6']} v6\n")

    L.append("## Subdomains, DNS & Cloudflare status\n")
    L.append("| Host | A / AAAA | CNAME | Cloudflare? | c99 IP |")
    L.append("|------|----------|-------|-------------|--------|")
    for rec in r["hosts"]:
        ips = ", ".join(rec["a"] + rec["aaaa"]) or "-"
        cn = ", ".join(rec["cname"]) or "-"
        lab = {"cloudflare": "**yes**", "direct": "no (direct)", "no-record": "n/a (no record)"}[rec["label"]]
        L.append(f"| {rec['host']} | {ips} | {cn} | {lab} | {rec.get('c99_ip') or '-'} |")
    L.append("")

    L.append("## Candidate origin IPs\n")
    if r["candidate_origins"]:
        L.append("Current **non-Cloudflare** A/AAAA records (origin is often already exposed on sibling "
                 "subdomains sharing a netblock):\n")
        for ip in r["candidate_origins"]:
            hs = ", ".join(verify.get(ip, {}).get("hosts", []))
            L.append(f"- `{ip}` (from: {hs})")
        L.append("")
    else:
        L.append("No non-Cloudflare A/AAAA records were found in current DNS.\n")
    L.append("> Paid/historical sources (SecurityTrails, ViewDNS full history, Censys/Shodan) can reveal "
             "**former** origin IPs from before Cloudflare was added, but they need API keys/paid plans and "
             "are not queried here. crt.sh certificate history and current sibling A-records are the free signals used.\n")

    if not r["flags"]["no_verify"]:
        L.append("## Origin verification (active)\n")
        eb = r["edge_baseline"]
        L.append("Cloudflare edge baseline:")
        for vhost, e in eb.items():
            L.append(f"- `https://{vhost}/` → status {e.get('status')}, title {e.get('title')!r}, {e.get('size')} bytes")
        L.append("")
        if verify:
            L.append("| Candidate IP | Ping | Best HTTP(S) probe | Serves real site? | TLS cert |")
            L.append("|--------------|------|--------------------|-------------------|----------|")
            for ip, e in verify.items():
                png = e.get("ping", {})
                pstr = "-" if not png.get("ran") else ("alive" if png.get("alive") else "no reply")
                if png.get("rtt_avg_ms"):
                    pstr += f" ~{png['rtt_avg_ms']:.0f}ms"
                bp = e.get("best_probe") or (e["probes"][0] if e.get("probes") else {})
                pd = (f"{bp.get('scheme','?')} {bp.get('status','?')} "
                      f"srv={bp.get('server','-')} sz={bp.get('size','-')} title={bp.get('title','-')!r}") if bp else "-"
                c = e.get("cert", {})
                cs = f"CN={c.get('cn','?')} O={c.get('o','?')}" if c else "-"
                L.append(f"| {ip} | {pstr} | {pd} | {'**YES**' if e.get('serves_site') else 'no'} | {cs} |")
            L.append("")

    L.append("## Summary\n")
    if verified:
        L.append(f"**Origin found.** These IPs serve the real site directly, bypassing Cloudflare: "
                 f"`{', '.join(verified)}`.\n")
        L.append("Direct-to-origin access enables un-throttled crawling/mapping (Cloudflare WAF, rate-limits, "
                 "bot-management and caching do not apply) with e.g.:\n")
        L.append("```bash")
        L.append(f"curl -k --resolve {domain}:443:{verified[0]} https://{domain}/")
        L.append(f"curl -k --resolve www.{domain}:443:{verified[0]} https://www.{domain}/")
        L.append("```")
    elif r["candidate_origins"]:
        L.append(f"Candidate origin IP(s) found in DNS (`{', '.join(r['candidate_origins'])}`) but none were "
                 "verified to serve the apex/www site during this run (may serve other vhosts, be firewalled, "
                 "or filter probes).\n")
    else:
        L.append("No origin-bypass candidates found: no non-Cloudflare records in current DNS.\n")
    L.append("**Caveats:** origin IPs may be firewalled to Cloudflare-only at any time; direct-IP content can "
             "be stale vs. the edge; ICMP may be filtered (no reply ≠ down); and using an origin bypass to "
             "crawl/scan/test is only appropriate under explicit authorization.\n")

    L.append("## Files\n")
    L.append("- `report.md` — this report\n- `recon.json` — machine-readable results\n"
             "- `subdomains.txt` — unique host list\n")
    path.write_text("\n".join(L), encoding="utf-8")


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\ninterrupted", file=sys.stderr)
        sys.exit(130)
