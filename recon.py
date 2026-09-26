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
import base64
import hashlib
import html
import ipaddress
import json
import os
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


def _san_matches(names, domain):
    """True if any SAN/CN entry equals `domain` or is a wildcard that covers it (one label)."""
    d = (domain or "").lower().rstrip(".")
    for n in names or []:
        n = str(n).lower().rstrip(".")
        if not n:
            continue
        if n == d:
            return True
        if n.startswith("*."):
            base = n[2:]
            if d == base or (d.endswith("." + base) and d.count(".") == base.count(".") + 1):
                return True
    return False


def tls_cert_inspect(host, servername, timeout, port=443, match_domain=None):
    """Open a TLS connection to host:port with SNI=servername and READ the presented certificate
    (stdlib ssl only, no new deps). Returns a dict: ok, cn, san (list), issuer, fingerprint_sha256,
    not_before, not_after, and san_match when match_domain is given. Never raises: timeouts,
    self-signed certs, refused SNI, handshake errors, etc. degrade to {'ok': False, 'error': ...}.
    This only reads the certificate the server presents; it does not bypass any control."""
    import socket
    import ssl
    import tempfile
    info = {"ok": False, "sni": servername, "port": port}
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE  # we only READ the cert (accept self-signed to inspect it)
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=servername) as ss:
                der = ss.getpeercert(binary_form=True)
        if not der:
            info["error"] = "sin certificado"
            return info
        info["fingerprint_sha256"] = hashlib.sha256(der).hexdigest()
        pem = ssl.DER_cert_to_PEM_cert(der)
        parsed = {}
        try:
            tf = tempfile.NamedTemporaryFile("w", suffix=".pem", delete=False)
            tf.write(pem)
            tf.close()
            try:
                parsed = ssl._ssl._test_decode_cert(tf.name)
            finally:
                try:
                    Path(tf.name).unlink()
                except Exception:  # noqa: BLE001
                    pass
        except Exception:  # noqa: BLE001
            parsed = {}
        san = [v for k, v in (parsed.get("subjectAltName") or []) if str(k).lower() == "dns"]
        cn = None
        for rdn in parsed.get("subject", ()) or ():
            for k, v in rdn:
                if k in ("commonName", "CN"):
                    cn = v
        issuer_parts = []
        for rdn in parsed.get("issuer", ()) or ():
            for k, v in rdn:
                if k in ("organizationName", "commonName", "O", "CN"):
                    issuer_parts.append(v)
        info.update({
            "ok": True, "cn": cn, "san": san,
            "issuer": ", ".join(dict.fromkeys(issuer_parts)) or None,
            "not_before": parsed.get("notBefore"), "not_after": parsed.get("notAfter"),
        })
        if match_domain:
            info["san_match"] = _san_matches(list(san) + ([cn] if cn else []), match_domain)
        return info
    except Exception as e:  # noqa: BLE001
        info["error"] = str(e)
        return info


def curl_probe(ip, vhost, scheme, timeout, ua, port=None):
    """curl -k --resolve vhost:port:ip scheme://vhost/  -> dict of response facts.

    port defaults to 443 (https) / 80 (http); pass 8443/8080 to probe alternate ports.
    Records a body hash and a few distinctive headers for cross-host matching.
    """
    if not shutil.which("curl"):
        return {"ok": False, "error": "curl not installed"}
    if port is None:
        port = 443 if scheme == "https" else 80
    port = int(port)
    hdr = subprocess.run(["mktemp"], capture_output=True, text=True).stdout.strip() or "/tmp/wnm_hdr"
    body = hdr + ".body"
    fmt = "%{http_code}|%{size_download}|%{time_total}|%{remote_ip}"
    args = ["curl", "-s", "-k", "-m", str(int(timeout)), "-A", ua,
            "-o", body, "-D", hdr,
            "--resolve", f"{vhost}:{port}:{ip}", f"{scheme}://{vhost}:{port}/",
            "-w", fmt]
    rc, out, err = run(args, timeout=timeout + 5)
    res = {"ok": rc == 0, "scheme": scheme, "vhost": vhost, "ip": ip, "port": port}
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
    distinctive = {}
    for ln in htext.splitlines():
        low = ln.lower()
        if low.startswith("server:"):
            res["server"] = ln.split(":", 1)[1].strip()
        elif low.startswith("location:"):
            res["location"] = ln.split(":", 1)[1].strip()
        elif low.startswith("cf-ray:"):
            res["cf_ray"] = ln.split(":", 1)[1].strip()
        for hname in ("content-type", "x-powered-by", "x-generator", "via", "x-aspnet-version"):
            if low.startswith(hname + ":"):
                distinctive[hname] = ln.split(":", 1)[1].strip()
    if distinctive:
        res["headers"] = distinctive
    mt = re.search(r"<title[^>]*>(.*?)</title>", btext, re.S | re.I)
    if mt:
        res["title"] = html.unescape(re.sub(r"\s+", " ", mt.group(1))).strip()[:200]
    if btext:
        res["body_hash"] = body_hash(btext)
    for f in (hdr, body):
        try:
            Path(f).unlink()
        except Exception:  # noqa: BLE001
            pass
    return res


def norm_title(t):
    return re.sub(r"[^a-z0-9]+", " ", (t or "").lower()).strip()


def body_hash(text):
    """Stable hash of an HTML body (whitespace-normalized) for cross-host comparison."""
    if not text:
        return None
    norm = re.sub(r"\s+", " ", text).strip()
    return hashlib.sha1(norm.encode("utf-8", "replace")).hexdigest()


def api_get_json(url, timeout, ua, headers=None, auth=None):
    """GET a JSON API with optional extra headers and (user, pass) basic auth.
    Returns (status:int|None, obj|None). Tries httpx then urllib then curl. Never raises."""
    h = {"User-Agent": ua, "Accept": "application/json"}
    if headers:
        h.update(headers)
    try:
        import httpx
        with httpx.Client(follow_redirects=True, timeout=timeout, headers=h, verify=True) as c:
            r = c.get(url, auth=auth)
            try:
                return r.status_code, r.json()
            except Exception:  # noqa: BLE001
                return r.status_code, None
    except Exception:  # noqa: BLE001
        pass
    try:
        import urllib.request
        req = urllib.request.Request(url, headers=h)
        if auth:
            tok = base64.b64encode(f"{auth[0]}:{auth[1]}".encode()).decode()
            req.add_header("Authorization", "Basic " + tok)
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310
            data = resp.read().decode("utf-8", "replace")
            return resp.status, json.loads(data)
    except Exception:  # noqa: BLE001
        pass
    if shutil.which("curl"):
        args = ["curl", "-sSL", "--max-time", str(int(timeout))]
        for k, v in h.items():
            args += ["-H", f"{k}: {v}"]
        if auth:
            args += ["-u", f"{auth[0]}:{auth[1]}"]
        args.append(url)
        rc, out, _ = run(args, timeout=timeout + 5)
        if rc == 0 and out:
            try:
                return 200, json.loads(out)
            except ValueError:
                return 200, None
    return None, None


def favicon_hash(domain, timeout, ua):
    """Shodan-style favicon hash: mmh3.hash(base64.encodebytes(favicon_bytes)).
    Fetches https://<domain>/favicon.ico from the edge. Returns (hash:int|None, meta:dict)."""
    meta = {"ok": False, "url": f"https://{domain}/favicon.ico"}
    try:
        import mmh3
    except Exception as e:  # noqa: BLE001
        meta["error"] = f"mmh3 no instalado ({e})"
        return None, meta
    st, data = http_get(meta["url"], timeout, ua, binary=True)
    if not data:
        meta["error"] = "favicon no accesible"
        return None, meta
    if isinstance(data, str):
        data = data.encode("utf-8", "replace")
    try:
        h = mmh3.hash(base64.encodebytes(data))
    except Exception as e:  # noqa: BLE001
        meta["error"] = str(e)
        return None, meta
    meta.update({"ok": True, "hash": h, "size": len(data), "status": st})
    return h, meta


def _ip_set_from(vals):
    out = set()
    for v in vals:
        s = str(v).strip()
        if re.fullmatch(r"(\d{1,3}\.){3}\d{1,3}", s):
            out.add(s)
    return out


def securitytrails_history(domain, api_key, timeout, ua):
    """Historical A records via SecurityTrails. Returns (ips:set, meta:dict). Key optional."""
    meta = {"source": "securitytrails", "ok": False}
    if not api_key:
        meta["note"] = "no configurado: exporta SECURITYTRAILS_API_KEY"
        return set(), meta
    url = f"https://api.securitytrails.com/v1/history/{domain}/dns/a"
    st, obj = api_get_json(url, timeout, ua, headers={"APIKEY": api_key})
    vals = []
    if isinstance(obj, dict):
        for rec in obj.get("records", []) or []:
            for v in rec.get("values", []) or []:
                vals.append(v.get("ip") if isinstance(v, dict) else v)
    ips = _ip_set_from([v for v in vals if v])
    meta.update({"ok": st == 200, "status": st, "count": len(ips)})
    if st and st != 200:
        meta["note"] = f"HTTP {st} (¿clave inválida o límite excedido?)"
    return ips, meta


def shodan_domain(domain, api_key, timeout, ua):
    """Passive DNS via Shodan dns/domain. Returns (ips:set, meta:dict). Key optional."""
    meta = {"source": "shodan:dns", "ok": False}
    if not api_key:
        meta["note"] = "no configurado: exporta SHODAN_API_KEY"
        return set(), meta
    url = f"https://api.shodan.io/dns/domain/{domain}?key={api_key}"
    st, obj = api_get_json(url, timeout, ua)
    vals = []
    if isinstance(obj, dict):
        for rec in obj.get("data", []) or []:
            if rec.get("type") == "A" and rec.get("value"):
                vals.append(rec["value"])
    ips = _ip_set_from(vals)
    meta.update({"ok": st == 200, "status": st, "count": len(ips)})
    if st and st != 200:
        meta["note"] = f"HTTP {st}"
    return ips, meta


def shodan_host(ip, api_key, timeout, ua):
    """Enrich a candidate IP via Shodan /shodan/host/<ip>. Returns meta dict (best-effort)."""
    meta = {"source": "shodan:host", "ip": ip, "ok": False}
    if not api_key:
        meta["note"] = "no configurado: exporta SHODAN_API_KEY"
        return meta
    st, obj = api_get_json(f"https://api.shodan.io/shodan/host/{ip}?key={api_key}", timeout, ua)
    if isinstance(obj, dict):
        meta.update({"ok": st == 200, "status": st,
                     "ports": obj.get("ports"), "org": obj.get("org"),
                     "hostnames": obj.get("hostnames")})
    else:
        meta["status"] = st
    return meta


def shodan_favicon_search(fav_hash, api_key, timeout, ua):
    """Find servers serving the same favicon (candidate origins). Returns (ips:set, meta:dict)."""
    meta = {"source": "favicon:shodan", "ok": False, "hash": fav_hash}
    if not api_key:
        meta["note"] = "no configurado: exporta SHODAN_API_KEY"
        return set(), meta
    if fav_hash is None:
        meta["note"] = "sin hash de favicon"
        return set(), meta
    url = f"https://api.shodan.io/shodan/host/search?query=http.favicon.hash:{fav_hash}&key={api_key}"
    st, obj = api_get_json(url, timeout, ua)
    vals = []
    if isinstance(obj, dict):
        for m in obj.get("matches", []) or []:
            if m.get("ip_str"):
                vals.append(m["ip_str"])
    ips = _ip_set_from(vals)
    meta.update({"ok": st == 200, "status": st, "count": len(ips)})
    if st and st != 200:
        meta["note"] = f"HTTP {st}"
    return ips, meta


def censys_hosts(domain, api_id, api_secret, timeout, ua):
    """Search Censys hosts by domain. Returns (ips:set, meta:dict). Credentials optional."""
    meta = {"source": "censys", "ok": False}
    if not (api_id and api_secret):
        meta["note"] = "no configurado: exporta CENSYS_API_ID y CENSYS_API_SECRET"
        return set(), meta
    from urllib.parse import quote
    url = f"https://search.censys.io/api/v2/hosts/search?q={quote(domain)}&per_page=50"
    st, obj = api_get_json(url, timeout, ua, auth=(api_id, api_secret))
    vals = []
    if isinstance(obj, dict):
        hits = (obj.get("result", {}) or {}).get("hits", []) or []
        for h in hits:
            if h.get("ip"):
                vals.append(h["ip"])
    ips = _ip_set_from(vals)
    meta.update({"ok": st == 200, "status": st, "count": len(ips)})
    if st and st != 200:
        meta["note"] = f"HTTP {st}"
    return ips, meta


def _collect_ips_from_json(obj, keys):
    """Recursively collect IPv4 strings found under any of `keys` in a nested JSON structure."""
    out = set()
    kset = {k.lower() for k in keys}

    def walk(o):
        if isinstance(o, dict):
            for k, v in o.items():
                if str(k).lower() in kset:
                    if isinstance(v, str):
                        out.add(v)
                    elif isinstance(v, list):
                        for x in v:
                            (out.add(x) if isinstance(x, str) else walk(x))
                    else:
                        walk(v)
                else:
                    walk(v)
        elif isinstance(o, list):
            for x in o:
                walk(x)

    walk(obj)
    return out


def virustotal_domain(domain, api_key, timeout, ua):
    """VirusTotal passive DNS: historical resolutions (IPs) + subdomains. Returns (ips:set, meta).
    Key optional; without it the source is skipped with a Spanish 'no configurado' note."""
    meta = {"source": "virustotal", "ok": False}
    if not api_key:
        meta["note"] = "no configurado: exporta VIRUSTOTAL_API_KEY (o usa --virustotal-key)"
        return set(), meta
    ips, subs = set(), set()
    st1, obj = api_get_json(
        f"https://www.virustotal.com/api/v3/domains/{domain}/resolutions?limit=40",
        timeout, ua, headers={"x-apikey": api_key})
    if isinstance(obj, dict):
        for rec in obj.get("data", []) or []:
            attr = rec.get("attributes", {}) if isinstance(rec, dict) else {}
            if attr.get("ip_address"):
                ips.add(attr["ip_address"])
    st2, obj2 = api_get_json(
        f"https://www.virustotal.com/api/v3/domains/{domain}/subdomains?limit=40",
        timeout, ua, headers={"x-apikey": api_key})
    if isinstance(obj2, dict):
        for rec in obj2.get("data", []) or []:
            sid = rec.get("id") if isinstance(rec, dict) else None
            if sid:
                subs.add(str(sid).lower())
    ips = _ip_set_from(ips)
    st = st1 or st2
    meta.update({"ok": (st1 == 200 or st2 == 200), "status": st, "count": len(ips),
                 "subdomains": sorted(subs)[:50], "subdomain_count": len(subs)})
    if st and st not in (200, None) and not ips:
        meta["note"] = f"HTTP {st} (¿clave inválida o límite excedido?)"
    return ips, meta


def urlscan_domain(domain, api_key, timeout, ua):
    """urlscan.io search: IPs/ASN observed for the domain. The search endpoint is public, so it is
    queried even without a key (reduced quota); a key (API-Key header) raises the limit.
    Returns (ips:set, meta)."""
    meta = {"source": "urlscan", "ok": False}
    headers = {}
    if api_key:
        headers["API-Key"] = api_key
    else:
        meta["note"] = "sin clave: búsqueda pública de urlscan (cuota reducida). Exporta URLSCAN_API_KEY para más."
    from urllib.parse import quote
    url = f"https://urlscan.io/api/v1/search/?q=domain:{quote(domain)}&size=100"
    st, obj = api_get_json(url, timeout, ua, headers=headers or None)
    ips, asns = set(), set()
    if isinstance(obj, dict):
        for rec in obj.get("results", []) or []:
            page = rec.get("page", {}) if isinstance(rec, dict) else {}
            if page.get("ip"):
                ips.add(page["ip"])
            if page.get("asn"):
                asns.add(str(page["asn"]))
    ips = _ip_set_from(ips)
    meta.update({"ok": st == 200, "status": st, "count": len(ips), "asns": sorted(asns)[:20]})
    if st and st != 200 and api_key:
        meta["note"] = f"HTTP {st}"
    return ips, meta


def netlas_domain(domain, api_key, timeout, ua):
    """Netlas.io: hosts / certificate data associated with the domain. Returns (ips:set, meta).
    Key optional; without it the source is skipped with a Spanish 'no configurado' note."""
    meta = {"source": "netlas", "ok": False}
    if not api_key:
        meta["note"] = "no configurado: exporta NETLAS_API_KEY (o usa --netlas-key)"
        return set(), meta
    from urllib.parse import quote
    url = (f"https://app.netlas.io/api/domains/?q={quote('domain:' + domain)}"
           f"&source_type=include&start=0")
    st, obj = api_get_json(url, timeout, ua, headers={"X-API-Key": api_key})
    ips = set()
    if isinstance(obj, dict):
        items = obj.get("items") or obj.get("data") or obj
        ips |= _collect_ips_from_json(items, ("a", "ip", "ip_address", "addr", "address"))
    ips = _ip_set_from(ips)
    meta.update({"ok": st == 200, "status": st, "count": len(ips)})
    if st and st != 200:
        meta["note"] = f"HTTP {st}"
    return ips, meta


COMMON_ORIGIN_SUBS = ("mail", "smtp", "ftp", "cpanel", "webmail", "direct", "origin", "server")


def _mx_host(entry):
    parts = entry.split()
    return parts[-1].rstrip(".").lower() if parts else ""


def extra_dns_records(domain, timeout, resolver=None):
    """Passive infra DNS: MX, TXT/SPF, _dmarc, and common origin-leaking subdomains.
    Resolves the discovered hosts so callers can classify them vs. Cloudflare."""
    out = {"mx": [], "txt": [], "spf": [], "dmarc": [], "common": {}, "hosts": {}}
    out["mx"] = dig_short(domain, "MX", timeout, resolver)
    txt = dig_short(domain, "TXT", timeout, resolver)
    out["txt"] = txt
    out["spf"] = [t for t in txt if "v=spf1" in t.lower()]
    out["dmarc"] = dig_short(f"_dmarc.{domain}", "TXT", timeout, resolver)
    for m in out["mx"]:
        host = _mx_host(m)
        if host and re.fullmatch(r"[a-z0-9.-]+\.[a-z]{2,}", host):
            out["hosts"][host] = resolve_host(host, timeout, resolver)
    for sub in COMMON_ORIGIN_SUBS:
        host = f"{sub}.{domain}"
        rec = resolve_host(host, timeout, resolver)
        if rec["a"] or rec["aaaa"] or rec["cname"]:
            out["common"][host] = rec
            out["hosts"][host] = rec
    return out


def probe_serves(pr, edge_titles, edge_hashes, domain):
    """Decide whether a curl_probe result looks like the real site (title OR body-hash match)."""
    if pr.get("status") != 200:
        return False
    if "cloudflare" in (pr.get("server", "") or "").lower():
        return False
    bh = pr.get("body_hash")
    if bh and edge_hashes and bh in edge_hashes:
        return True
    t = norm_title(pr.get("title"))
    if t:
        if edge_titles and t in edge_titles:
            return True
        first = domain.split(".")[0]
        if first and first in t:
            return True
    return False


def scan_range(origin_ip, domain, edge_titles, edge_hashes, timeout, ua,
               prefix=24, max_ips=256, delay=0.3, exclude=None):
    """Scan the /prefix around a verified origin (IPv4) for sibling origins serving the same site.
    Opt-in, bounded, polite. Returns a list of {ip, probe} for matches."""
    results = []
    try:
        net = ipaddress.ip_network(f"{origin_ip}/{prefix}", strict=False)
    except ValueError:
        return results
    if net.version != 4:
        return results
    exclude = set(exclude or [])
    count = 0
    for ip in net.hosts():
        if count >= max_ips:
            break
        ips = str(ip)
        if ips == origin_ip or ips in exclude:
            continue
        count += 1
        pr = curl_probe(ips, domain, "https", timeout, ua)
        if probe_serves(pr, edge_titles, edge_hashes, domain):
            results.append({"ip": ips, "probe": pr})
        time.sleep(delay)
    return results


def fetch_edge_full(url, timeout, ua):
    """Fetch a URL returning (status, headers:dict, body:str, cookies:dict). Best-effort, never raises."""
    status, headers_out, body_out, cookies_out = None, {}, "", {}
    try:
        import httpx
        with httpx.Client(follow_redirects=True, timeout=timeout,
                          headers={"User-Agent": ua, "Accept": "*/*"}, verify=True) as c:
            r = c.get(url)
            status = r.status_code
            headers_out = {k.lower(): v for k, v in r.headers.items()}
            body_out = r.text
            try:
                cookies_out = {k: v for k, v in r.cookies.items()}
            except Exception:  # noqa: BLE001
                cookies_out = {}
            return status, headers_out, body_out, cookies_out
    except Exception:  # noqa: BLE001
        pass
    if shutil.which("curl"):
        body_f = subprocess.run(["mktemp"], capture_output=True, text=True).stdout.strip() or "/tmp/wnm_edge"
        hdr_f = body_f + ".hdr"
        rc, out, _ = run(["curl", "-sSL", "-A", ua, "--max-time", str(int(timeout)),
                          "-o", body_f, "-D", hdr_f, "-w", "%{http_code}", url], timeout=timeout + 5)
        try:
            htext = Path(hdr_f).read_text(errors="replace")
        except Exception:  # noqa: BLE001
            htext = ""
        try:
            body_out = Path(body_f).read_text(errors="replace")
        except Exception:  # noqa: BLE001
            body_out = ""
        for ln in htext.splitlines():
            if ":" in ln and not ln.lower().startswith("http/"):
                k, v = ln.split(":", 1)
                kl = k.strip().lower()
                if kl == "set-cookie":
                    mck = re.match(r"\s*([^=;]+)=([^;]*)", v)
                    if mck:
                        cookies_out[mck.group(1).strip()] = mck.group(2).strip()
                else:
                    headers_out[kl] = v.strip()
        status = int(out) if out.strip().isdigit() else status
        for f in (hdr_f, body_f):
            try:
                Path(f).unlink()
            except Exception:  # noqa: BLE001
                pass
    return status, headers_out, body_out, cookies_out


def _render_anti_bot(ab):
    """Render whatever detect_anti_bot returned (dict/list/str) into one Spanish line."""
    if ab in (None, {}, [], ""):
        return "No se detectó protección anti-bot conocida en la respuesta del edge."
    if isinstance(ab, dict):
        if ab.get("error"):
            return f"detección anti-bot no disponible: {ab['error']}"
        det = ab.get("detected") or ab.get("vendors") or ab.get("providers")
        if det:
            return "Detectado: " + ", ".join(str(x) for x in det)
        trues = [k for k, v in ab.items() if v is True]
        if trues:
            return "Detectado: " + ", ".join(trues)
        return "Resultado anti-bot: " + json.dumps(ab, ensure_ascii=False, default=str)
    if isinstance(ab, (list, tuple, set)):
        items = []
        for x in ab:
            if isinstance(x, dict):
                name = x.get("vendor") or x.get("name") or x.get("provider") or json.dumps(x, ensure_ascii=False, default=str)
                if x.get("active") is True:
                    name = f"{name} (desafío activo)"
                items.append(str(name))
            else:
                items.append(str(x))
        return ("Detectado: " + ", ".join(items)) if items else "No se detectó protección anti-bot conocida en la respuesta del edge."
    return f"Detectado: {ab}"


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
    ap.add_argument("--securitytrails-key", default=None,
                    help="SecurityTrails API key (overrides $SECURITYTRAILS_API_KEY)")
    ap.add_argument("--shodan-key", default=None, help="Shodan API key (overrides $SHODAN_API_KEY)")
    ap.add_argument("--censys-id", default=None, help="Censys API ID (overrides $CENSYS_API_ID)")
    ap.add_argument("--censys-secret", default=None, help="Censys API secret (overrides $CENSYS_API_SECRET)")
    ap.add_argument("--virustotal-key", default=None,
                    help="VirusTotal API key (overrides $VIRUSTOTAL_API_KEY)")
    ap.add_argument("--urlscan-key", default=None,
                    help="urlscan.io API key (overrides $URLSCAN_API_KEY; búsqueda pública si falta)")
    ap.add_argument("--netlas-key", default=None,
                    help="Netlas API key (overrides $NETLAS_API_KEY)")
    ap.add_argument("--scan-range", action="store_true",
                    help="scan the /24 (see --range-prefix) around a verified origin for siblings (opt-in, slow)")
    ap.add_argument("--range-prefix", type=int, default=24, help="CIDR prefix length for --scan-range (default 24)")
    ap.add_argument("--range-max", type=int, default=256, help="max IPs to probe during --scan-range (default 256)")
    ap.add_argument("--json", action="store_true", help="dump recon.json content to stdout at the end")
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

    # 4) candidate origins = current non-Cloudflare A/AAAA records + optional enrichment sources
    cand_sources = {}  # ip -> set(source labels)

    def _add_cand(ip, source):
        if ip:
            cand_sources.setdefault(ip, set()).add(source)

    for ip in direct_ips:
        _add_cand(ip, "dns:direct")
    current_candidates = sorted(direct_ips.keys())
    log(f"candidate origin IPs (non-Cloudflare A/AAAA in DNS): {current_candidates or 'none'}")

    # 4a) API keys: CLI flag overrides env var (each source is optional / skipped without a key)
    st_key = args.securitytrails_key or os.environ.get("SECURITYTRAILS_API_KEY")
    shodan_key = args.shodan_key or os.environ.get("SHODAN_API_KEY")
    censys_id = args.censys_id or os.environ.get("CENSYS_API_ID")
    censys_secret = args.censys_secret or os.environ.get("CENSYS_API_SECRET")
    vt_key = args.virustotal_key or os.environ.get("VIRUSTOTAL_API_KEY")
    urlscan_key = args.urlscan_key or os.environ.get("URLSCAN_API_KEY")
    netlas_key = args.netlas_key or os.environ.get("NETLAS_API_KEY")

    # 4b) passive infra DNS (MX / TXT / SPF / DMARC + common origin-leaking subdomains)
    log("querying infra DNS records (MX/TXT/SPF/DMARC + common subdomains)")
    try:
        dns_infra = extra_dns_records(domain, timeout, args.resolver)
    except Exception as e:  # noqa: BLE001
        log(f"  infra DNS query failed: {e}")
        dns_infra = {"mx": [], "txt": [], "spf": [], "dmarc": [], "common": {}, "hosts": {}}
    mx_hosts = {_mx_host(m) for m in dns_infra.get("mx", []) if _mx_host(m)}
    for host, rec in dns_infra.get("hosts", {}).items():
        rec["_cf"] = any(ip_in_cf(ip, cf_v4, cf_v6) for ip in rec.get("a", []) + rec.get("aaaa", []))
        label = "dns:mx" if host in mx_hosts else "dns:common"
        for ip in rec.get("a", []) + rec.get("aaaa", []):
            if not ip_in_cf(ip, cf_v4, cf_v6):
                _add_cand(ip, label)

    # 4c) historical / passive-DNS sources (only used if their API key env/flag is set)
    hist_meta = {}
    for name, fn, fn_args in (
        ("securitytrails", securitytrails_history, (domain, st_key, timeout, ua)),
        ("shodan_dns", shodan_domain, (domain, shodan_key, timeout, ua)),
        ("censys", censys_hosts, (domain, censys_id, censys_secret, timeout, ua)),
    ):
        try:
            ips, meta = fn(*fn_args)
        except Exception as e:  # noqa: BLE001
            ips, meta = set(), {"source": name, "ok": False, "error": str(e)}
        hist_meta[name] = meta
        for ip in ips:
            _add_cand(ip, f"historical:{meta.get('source', name)}")
        if ips:
            log(f"  {name}: {len(ips)} historical IP(s)")
        time.sleep(delay)

    # 4c-bis) extra passive sources (VirusTotal / urlscan / Netlas). Each degrades to a
    # "no configurado" note when its key is missing; urlscan works publicly without a key.
    extra_meta = {}
    extra_subdomains = set()
    log("consultando fuentes pasivas extra (VirusTotal / urlscan / Netlas)")
    for name, fn, fn_args in (
        ("virustotal", virustotal_domain, (domain, vt_key, timeout, ua)),
        ("urlscan", urlscan_domain, (domain, urlscan_key, timeout, ua)),
        ("netlas", netlas_domain, (domain, netlas_key, timeout, ua)),
    ):
        try:
            ips, meta = fn(*fn_args)
        except Exception as e:  # noqa: BLE001
            ips, meta = set(), {"source": name, "ok": False, "error": str(e)}
        extra_meta[name] = meta
        for ip in ips:
            if not ip_in_cf(ip, cf_v4, cf_v6):
                _add_cand(ip, f"passive:{meta.get('source', name)}")
        for sd in meta.get("subdomains", []) or []:
            sd = str(sd).lower().strip().lstrip("*.")
            if sd == domain or sd.endswith("." + domain):
                extra_subdomains.add(sd)
        if ips:
            log(f"  {name}: {len(ips)} IP(s) candidata(s) (no-Cloudflare)")
        time.sleep(delay)
    # merge any new subdomains VirusTotal surfaced (they still get resolved/classified below is
    # already done, so record them and resolve+classify the new ones here defensively)
    new_subs = sorted(sd for sd in extra_subdomains if not any(rec["host"] == sd for rec in records))
    for sd in new_subs:
        try:
            rec = resolve_host(sd, timeout, args.resolver)
        except Exception:  # noqa: BLE001
            continue
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
                direct_ips.setdefault(ip, set()).add(sd)
                _add_cand(ip, "passive:virustotal")
        records.append({"host": sd, "a": rec["a"], "aaaa": rec["aaaa"], "cname": rec["cname"],
                        "label": label, "c99_ip": None})

    # 4d) favicon hash + Shodan favicon correlation (find origins serving the same favicon)
    fav_hash, fav_meta = favicon_hash(domain, timeout, ua)
    fav_search_meta = {"source": "favicon:shodan", "ok": False}
    if not shodan_key:
        fav_search_meta["note"] = "no configurado: exporta SHODAN_API_KEY"
    if fav_hash is not None and shodan_key:
        try:
            fav_ips, fav_search_meta = shodan_favicon_search(fav_hash, shodan_key, timeout, ua)
        except Exception as e:  # noqa: BLE001
            fav_ips, fav_search_meta = set(), {"source": "favicon:shodan", "ok": False, "error": str(e)}
        for ip in fav_ips:
            _add_cand(ip, "favicon:shodan")
        if fav_ips:
            log(f"  favicon:shodan: {len(fav_ips)} IP(s) with matching favicon")
        time.sleep(delay)

    candidates = sorted(cand_sources.keys())
    if candidates != current_candidates:
        log(f"candidate origin IPs (all sources): {candidates or 'none'}")

    # baseline: what the Cloudflare edge / public DNS serves (title + body hash)
    edge = {}
    edge_hashes = set()
    if not args.no_verify:
        for vhost in (domain, f"www.{domain}"):
            st, body = http_get(f"https://{vhost}/", timeout, ua)
            title = None
            bh = None
            if body:
                mt = re.search(r"<title[^>]*>(.*?)</title>", body, re.S | re.I)
                if mt:
                    title = html.unescape(re.sub(r"\s+", " ", mt.group(1))).strip()[:200]
                bh = body_hash(body)
                if bh:
                    edge_hashes.add(bh)
            edge[vhost] = {"status": st, "title": title, "size": len(body) if body else 0, "body_hash": bh}
            time.sleep(delay)

    # anti-bot detection on the edge response (optional shared helper from wnm_common)
    anti_bot = None
    try:
        from wnm_common import detect_anti_bot as _detect_anti_bot
    except Exception:  # noqa: BLE001
        _detect_anti_bot = None
    if _detect_anti_bot and not args.no_verify:
        try:
            _est, _eh, _eb, _ec = fetch_edge_full(f"https://{domain}/", timeout, ua)
            anti_bot = _detect_anti_bot(_eh, _eb, _ec)
        except Exception as e:  # noqa: BLE001
            anti_bot = {"error": str(e)}

    # 5) verify candidates (ping + Host-spoofed HTTP(S) + TLS cert; body-hash & title matching)
    verify = {}
    edge_titles = {norm_title(v.get("title")) for v in edge.values() if v.get("title")}
    # baseline TLS cert served by the edge/domain (stdlib ssl), for fingerprint/SAN comparison
    edge_tls = {}
    edge_fps = set()
    if not args.no_verify:
        for vhost in (domain, f"www.{domain}"):
            try:
                ci = tls_cert_inspect(vhost, vhost, min(timeout, 10), match_domain=domain)
            except Exception as e:  # noqa: BLE001
                ci = {"ok": False, "error": str(e)}
            edge_tls[vhost] = ci
            if ci.get("fingerprint_sha256"):
                edge_fps.add(ci["fingerprint_sha256"])
            time.sleep(delay)
    for ip in candidates:
        srcs = sorted(cand_sources.get(ip, []))
        hosts = sorted(direct_ips.get(ip, []))
        if not hosts:
            for host, rec in dns_infra.get("hosts", {}).items():
                if ip in (rec.get("a", []) + rec.get("aaaa", [])):
                    hosts.append(host)
        entry = {"ip": ip, "hosts": sorted(set(hosts)), "sources": srcs, "serves_site": False, "probes": []}
        if not args.no_ping:
            entry["ping"] = ping_ip(ip, args.ping_count, min(timeout, 3))
            time.sleep(delay)
        if not args.no_verify:
            entry["cert"] = cert_info(ip, f"www.{domain}", timeout)
            # stdlib TLS inspection of the cert this IP presents with SNI = target domain
            try:
                tls = tls_cert_inspect(ip, domain, min(timeout, 10), match_domain=domain)
            except Exception as e:  # noqa: BLE001
                tls = {"ok": False, "error": str(e)}
            entry["tls"] = tls
            entry["san_match"] = bool(tls.get("san_match"))
            entry["fp_match"] = bool(tls.get("fingerprint_sha256") and tls["fingerprint_sha256"] in edge_fps)
            if entry["san_match"] or entry["fp_match"]:
                # strong evidence the IP directly serves the same site -> promote to served & verdict
                entry["serves_site"] = True
                _add_cand(ip, "cert-match")
            best = None
            served_by = None
            for vhost in (domain, f"www.{domain}"):
                for scheme in ("https", "http"):
                    pr = curl_probe(ip, vhost, scheme, timeout, ua)
                    entry["probes"].append(pr)
                    if probe_serves(pr, edge_titles, edge_hashes, domain):
                        entry["serves_site"] = True
                        if best is None or scheme == "https":
                            best = pr
                            served_by = f"{scheme}/{pr.get('port')}"
                    time.sleep(delay)
            # alternate ports 8080/8443 if the standard ports did not serve the site
            if not entry["serves_site"]:
                for scheme, port in (("https", 8443), ("http", 8080)):
                    pr = curl_probe(ip, domain, scheme, timeout, ua, port=port)
                    entry["probes"].append(pr)
                    if probe_serves(pr, edge_titles, edge_hashes, domain):
                        entry["serves_site"] = True
                        best = pr
                        served_by = f"{scheme}/{port}"
                        time.sleep(delay)
                        break
                    time.sleep(delay)
            if best:
                entry["best_probe"] = best
                entry["served_by"] = served_by
                entry["body_match"] = bool(best.get("body_hash") and best["body_hash"] in edge_hashes)
        verify[ip] = entry

    # verified origins that serve the apex/www site (for attributing to CF-fronted hosts)
    verified_serving = sorted([ip for ip, e in verify.items() if e.get("serves_site")])

    # 5b) optional /24 range scan around a verified origin for sibling origins
    range_scan = {"ran": False}
    if getattr(args, "scan_range", False) and verified_serving and not args.no_verify:
        base_ip = next((ip for ip in verified_serving if ":" not in ip), None)
        range_scan = {"ran": True, "prefix": args.range_prefix, "max": args.range_max,
                      "base_ip": base_ip, "siblings": []}
        if base_ip:
            log(f"scanning /{args.range_prefix} around {base_ip} (max {args.range_max} IPs)")
            try:
                sibs = scan_range(base_ip, domain, edge_titles, edge_hashes, timeout, ua,
                                  prefix=args.range_prefix, max_ips=args.range_max,
                                  delay=max(delay, 0.2), exclude=verified_serving)
            except Exception as e:  # noqa: BLE001
                sibs = []
                range_scan["error"] = str(e)
            range_scan["siblings"] = sibs
            for s in sibs:
                _add_cand(s["ip"], "range-scan")
                verify.setdefault(s["ip"], {"ip": s["ip"], "hosts": [], "sources": ["range-scan"],
                                            "serves_site": True, "probes": [s["probe"]],
                                            "best_probe": s["probe"]})
            candidates = sorted(cand_sources.keys())
            verified_serving = sorted(set(verified_serving) | {s["ip"] for s in sibs})

    # ---- Cloudflare-bypass verdict: can we reach the real origin directly? ----
    apex_rec = next((rec for rec in records if rec["host"] == domain), None)
    apex_on_cf = bool(zone_on_cf or (apex_rec and apex_rec["label"] == "cloudflare"))
    any_cf = apex_on_cf or any(rec["label"] == "cloudflare" for rec in records)
    def _is_corroborating(src):
        return (src.startswith("historical:") or src.startswith("favicon:")
                or src.startswith("passive:") or src == "cert-match")

    hist_ips = sorted({ip for ip, s in cand_sources.items() if any(_is_corroborating(x) for x in s)})

    def _corr_note(ips):
        srcs = sorted({x for ip in ips for x in cand_sources.get(ip, []) if _is_corroborating(x)})
        return (" Corroborado por: " + ", ".join(srcs) + ".") if srcs else ""

    if not any_cf:
        verdict = {
            "bypass_possible": None, "confidence": "n/a",
            "origin_ips": current_candidates,
            "headline": "Cloudflare no detectado: el sitio parece servirse directo, no hace falta bypass.",
        }
    elif verified_serving:
        verdict = {
            "bypass_possible": True, "confidence": "high",
            "origin_ips": verified_serving,
            "headline": f"SI: IP de origen directa encontrada y verificada ({', '.join(verified_serving)}). "
                        "Sirve el sitio real saltando Cloudflare." + _corr_note(verified_serving),
        }
    elif args.no_verify and (current_candidates or hist_ips):
        allc = current_candidates + [ip for ip in hist_ips if ip not in current_candidates]
        verdict = {
            "bypass_possible": None, "confidence": "unverified",
            "origin_ips": allc,
            "headline": f"POSIBLE (sin verificar): IPs candidatas no-Cloudflare "
                        f"({', '.join(allc)}). Corre sin --no-verify para confirmar." + _corr_note(hist_ips),
        }
    elif hist_ips:
        verdict = {
            "bypass_possible": None, "confidence": "medium",
            "origin_ips": hist_ips,
            "headline": f"POSIBLE: fuentes historicas/pasivas exponen IP(s) ({', '.join(hist_ips)}) que no "
                        "sirvieron el sitio actual al probarlas (posible origen antiguo o filtrado)." + _corr_note(hist_ips),
        }
    elif current_candidates:
        verdict = {
            "bypass_possible": False, "confidence": "low",
            "origin_ips": current_candidates,
            "headline": f"PROBABLEMENTE NO: hay IPs candidatas ({', '.join(current_candidates)}) pero ninguna "
                        "sirvio el sitio real al probarla (firewall a solo-Cloudflare, otro vhost, o filtra sondas).",
        }
    else:
        verdict = {
            "bypass_possible": False, "confidence": "high",
            "origin_ips": [],
            "headline": "NO: no se encontro ninguna IP de origen fuera de Cloudflare (DNS actual + fuentes "
                        "historicas/favicon consultadas). La IP real esta oculta.",
        }

    # ---------------------------------------------------------------- assemble output
    result = {
        "target": domain, "generated": now_iso(), "run_dir": str(out_dir),
        "authoritative_ns": ns, "zone_on_cloudflare": zone_on_cf,
        "sources": {"crtsh": crt_meta, "c99": c99_meta},
        "cloudflare_ranges": {"v4": len(cf_v4), "v6": len(cf_v6)},
        "hosts": records, "candidate_origins": current_candidates,
        "all_candidate_origins": candidates,
        "candidate_sources": {ip: sorted(s) for ip, s in cand_sources.items()},
        "verified_serving_origins": verified_serving,
        "cloudflare_detected": any_cf, "bypass_verdict": verdict,
        "edge_baseline": edge, "verification": verify,
        "dns_infra": dns_infra,
        "favicon": {**fav_meta, "search": fav_search_meta},
        "historical_sources": hist_meta,
        "passive_sources": extra_meta,
        "tls_edge": edge_tls,
        "anti_bot": anti_bot,
        "range_scan": range_scan,
        "flags": {k: getattr(args, k) for k in
                  ("no_c99", "no_crtsh", "no_ping", "no_verify", "resolve_only", "no_browser",
                   "scan_range", "range_prefix", "range_max", "json")},
        "api_keys_configured": {
            "securitytrails": bool(st_key), "shodan": bool(shodan_key),
            "censys": bool(censys_id and censys_secret), "virustotal": bool(vt_key),
            "urlscan": bool(urlscan_key), "netlas": bool(netlas_key),
        },
    }
    (out_dir / "recon.json").write_text(json.dumps(result, indent=2, default=str), encoding="utf-8")
    (out_dir / "subdomains.txt").write_text("\n".join(hosts) + "\n", encoding="utf-8")

    write_report(out_dir / "report.md", result)
    if getattr(args, "json", False):
        print(json.dumps(result, indent=2, default=str))
    else:
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
    v = result.get("bypass_verdict") or {}
    mark = {True: "[+] BYPASS CLOUDFLARE: SI", False: "[-] BYPASS CLOUDFLARE: NO",
            None: "[?] BYPASS CLOUDFLARE: ?"}.get(v.get("bypass_possible"), "[?] BYPASS CLOUDFLARE")
    print(f"{mark}  (confianza: {v.get('confidence','?')})")
    print(f"    {v.get('headline','')}")
    if v.get("origin_ips"):
        print(f"    IP(s) de origen: {', '.join(v['origin_ips'])}")
    ab = result.get("anti_bot")
    if ab is not None:
        print(f"anti-bot: {_render_anti_bot(ab)}")
    fav = result.get("favicon") or {}
    if fav.get("ok"):
        print(f"favicon hash (Shodan-style): {fav.get('hash')}")
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
    v = r.get("bypass_verdict") or {}
    icon = {True: "✅", False: "❌", None: "⚠️"}.get(v.get("bypass_possible"), "⚠️")
    L.append("## 🎯 Veredicto: ¿se puede bypassear Cloudflare?\n")
    L.append(f"{icon} **{v.get('headline','(sin datos)')}**  ")
    L.append(f"Confianza: `{v.get('confidence','?')}` · Cloudflare detectado: `{r.get('cloudflare_detected')}`")
    if v.get("origin_ips"):
        L.append(f" · IP(s) de origen: `{', '.join(v['origin_ips'])}`")
    L.append("")
    if v.get("bypass_possible") and v.get("origin_ips"):
        ip0 = v["origin_ips"][0]
        L.append("```bash")
        L.append(f"curl -k --resolve {domain}:443:{ip0} https://{domain}/")
        L.append("```")
    L.append("")
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

    # ---- infra DNS (mail, etc.) ----
    di = r.get("dns_infra") or {}
    L.append("## Registros DNS de infraestructura (correo, etc.)\n")
    L.append("Los servidores de correo (MX), SPF/DMARC y subdominios comunes (`mail`, `cpanel`, `webmail`, "
             "`ftp`, `smtp`, `direct`, `origin`, `server`) suelen quedar **fuera de Cloudflare** y filtran el "
             "netblock real del origen.\n")
    mx = di.get("mx") or []
    L.append(f"- **MX:** {', '.join(mx) if mx else '(ninguno)'}")
    spf = di.get("spf") or []
    L.append(f"- **SPF:** {', '.join(spf) if spf else '(ninguno)'}")
    dmarc = di.get("dmarc") or []
    L.append(f"- **DMARC (`_dmarc`):** {', '.join(dmarc) if dmarc else '(ninguno)'}")
    hostmap = di.get("hosts") or {}
    if hostmap:
        L.append("")
        L.append("| Host | A / AAAA | CNAME | ¿Cloudflare? |")
        L.append("|------|----------|-------|--------------|")
        for host, rec in hostmap.items():
            hips = ", ".join((rec.get("a") or []) + (rec.get("aaaa") or [])) or "-"
            cn = ", ".join(rec.get("cname") or []) or "-"
            cfv = "**yes**" if rec.get("_cf") else ("no (direct)" if hips != "-" else "-")
            L.append(f"| {host} | {hips} | {cn} | {cfv} |")
    L.append("")

    # ---- favicon + historical/passive sources ----
    L.append("## Fuentes historicas / pasivas y favicon\n")
    fav = r.get("favicon") or {}
    if fav.get("ok"):
        L.append(f"- **Favicon hash (estilo Shodan):** `{fav.get('hash')}` "
                 f"({fav.get('size','?')} bytes desde {fav.get('url')})")
    else:
        L.append(f"- **Favicon hash:** no calculado ({fav.get('error','n/a')})")
    fs = fav.get("search") or {}
    if fs.get("ok"):
        L.append(f"  - Shodan `http.favicon.hash`: {fs.get('count',0)} host(s) con el mismo favicon "
                 "(candidatos a origen)")
    elif fs.get("note"):
        L.append(f"  - Shodan favicon: {fs['note']}")
    for name, meta in (r.get("historical_sources") or {}).items():
        if meta.get("ok"):
            L.append(f"- **{name}:** {meta.get('count',0)} IP(s) historicas (HTTP {meta.get('status','?')})")
        elif meta.get("note"):
            L.append(f"- **{name}:** {meta['note']}")
        else:
            L.append(f"- **{name}:** sin datos ({meta.get('error') or 'HTTP ' + str(meta.get('status','?'))})")
    cs = r.get("candidate_sources") or {}
    if cs:
        L.append("")
        L.append("IPs candidatas por fuente:\n")
        for ip in sorted(cs):
            L.append(f"- `{ip}` — fuentes: {', '.join(cs[ip])}")
    L.append("")

    # ---- extra passive sources: VirusTotal / urlscan / Netlas ----
    L.append("## Fuentes pasivas adicionales (VirusTotal / urlscan / Netlas)\n")
    L.append("Fuentes OSINT opcionales por clave de API propia del usuario. Cada IP que aportan entra al "
             "mismo camino de verificación (probe HTTP(S) + TLS) que las demás candidatas y suma a "
             "`bypass_verdict`; cuando varias fuentes independientes coinciden en una IP, sube la confianza "
             "(ver \"Corroborado por\").\n")
    ps = r.get("passive_sources") or {}
    if not ps:
        L.append("- (no se consultaron fuentes pasivas adicionales)")
    labels = {"virustotal": "VirusTotal", "urlscan": "urlscan.io", "netlas": "Netlas"}
    for name in ("virustotal", "urlscan", "netlas"):
        meta = ps.get(name)
        if not meta:
            continue
        title = labels.get(name, name)
        if meta.get("ok"):
            det = f"{meta.get('count', 0)} IP(s) candidata(s)"
            if meta.get("subdomain_count"):
                det += f", {meta['subdomain_count']} subdominio(s)"
            if meta.get("asns"):
                det += f", ASN: {', '.join(meta['asns'][:8])}"
            L.append(f"- **{title}:** {det} (HTTP {meta.get('status', '?')})")
        elif meta.get("note"):
            L.append(f"- **{title}:** {meta['note']}")
        else:
            L.append(f"- **{title}:** sin datos ({meta.get('error') or 'HTTP ' + str(meta.get('status', '?'))})")
    L.append("")

    # ---- anti-bot protection ----
    ab = r.get("anti_bot")
    if ab is not None:
        L.append("## Proteccion anti-bot\n")
        L.append(_render_anti_bot(ab))
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
    L.append("> Las fuentes historicas/pasivas (SecurityTrails, Shodan, Censys) pueden revelar IPs de origen "
             "**anteriores** a Cloudflare; aqui se consultan solo si su clave de API esta configurada (ver seccion "
             "\"Fuentes historicas / pasivas y favicon\"). ViewDNS (de pago/HTML) se omite. El hash del favicon y "
             "los A-records hermanos actuales son senales gratuitas ya usadas.\n")

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
                sv = "no"
                if e.get("serves_site"):
                    extra = e.get("served_by") or ""
                    if e.get("body_match"):
                        extra = (extra + " · body-match").strip(" ·")
                    sv = f"**YES** ({extra})" if extra else "**YES**"
                L.append(f"| {ip} | {pstr} | {pd} | {sv} | {cs} |")
            L.append("")

    if not r["flags"]["no_verify"]:
        L.append("## Verificación TLS / certificado\n")
        L.append("Lectura (solo lectura) del certificado que presenta cada IP candidata al abrir TLS con "
                 "SNI = dominio objetivo (stdlib `ssl`). Si el SAN incluye el dominio (o un wildcard que lo "
                 "cubre) y/o el fingerprint SHA256 coincide con el del edge, es evidencia fuerte de que esa "
                 "IP directa sirve el mismo sitio (`cert-match`).\n")
        et = r.get("tls_edge") or {}
        for vhost, ci in et.items():
            if ci.get("ok"):
                L.append(f"- **Edge `{vhost}`:** CN={ci.get('cn')!r} · fingerprint `"
                         f"{(ci.get('fingerprint_sha256') or '')[:16]}…` · válido hasta {ci.get('not_after')}")
            else:
                L.append(f"- **Edge `{vhost}`:** cert no leído ({ci.get('error', 'n/a')})")
        L.append("")
        tls_rows = [(ip, e) for ip, e in verify.items() if e.get("tls")]
        if tls_rows:
            L.append("| Candidate IP | CN | SAN match | Fingerprint match | Issuer | Válido hasta |")
            L.append("|--------------|----|-----------|-------------------|--------|--------------|")
            for ip, e in tls_rows:
                t = e.get("tls") or {}
                if not t.get("ok"):
                    L.append(f"| {ip} | - | - | - | (sin cert: {t.get('error', 'n/a')}) | - |")
                    continue
                sanm = "**sí**" if e.get("san_match") else "no"
                fpm = "**sí**" if e.get("fp_match") else "no"
                san_preview = ", ".join((t.get("san") or [])[:4])
                cnp = t.get("cn") or "-"
                if san_preview:
                    cnp = f"{cnp} (SAN: {san_preview})"
                L.append(f"| {ip} | {cnp} | {sanm} | {fpm} | {t.get('issuer', '-')} | {t.get('not_after', '-')} |")
            L.append("")
        else:
            L.append("No hubo IPs candidatas con lectura de certificado en esta ejecución.\n")

    rs = r.get("range_scan") or {}
    if rs.get("ran"):
        L.append(f"## Escaneo de rango /{rs.get('prefix', 24)} alrededor del origen\n")
        sibs = rs.get("siblings") or []
        if sibs:
            L.append(f"Se encontraron {len(sibs)} IP(s) hermanas sirviendo el mismo sitio (candidatos a origen):")
            for s in sibs:
                pr = s.get("probe", {})
                L.append(f"- `{s.get('ip')}` — {pr.get('scheme','?')} {pr.get('status','?')} "
                         f"title={pr.get('title','-')!r}")
        else:
            L.append(f"No se encontraron IPs hermanas (hasta {rs.get('max')} IPs sondeadas en /{rs.get('prefix',24)}).")
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
