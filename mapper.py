#!/usr/bin/env python3
"""web-network-mapper: crawl a site with Playwright/Chromium, capture everything the DevTools
Network tab sees (via a CDP session), and build a site map + deduplicated API map.

Outputs (per run, default <tool>/runs/<domain>-<timestamp>/):
  requests.jsonl   one CDP-derived record per request (headers, post data, status, timing, body ref)
  network.har      standard HAR recorded by Playwright
  bodies/          saved response bodies (XHR/fetch/document/JSON by default)
  websockets.jsonl WebSocket frames (if any)
  ws_sse.jsonl     one record per WebSocket connection / SSE stream (frames/events consolidated)
  pages.json       site map (url, title, status, links, API calls triggered)
  api_map.json/.md deduplicated endpoint map (built by analyze.py)
  run_meta.json    arguments, timings, counts
"""
from __future__ import annotations

import argparse
import asyncio
import base64
import json
import re
import signal
import sys
import time
from datetime import datetime
from pathlib import Path
from urllib.parse import urldefrag, urlsplit
from urllib.robotparser import RobotFileParser

TOOL_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(TOOL_DIR))

import httpx  # noqa: E402
from playwright.async_api import async_playwright  # noqa: E402

import analyze  # noqa: E402
from wnm_common import (  # noqa: E402
    REDACTED, is_sensitive_header, is_sensitive_field, load_cookies_file, lower_headers,
    parse_header_args, redact_headers, redact_post_data, redact_url, slugify, guard_target,
    detect_body_kind,
)
try:  # session cache + SSE helpers (additive; degrade if an older wnm_common is present)
    from wnm_common import (  # noqa: E402
        load_session, save_session, session_domain, session_summary, session_ttl, parse_sse, redact_obj,
    )
except Exception:  # pragma: no cover
    load_session = save_session = session_domain = session_summary = session_ttl = parse_sse = redact_obj = None

SKIP_EXT = re.compile(
    r"\.(pdf|zip|gz|tgz|rar|7z|exe|dmg|msi|apk|iso|bin|jpg|jpeg|png|gif|webp|svg|ico|bmp|tiff?|"
    r"mp3|mp4|m4a|wav|ogg|webm|avi|mov|mkv|woff2?|ttf|otf|eot|css|js|mjs|map|xml|rss|atom|csv|xlsx?|docx?|pptx?)$",
    re.I,
)
DEFAULT_BODY_TYPES = "Document,XHR,Fetch,EventSource"
BODY_MIME_RE = re.compile(r"json|graphql|ndjson|x-protobuf|grpc|text/plain|text/csv|xml", re.I)


def log(*a):
    print(f"[{datetime.now().strftime('%H:%M:%S')}]", *a, file=sys.stderr, flush=True)


def now_iso():
    return datetime.now().astimezone().isoformat(timespec="seconds")


def norm_link(u: str) -> str | None:
    if not u:
        return None
    u = urldefrag(u.strip())[0]
    if not u.lower().startswith(("http://", "https://")):
        return None
    return u


def origin(u: str) -> str:
    p = urlsplit(u)
    return f"{p.scheme}://{p.netloc}".lower()


def base_host(h: str) -> str:
    h = (h or "").lower().split(":")[0]
    return h[4:] if h.startswith("www.") else h


# ============================================================ capture

class Capture:
    """Collects Network.* CDP events into request records."""

    def __init__(self, run_dir: Path, args):
        self.run_dir = run_dir
        self.args = args
        self.bodies_dir = run_dir / "bodies"
        self.bodies_dir.mkdir(parents=True, exist_ok=True)
        self.records: dict[str, dict] = {}
        self.extra_req: dict[str, dict] = {}
        self.extra_resp: dict[str, dict] = {}
        self.redirect_counts: dict[str, int] = {}
        self.pending: set[asyncio.Task] = set()
        self.written: set[str] = set()
        self.seq = 0
        self.current_page: str | None = None
        self.cdp = None
        self.body_types = {t.strip() for t in args.body_types.split(",") if t.strip()}
        self.req_out = open(run_dir / "requests.jsonl", "a", encoding="utf-8")
        self.ws_out = None
        self.ws_meta: dict[str, dict] = {}
        self.stats = {"requests": 0, "bodies_saved": 0, "body_errors": 0, "ws_frames": 0}
        # auto-attached child targets (OOP iframes, dedicated/shared workers, service workers)
        self.children: dict[str, dict] = {}       # sessionId -> {"type", "url", "target_id"}
        self._child_pending: dict[int, asyncio.Future] = {}
        self._child_msg_id = 900_000
        self._main_rids: set[str] = set()          # raw requestIds seen on the main session
        self._child_ignored: set[str] = set()      # "sid|rid" keys dropped as duplicates of main
        self._sw_served: set[tuple] = set()        # (method, url) the page got from its service worker
        self.auto_attach = {"enabled": bool(getattr(args, "auto_attach", True)), "status": "not_started",
                            "mode": None, "targets_attached": {}, "child_requests": 0,
                            "duplicates_skipped": 0, "notes": []}
        # consolidated WebSocket / SSE capture -> ws_sse.jsonl (disabled with --no-ws)
        self.ws_enabled = not bool(getattr(args, "no_ws", False))
        self.wsx: dict[str, dict] = {}            # key -> websocket connection record (open)
        self.ssex: dict[str, dict] = {}           # key -> SSE stream record (open)
        self._ssex_buf: dict[str, str] = {}       # key -> incomplete SSE text awaiting more data
        self._ssex_streaming: set[str] = set()    # keys with Network.streamResourceContent active
        self._wsx_main_seen: set[str] = set()     # raw requestIds of WebSockets seen on the main session
        self._wall_offset: float | None = None    # wallTime - monotonic timestamp (CDP)
        self.ws_sse_out = None
        self.ws_sse = {"enabled": self.ws_enabled, "file": "ws_sse.jsonl" if self.ws_enabled else None, "websocket_connections": 0,
                       "websocket_frames": 0, "websocket_frames_sent": 0, "websocket_frames_received": 0,
                       "websocket_frames_dropped": 0, "websocket_child_connections": 0,
                       "websocket_duplicates_skipped": 0, "sse_streams": 0, "sse_events": 0,
                       "sse_sources": {}, "notes": []}

    # -------- attach
    async def attach(self, page):
        self.cdp = await page.context.new_cdp_session(page)
        self.children.clear()
        on = self.cdp.on
        on("Network.requestWillBeSent", self._on_main_request)
        on("Network.requestWillBeSentExtraInfo", self._on_request_extra)
        on("Network.responseReceived", self._on_response)
        on("Network.responseReceivedExtraInfo", self._on_response_extra)
        on("Network.loadingFinished", self._on_finished)
        on("Network.loadingFailed", self._on_failed)
        on("Network.webSocketCreated", self._on_ws_created)
        on("Network.webSocketFrameSent", lambda p: self._on_ws_frame(p, "sent"))
        on("Network.webSocketFrameReceived", lambda p: self._on_ws_frame(p, "received"))
        on("Network.webSocketClosed", self._on_ws_closed)
        on("Network.eventSourceMessageReceived", self._on_sse)
        self._attach_ws_sse(on)
        params = {"maxTotalBufferSize": 256 * 1024 * 1024, "maxResourceBufferSize": 64 * 1024 * 1024,
                  "maxPostDataSize": 1024 * 1024}
        try:
            await self.cdp.send("Network.enable", params)
        except Exception:
            await self.cdp.send("Network.enable", {})
        if self.args.disable_cache:
            await self.cdp.send("Network.setCacheDisabled", {"cacheDisabled": True})
        await self._setup_auto_attach()

    # -------- auto-attach (iframes / workers / service workers)
    async def _setup_auto_attach(self):
        """Capture requests from out-of-process iframes, workers and service workers.

        Uses Target.setAutoAttach on the page's CDP session. Playwright's CDPSession object can only
        address its own session, so flat-mode child sessions (flatten=true) are unreachable through it
        (their events are dropped and Target.sendMessageToTarget is refused). We therefore probe
        flatten=true only to record that limitation, and run in the non-flat mode where child
        sessions are driven via Target.sendMessageToTarget / Target.receivedMessageFromTarget.
        Any failure falls back to main-session-only capture (previous behaviour) with a note."""
        aa = self.auto_attach
        if not aa["enabled"]:
            aa["status"] = "disabled"
            return
        try:
            self.cdp.on("Target.attachedToTarget", self._on_attached)
            self.cdp.on("Target.detachedFromTarget", self._on_detached)
            self.cdp.on("Target.receivedMessageFromTarget", self._on_child_message)
            await self.cdp.send("Target.setAutoAttach",
                                {"autoAttach": True, "waitForDebuggerOnStart": False, "flatten": False})
            aa["status"] = "ok"
            aa["mode"] = "non-flat (Target.sendMessageToTarget)"
            if not any("flatten" in n for n in aa["notes"]):
                aa["notes"].append("flatten=true no es direccionable con la CDPSession de Playwright; "
                                   "se usa modo no-flat (sendMessageToTarget) para las sesiones hijas")
        except Exception as e:
            aa["status"] = "failed"
            aa["notes"].append(f"auto-attach no disponible, solo se captura el frame principal: {str(e)[:200]}")
            log("WARN auto-attach unavailable, main-frame capture only:", str(e).splitlines()[0][:200])

    def _on_attached(self, p):
        try:
            sid = p.get("sessionId")
            ti = p.get("targetInfo") or {}
            ttype = ti.get("type") or "other"
            self.children[sid] = {"type": ttype, "url": ti.get("url"), "target_id": ti.get("targetId")}
            ta = self.auto_attach["targets_attached"]
            ta[ttype] = ta.get(ttype, 0) + 1
            self._spawn(self._enable_child(sid, ttype))
        except Exception as e:
            log("WARN attachedToTarget handler:", e)

    async def _enable_child(self, sid, ttype):
        params = {"maxTotalBufferSize": 64 * 1024 * 1024, "maxResourceBufferSize": 16 * 1024 * 1024,
                  "maxPostDataSize": 1024 * 1024}
        try:
            try:
                await self._child_send(sid, "Network.enable", params)
            except Exception:
                await self._child_send(sid, "Network.enable", {})
            if self.args.disable_cache:
                await self._child_send(sid, "Network.setCacheDisabled", {"cacheDisabled": True})
        except Exception as e:
            note = f"Network.enable falló en {ttype}: {str(e)[:120]}"
            if note not in self.auto_attach["notes"] and len(self.auto_attach["notes"]) < 20:
                self.auto_attach["notes"].append(note)
        # workers are started paused only if waitForDebuggerOnStart; harmless otherwise
        try:
            await self._child_send(sid, "Runtime.runIfWaitingForDebugger", {}, timeout=3)
        except Exception:
            pass

    def _on_detached(self, p):
        sid = p.get("sessionId")
        self.children.pop(sid, None)
        for fut in list(self._child_pending.values()):
            if getattr(fut, "_wnm_sid", None) == sid and not fut.done():
                fut.set_exception(RuntimeError("target detached"))

    async def _child_send(self, sid, method, params=None, timeout=15):
        self._child_msg_id += 1
        mid = self._child_msg_id
        fut = asyncio.get_running_loop().create_future()
        fut._wnm_sid = sid
        self._child_pending[mid] = fut
        try:
            await self.cdp.send("Target.sendMessageToTarget",
                                {"sessionId": sid, "message": json.dumps({"id": mid, "method": method,
                                                                          "params": params or {}})})
            return await asyncio.wait_for(fut, timeout)
        finally:
            self._child_pending.pop(mid, None)

    def _on_child_message(self, p):
        try:
            sid = p.get("sessionId")
            msg = json.loads(p.get("message") or "{}")
            if "id" in msg:
                fut = self._child_pending.get(msg["id"])
                if fut and not fut.done():
                    if "error" in msg:
                        fut.set_exception(RuntimeError(str(msg["error"].get("message", msg["error"]))))
                    else:
                        fut.set_result(msg.get("result") or {})
                return
            method = msg.get("method") or ""
            if not method.startswith("Network."):
                return
            params = dict(msg.get("params") or {})
            raw_rid = params.get("requestId")
            if raw_rid is None:
                return
            key = f"{sid}|{raw_rid}"
            if method == "Network.requestWillBeSent" and raw_rid in self._main_rids and not params.get("redirectResponse"):
                self._child_ignored.add(key)
                self.auto_attach["duplicates_skipped"] += 1
                return
            if key in self._child_ignored:
                return
            params["requestId"] = key
            handler = {
                "Network.requestWillBeSent": self._on_request,
                "Network.requestWillBeSentExtraInfo": self._on_request_extra,
                "Network.responseReceived": self._on_response,
                "Network.responseReceivedExtraInfo": self._on_response_extra,
                "Network.loadingFinished": self._on_finished,
                "Network.loadingFailed": self._on_failed,
                "Network.webSocketCreated": self._on_ws_created,
                "Network.webSocketFrameSent": lambda q: self._on_ws_frame(q, "sent"),
                "Network.webSocketFrameReceived": lambda q: self._on_ws_frame(q, "received"),
                "Network.webSocketClosed": self._on_ws_closed,
                "Network.eventSourceMessageReceived": self._on_sse,
            }.get(method)
            self._ws_sse_child(method, params, sid)
            if handler is None:
                return
            handler(params)
            if method == "Network.requestWillBeSent":
                rec = self.records.get(key)
                if rec is not None:
                    ch = self.children.get(sid) or {}
                    rec["target_type"] = ch.get("type") or "child"
                    rec["target_id"] = ch.get("target_id")
                    rec["target_url"] = ch.get("url")
                    if not rec.get("frame_id") and ch.get("type") == "iframe":
                        rec["frame_id"] = ch.get("target_id")
                    self.auto_attach["child_requests"] += 1
        except Exception as e:
            log("WARN child target message:", e)

    def _on_main_request(self, p):
        try:
            self._main_rids.add(p.get("requestId"))
        except Exception:
            pass
        self._on_request(p)
        try:
            rec = self.records.get(p.get("requestId"))
            if rec is not None and "target_type" not in rec:
                rec["target_type"] = "page"
        except Exception:
            pass

    async def _send_for(self, rid: str, method: str, params: dict):
        """Send a Network.* command to the session that owns the request (main or child target)."""
        if isinstance(rid, str) and "|" in rid and not rid.startswith("|"):
            sid, raw = rid.split("|", 1)
            if "#redirect" in raw:
                raw = raw.split("#", 1)[0]
            p2 = dict(params)
            p2["requestId"] = raw
            return await self._child_send(sid, method, p2)
        return await self.cdp.send(method, params)

    def _spawn(self, coro):
        t = asyncio.get_running_loop().create_task(coro)
        self.pending.add(t)
        t.add_done_callback(self.pending.discard)

    # -------- request lifecycle
    def _on_request(self, p):
        try:
            rid = p["requestId"]
            if p.get("redirectResponse") and rid in self.records:
                old = self.records.pop(rid)
                self._apply_response(old, p["redirectResponse"], rid)
                old["state"] = "redirected"
                old["redirected_to"] = p["request"]["url"]
                n = self.redirect_counts.get(rid, 0) + 1
                self.redirect_counts[rid] = n
                key = f"{rid}#redirect{n}"
                old["request_id"] = key
                self.records[key] = old
            req = p["request"]
            self.seq += 1
            self.stats["requests"] += 1
            init = p.get("initiator") or {}
            rec = {
                "seq": self.seq,
                "request_id": rid,
                "page": self.current_page,
                "document_url": p.get("documentURL"),
                "frame_id": p.get("frameId"),
                "resource_type": p.get("type") or "Other",
                "url": req.get("url", "") + (req.get("urlFragment") or ""),
                "method": req.get("method"),
                "request_headers": lower_headers(req.get("headers")),
                "post_data": req.get("postData"),
                "has_post_data": bool(req.get("hasPostData")),
                "initiator": {"type": init.get("type"), "url": init.get("url")},
                "wall_time": p.get("wallTime"),
                "started_iso": datetime.fromtimestamp(p["wallTime"]).astimezone().isoformat(timespec="milliseconds") if p.get("wallTime") else None,
                "_ts": p.get("timestamp"),
                "state": "pending",
            }
            if rid in self.extra_req:
                rec["request_headers"].update(self.extra_req.pop(rid))
            self.records[rid] = rec
            if rec["has_post_data"] and rec["post_data"] is None:
                self._spawn(self._fetch_post_data(rid, rec))
        except Exception as e:  # never let a handler kill the capture
            log("WARN requestWillBeSent handler:", e)

    def _on_request_extra(self, p):
        rid = p.get("requestId")
        hdrs = lower_headers(p.get("headers"))
        rec = self.records.get(rid)
        if rec and rec.get("status") is None:
            rec["request_headers"].update(hdrs)
            if p.get("associatedCookies") is not None:
                rec["blocked_cookies"] = sum(1 for c in p["associatedCookies"] if c.get("blockedReasons"))
        else:
            self.extra_req[rid] = hdrs

    def _apply_response(self, rec, resp, rid):
        rec["status"] = resp.get("status")
        rec["status_text"] = resp.get("statusText")
        rec["mime_type"] = resp.get("mimeType")
        rec["response_headers"] = lower_headers(resp.get("headers"))
        rec["protocol"] = resp.get("protocol")
        rec["remote_ip"] = resp.get("remoteIPAddress")
        rec["from_disk_cache"] = resp.get("fromDiskCache", False)
        rec["from_service_worker"] = resp.get("fromServiceWorker", False)
        if rec["from_service_worker"] and "|" not in str(rid):
            self._sw_served.add((rec.get("method"), rec.get("url")))
        rec["from_prefetch_cache"] = resp.get("fromPrefetchCache", False)
        t = resp.get("timing")
        if t:
            rec["timing"] = {k: round(v, 3) if isinstance(v, float) else v for k, v in t.items()
                             if k in ("requestTime", "dnsStart", "dnsEnd", "connectStart", "connectEnd", "sslStart",
                                      "sslEnd", "sendStart", "sendEnd", "receiveHeadersStart", "receiveHeadersEnd")}
            if t.get("receiveHeadersEnd") is not None:
                rec["ttfb_ms"] = round(t["receiveHeadersEnd"] - max(t.get("sendStart", 0), 0), 2)
        ex = self.extra_resp.pop(rid, None)
        if ex:
            rec["response_headers"].update(ex)

    def _on_response(self, p):
        rid = p.get("requestId")
        rec = self.records.get(rid)
        if not rec:
            return
        if p.get("type"):
            rec["resource_type"] = p["type"]
        self._apply_response(rec, p.get("response") or {}, rid)

    def _on_response_extra(self, p):
        rid = p.get("requestId")
        hdrs = lower_headers(p.get("headers"))
        rec = self.records.get(rid)
        if rec and rec.get("status") is not None:
            rec["response_headers"].update(hdrs)
        else:
            self.extra_resp[rid] = hdrs

    def _on_finished(self, p):
        rid = p.get("requestId")
        rec = self.records.get(rid)
        if not rec:
            return
        rec["state"] = "finished"
        rec["encoded_data_length"] = p.get("encodedDataLength")
        if rec.get("_ts") and p.get("timestamp"):
            rec["duration_ms"] = round((p["timestamp"] - rec["_ts"]) * 1000, 2)
        if self._want_body(rec):
            self._spawn(self._fetch_body(rid, rec))

    def _on_failed(self, p):
        rid = p.get("requestId")
        rec = self.records.get(rid)
        if not rec:
            return
        rec["state"] = "failed"
        rec["error_text"] = p.get("errorText")
        rec["canceled"] = p.get("canceled", False)
        if p.get("blockedReason"):
            rec["blocked_reason"] = p["blockedReason"]
        if rec.get("_ts") and p.get("timestamp"):
            rec["duration_ms"] = round((p["timestamp"] - rec["_ts"]) * 1000, 2)

    def _want_body(self, rec) -> bool:
        if self.args.max_body_bytes == 0 or self.args.no_bodies:
            return False
        if rec.get("status") in (204, 304) or (rec.get("status") or 0) >= 300 and (rec.get("status") or 0) < 400:
            return False
        if self.args.all_bodies:
            return True
        if rec.get("resource_type") in self.body_types:
            return True
        return bool(BODY_MIME_RE.search(rec.get("mime_type") or "")) and rec.get("resource_type") not in ("Script", "Stylesheet", "Image", "Font", "Media")

    async def _fetch_post_data(self, rid, rec):
        rec["_busy"] = True
        try:
            r = await self._send_for(rid, "Network.getRequestPostData", {"requestId": rid})
            rec["post_data"] = r.get("postData")
        except Exception as e:
            rec["post_data_error"] = str(e)[:200]
        finally:
            rec.pop("_busy", None)

    async def _fetch_body(self, rid, rec):
        rec["_busy"] = True
        try:
            await self._fetch_body_inner(rid, rec)
        finally:
            rec.pop("_busy", None)

    async def _fetch_body_inner(self, rid, rec):
        try:
            r = await self._send_for(rid, "Network.getResponseBody", {"requestId": rid})
        except Exception as e:
            rec["body_error"] = str(e).splitlines()[0][:200]
            self.stats["body_errors"] += 1
            return
        try:
            body = r.get("body") or ""
            if r.get("base64Encoded"):
                raw = base64.b64decode(body)
                rec["body_base64"] = True
            else:
                raw = body.encode("utf-8")
            rec["body_size"] = len(raw)
            try:
                kind = detect_body_kind(rec.get("mime_type") or (rec.get("response_headers") or {}).get("content-type"))
                if kind:
                    rec["body_kind"] = kind  # grpc / protobuf: saved as raw binary, not decoded
                # CDP getResponseBody already returns the decoded (decompressed) payload
                if (rec.get("response_headers") or {}).get("content-encoding"):
                    rec["body_decoded"] = True
            except Exception:
                pass
            cap = self.args.max_body_bytes
            if cap > 0 and len(raw) > cap:
                raw = raw[:cap]
                rec["body_truncated"] = True
            u = urlsplit(rec["url"])
            pslug = slugify(u.path, 60) if u.path.strip("/") else "root"
            name = f"{rec['seq']:05d}_{rec['method']}_{slugify(u.netloc, 40)}_{pslug}"
            name += _ext_for(rec.get("mime_type"), u.path)
            (self.bodies_dir / name).write_bytes(raw)
            rec["body_file"] = f"bodies/{name}"
            self.stats["bodies_saved"] += 1
        except Exception as e:
            rec["body_error"] = f"save failed: {e}"[:200]
            self.stats["body_errors"] += 1

    # -------- websockets / SSE
    def _ws_file(self):
        if self.ws_out is None:
            self.ws_out = open(self.run_dir / "websockets.jsonl", "a", encoding="utf-8")
        return self.ws_out

    def _on_ws_created(self, p):
        if not self.ws_enabled:
            return
        self.ws_meta[p["requestId"]] = {"url": p.get("url"), "page": self.current_page}
        self._write_ws({"event": "created", "request_id": p["requestId"], "url": self._u(p.get("url")),
                        "page": self.current_page, "time": now_iso()})

    def _on_ws_frame(self, p, direction):
        if not self.ws_enabled:
            return
        meta = self.ws_meta.get(p.get("requestId"), {})
        resp = p.get("response") or {}
        payload = resp.get("payloadData") or ""
        cap = self.args.max_ws_payload
        self.stats["ws_frames"] += 1
        self._write_ws({"event": "frame", "direction": direction, "request_id": p.get("requestId"),
                        "url": self._u(meta.get("url")), "page": meta.get("page"), "opcode": resp.get("opcode"),
                        "payload_len": len(payload), "payload": payload[:cap], "truncated": len(payload) > cap,
                        "time": now_iso()})

    def _on_ws_closed(self, p):
        if not self.ws_enabled:
            return
        self._write_ws({"event": "closed", "request_id": p.get("requestId"), "time": now_iso()})

    def _on_sse(self, p):
        rec = self.records.get(p.get("requestId"))
        if rec is not None:
            msgs = rec.setdefault("sse_messages", [])
            if len(msgs) < 200:
                msgs.append({"event": p.get("eventName"), "id": p.get("eventId"),
                             "data": (p.get("data") or "")[: self.args.max_ws_payload]})

    def _write_ws(self, obj):
        try:
            f = self._ws_file()
            f.write(json.dumps(obj, ensure_ascii=False) + "\n")
            f.flush()
        except Exception as e:
            log("WARN ws write:", e)

    def _u(self, u):
        return u if self.args.keep_secrets or not u else redact_url(u)

    # -------- consolidated WebSocket / SSE capture (ws_sse.jsonl)
    # One JSON line per WebSocket connection ("kind": "websocket", with "frames") or per SSE stream
    # ("kind": "sse", with "events"), written when the connection closes / the stream ends, and at the
    # end of the run for anything still open. requests.jsonl is left untouched.
    _WS_OPCODES = {0: "continuation", 1: "text", 2: "binary", 8: "close", 9: "ping", 10: "pong"}

    def _attach_ws_sse(self, on):
        if not self.ws_enabled:
            return
        try:
            on("Network.webSocketCreated", self._wsx_created)
            on("Network.webSocketWillSendHandshakeRequest", self._wsx_hs_request)
            on("Network.webSocketHandshakeResponseReceived", self._wsx_hs_response)
            on("Network.webSocketFrameSent", lambda p: self._wsx_frame(p, "sent"))
            on("Network.webSocketFrameReceived", lambda p: self._wsx_frame(p, "received"))
            on("Network.webSocketFrameError", self._wsx_error)
            on("Network.webSocketClosed", self._wsx_closed)
            on("Network.responseReceived", self._ssex_response)
            on("Network.eventSourceMessageReceived", self._ssex_es_message)
            on("Network.dataReceived", self._ssex_data)
            on("Network.loadingFinished", self._ssex_finished)
            on("Network.loadingFailed", self._ssex_failed)
        except Exception as e:
            self._ws_note(f"no se pudo registrar la captura WS/SSE: {str(e)[:160]}")

    def _ws_sse_child(self, method, params, sid):
        """Same WS/SSE handlers for auto-attached child targets (iframes / workers). Never raises."""
        if not self.ws_enabled:
            return
        try:
            h = {
                "Network.webSocketCreated": self._wsx_created,
                "Network.webSocketWillSendHandshakeRequest": self._wsx_hs_request,
                "Network.webSocketHandshakeResponseReceived": self._wsx_hs_response,
                "Network.webSocketFrameSent": lambda q: self._wsx_frame(q, "sent"),
                "Network.webSocketFrameReceived": lambda q: self._wsx_frame(q, "received"),
                "Network.webSocketFrameError": self._wsx_error,
                "Network.webSocketClosed": self._wsx_closed,
                "Network.eventSourceMessageReceived": self._ssex_es_message,
                "Network.dataReceived": self._ssex_data,
                "Network.loadingFinished": self._ssex_finished,
                "Network.loadingFailed": self._ssex_failed,
            }.get(method)
            if h is not None:
                h(params)
            elif method == "Network.responseReceived":
                # the record still lacks the response here; pass the child target info explicitly
                self._ssex_response(params, child=self.children.get(sid) or {"type": "child"})
        except Exception as e:
            log("WARN captura WS/SSE en target hijo:", e)

    def _ws_note(self, note):
        try:
            notes = self.ws_sse["notes"]
            if note not in notes and len(notes) < 20:
                notes.append(note)
        except Exception:
            pass

    def _wall(self, ts=None):
        """Epoch seconds for a CDP monotonic timestamp (falls back to the local clock)."""
        try:
            if ts is not None and self._wall_offset is not None:
                return round(float(ts) + self._wall_offset, 3)
        except Exception:
            pass
        return round(time.time(), 3)

    @staticmethod
    def _iso(epoch):
        try:
            return datetime.fromtimestamp(epoch).astimezone().isoformat(timespec="milliseconds")
        except Exception:
            return now_iso()

    def _learn_offset(self, wall, ts):
        try:
            if wall and ts:
                self._wall_offset = float(wall) - float(ts)
        except Exception:
            pass

    def _target_of(self, key, child=None):
        if child is None and isinstance(key, str) and "|" in key and not key.startswith("|"):
            child = self.children.get(key.split("|", 1)[0]) or {"type": "child"}
        if child is None:
            return {"target_type": "page"}
        return {"target_type": child.get("type") or "child", "target_id": child.get("target_id"),
                "target_url": self._u(child.get("url"))}

    def _redact_text(self, text):
        """Redact secret-looking JSON fields in a WS/SSE text payload (also Socket.IO '42[...]').
        Returns (text, changed). With --keep-secrets the text is returned as is."""
        if self.args.keep_secrets or not text or redact_obj is None:
            return text, False
        try:
            m = re.match(r"^(\d{0,4})([\[{].*)$", text, re.S)
            if not m:
                return text, False
            obj = json.loads(m.group(2))
            red = redact_obj(obj)
            if red == obj:
                return text, False
            return m.group(1) + json.dumps(red, ensure_ascii=False), True
        except Exception:
            return text, False

    def _ws_sse_file(self):
        if self.ws_sse_out is None:
            self.ws_sse_out = open(self.run_dir / "ws_sse.jsonl", "a", encoding="utf-8")
        return self.ws_sse_out

    def _ws_sse_write(self, obj):
        try:
            f = self._ws_sse_file()
            f.write(json.dumps(obj, ensure_ascii=False) + "\n")
            f.flush()
        except Exception as e:
            log("WARN escritura ws_sse.jsonl:", e)

    # ---- websocket
    def _wsx_get(self, key, url=None):
        c = self.wsx.get(key)
        if c is None:
            now = self._wall()
            c = self.wsx[key] = {
                "kind": "websocket", "request_id": key, "url": url, "page": self.current_page,
                **self._target_of(key), "created_ts": now, "created_iso": self._iso(now),
                "closed_ts": None, "closed_iso": None, "state": "open", "handshake": None,
                "frames": [], "frames_sent": 0, "frames_received": 0, "frames_dropped": 0,
                "bytes_sent": 0, "bytes_received": 0, "errors": [], "initiator": None,
            }
            if "|" not in str(key):
                self._wsx_main_seen.add(str(key))
        elif url and not c.get("url"):
            c["url"] = url
        return c

    def _wsx_created(self, p):
        try:
            c = self._wsx_get(p.get("requestId"), p.get("url"))
            init = p.get("initiator") or {}
            c["initiator"] = {"type": init.get("type"), "url": self._u(init.get("url"))}
        except Exception as e:
            log("WARN webSocketCreated:", e)

    def _wsx_hs_request(self, p):
        try:
            self._learn_offset(p.get("wallTime"), p.get("timestamp"))
            c = self._wsx_get(p.get("requestId"))
            hs = c["handshake"] = c.get("handshake") or {}
            hs["request_headers"] = lower_headers((p.get("request") or {}).get("headers"))
            if p.get("wallTime"):
                c["created_ts"] = round(float(p["wallTime"]), 3)
                c["created_iso"] = self._iso(c["created_ts"])
        except Exception as e:
            log("WARN webSocketWillSendHandshakeRequest:", e)

    def _wsx_hs_response(self, p):
        try:
            c = self._wsx_get(p.get("requestId"))
            r = p.get("response") or {}
            hs = c["handshake"] = c.get("handshake") or {}
            hs["status"] = r.get("status")
            hs["status_text"] = r.get("statusText")
            hs["response_headers"] = lower_headers(r.get("headers"))
            if r.get("requestHeaders") and not hs.get("request_headers"):
                hs["request_headers"] = lower_headers(r.get("requestHeaders"))
        except Exception as e:
            log("WARN webSocketHandshakeResponseReceived:", e)

    def _wsx_frame(self, p, direction):
        try:
            c = self._wsx_get(p.get("requestId"))
            resp = p.get("response") or {}
            op = resp.get("opcode")
            payload = resp.get("payloadData") or ""
            is_text = op == 1
            if is_text:
                size = len(payload.encode("utf-8", "replace"))
            else:
                size = max(0, len(payload) * 3 // 4 - payload[-2:].count("="))
            c["frames_" + direction] += 1
            c["bytes_" + direction] += size
            if len(c["frames"]) >= self.args.max_ws_frames > 0:
                c["frames_dropped"] += 1
                return
            changed = False
            if is_text:
                payload, changed = self._redact_text(payload)
            cap = self.args.max_ws_payload
            truncated = cap >= 0 and len(payload) > cap
            if truncated:
                payload = payload[:cap] if is_text else payload[: cap - cap % 4]
            fr = {"dir": direction, "opcode": op, "type": self._WS_OPCODES.get(op, "other"),
                  "encoding": "text" if is_text else "base64", "payload": payload, "payload_len": size,
                  "truncated": truncated}
            if changed:
                fr["redacted"] = True
            ts = self._wall(p.get("timestamp"))
            fr["ts"] = ts
            fr["time"] = self._iso(ts)
            c["frames"].append(fr)
        except Exception as e:
            log("WARN frame WebSocket:", e)

    def _wsx_error(self, p):
        try:
            c = self._wsx_get(p.get("requestId"))
            if len(c["errors"]) < 50:
                ts = self._wall(p.get("timestamp"))
                c["errors"].append({"message": str(p.get("errorMessage"))[:300], "ts": ts, "time": self._iso(ts)})
        except Exception as e:
            log("WARN webSocketFrameError:", e)

    def _wsx_closed(self, p):
        try:
            key = p.get("requestId")
            c = self._wsx_get(key)
            ts = self._wall(p.get("timestamp"))
            c["closed_ts"] = ts
            c["closed_iso"] = self._iso(ts)
            c["state"] = "closed"
            self._wsx_emit(key)
        except Exception as e:
            log("WARN webSocketClosed:", e)

    def _wsx_emit(self, key):
        c = self.wsx.pop(key, None)
        if c is None:
            return
        try:
            skey = str(key)
            if "|" in skey and not skey.startswith("|"):
                raw = skey.split("|", 1)[1]
                if raw in self._wsx_main_seen:
                    # same socket already reported by the page session (e.g. dedicated worker)
                    self.ws_sse["websocket_duplicates_skipped"] += 1
                    return
            st = self.ws_sse
            st["websocket_connections"] += 1
            if c.get("target_type") != "page":
                st["websocket_child_connections"] += 1
            st["websocket_frames"] += c["frames_sent"] + c["frames_received"]
            st["websocket_frames_sent"] += c["frames_sent"]
            st["websocket_frames_received"] += c["frames_received"]
            st["websocket_frames_dropped"] += c["frames_dropped"]
            out = dict(c)
            out["frames_total"] = c["frames_sent"] + c["frames_received"]
            if not out.get("url"):
                # webSocketCreated was missed (socket opened before Network.enable on a child target):
                # rebuild scheme://host from the handshake so the connection is still identifiable
                try:
                    rh = (c.get("handshake") or {}).get("request_headers") or {}
                    host = rh.get("host") or rh.get(":authority")
                    if host:
                        sch = "wss" if str(rh.get("origin") or "").startswith("https") else "ws"
                        out["url_partial"] = f"{sch}://{host}/"
                    out["notes"] = ["URL no disponible: el socket se abrió antes de habilitar la captura en el "
                                    "target hijo; url_partial se reconstruye desde el handshake"]
                except Exception:
                    pass
            if not self.args.keep_secrets:
                out["url"] = redact_url(out.get("url") or "") or None
                hs = out.get("handshake")
                if hs:
                    hs = dict(hs)
                    for k in ("request_headers", "response_headers"):
                        if k in hs:
                            hs[k] = redact_headers(hs[k])
                    out["handshake"] = hs
            out["redacted"] = not self.args.keep_secrets
            self._ws_sse_write(out)
        except Exception as e:
            log("WARN escribir conexión WebSocket:", e)

    # ---- SSE (text/event-stream)
    def _ssex_response(self, p, child=None):
        try:
            key = p.get("requestId")
            r = p.get("response") or {}
            rh = lower_headers(r.get("headers"))
            ct = (r.get("mimeType") or "") + " " + str(rh.get("content-type") or "")
            if "event-stream" not in ct.lower() or key in self.ssex:
                return
            rec = self.records.get(key) or {}
            self._learn_offset(rec.get("wall_time"), rec.get("_ts"))
            now = round(float(rec["wall_time"]), 3) if rec.get("wall_time") else self._wall()
            rtype = p.get("type") or rec.get("resource_type") or "Other"
            s = self.ssex[key] = {
                "kind": "sse", "request_id": key, "url": r.get("url") or rec.get("url"),
                "method": rec.get("method") or "GET", "page": rec.get("page", self.current_page),
                **self._target_of(key, child), "resource_type": rtype, "status": r.get("status"),
                "status_text": r.get("statusText"), "mime_type": r.get("mimeType"),
                "request_headers": dict(rec.get("request_headers") or lower_headers(r.get("requestHeaders"))),
                "response_headers": rh, "started_ts": now, "started_iso": self._iso(now),
                "ended_ts": None, "ended_iso": None, "state": "open", "source": None,
                "events": [], "events_total": 0, "events_dropped": 0, "bytes": 0, "notes": [],
            }
            if rtype == "EventSource":
                s["source"] = "eventsource"   # Network.eventSourceMessageReceived delivers parsed events
            else:
                self._spawn(self._ssex_start_stream(key))
        except Exception as e:
            log("WARN detección SSE:", e)

    async def _ssex_start_stream(self, key):
        """fetch()/XHR-based SSE: ask Chrome to stream the body (Network.streamResourceContent, recent
        Chromium). Buffered data comes back now; later chunks arrive as Network.dataReceived.data."""
        s = self.ssex.get(key)
        if s is None:
            return
        try:
            r = await self._send_for(key, "Network.streamResourceContent", {"requestId": key})
            s["source"] = "stream"
            self._ssex_streaming.add(key)
            buf = r.get("bufferedData") or ""
            if buf:
                self._ssex_feed(key, base64.b64decode(buf).decode("utf-8", "replace"))
        except Exception as e:
            s["notes"].append(f"streamResourceContent no disponible: {str(e).splitlines()[0][:120]}; "
                              "se intentará leer el body al terminar")

    def _ssex_feed(self, key, text, ts=None):
        s = self.ssex.get(key)
        if s is None or not text or parse_sse is None:
            return
        s["bytes"] += len(text.encode("utf-8", "replace"))
        evs, left = parse_sse(self._ssex_buf.pop(key, "") + text, max_events=10**9, max_data=10**9)
        if left:
            self._ssex_buf[key] = left[-1_000_000:]
        for ev in evs:
            self._ssex_add(s, ev, ts)

    def _ssex_add(self, s, ev, ts=None):
        s["events_total"] += 1
        if len(s["events"]) >= self.args.max_ws_frames > 0:
            s["events_dropped"] += 1
            return
        data, changed = self._redact_text(ev.get("data") or "")
        cap = self.args.max_ws_payload
        cut = cap >= 0 and len(data) > cap
        out = {"event": ev.get("event") or "message", "data": data[:cap] if cut else data, "id": ev.get("id"),
               "retry": ev.get("retry")}
        if cut or ev.get("truncated"):
            out["truncated"] = True
        if ev.get("incomplete"):
            out["incomplete"] = True
        if changed:
            out["redacted"] = True
        t = self._wall(ts)
        out["ts"] = t
        out["time"] = self._iso(t)
        s["events"].append(out)

    def _ssex_es_message(self, p):
        try:
            s = self.ssex.get(p.get("requestId"))
            if s is None:
                return
            if s.get("source") != "eventsource":
                s["source"] = "eventsource"
                s["notes"] = [n for n in s["notes"] if not n.startswith("streamResourceContent")]
                self._ssex_streaming.discard(p.get("requestId"))
            data = p.get("data") or ""
            ev = {"event": p.get("eventName") or "message", "data": data, "id": p.get("eventId") or None,
                  "retry": None}
            s["bytes"] += len(data.encode("utf-8", "replace"))
            self._ssex_add(s, ev, p.get("timestamp"))
        except Exception as e:
            log("WARN evento SSE:", e)

    def _ssex_data(self, p):
        key = p.get("requestId")
        if key not in self._ssex_streaming:
            return
        try:
            if p.get("data"):
                self._ssex_feed(key, base64.b64decode(p["data"]).decode("utf-8", "replace"), p.get("timestamp"))
        except Exception as e:
            log("WARN datos SSE:", e)

    def _ssex_finished(self, p):
        key = p.get("requestId")
        s = self.ssex.get(key)
        if s is None:
            return
        s["ended_ts"] = self._wall(p.get("timestamp"))
        s["ended_iso"] = self._iso(s["ended_ts"])
        s["state"] = "finished"
        if not s["events"] and s.get("source") != "stream":
            self._spawn(self._ssex_from_body(key))
        else:
            self._ssex_emit(key)

    def _ssex_failed(self, p):
        key = p.get("requestId")
        s = self.ssex.get(key)
        if s is None:
            return
        s["ended_ts"] = self._wall(p.get("timestamp"))
        s["ended_iso"] = self._iso(s["ended_ts"])
        s["state"] = "closed" if p.get("canceled") else "failed"
        if p.get("errorText") and not p.get("canceled"):
            s["error_text"] = p.get("errorText")
        self._ssex_emit(key)

    async def _ssex_from_body(self, key):
        s = self.ssex.get(key)
        try:
            if s is not None:
                r = await self._send_for(key, "Network.getResponseBody", {"requestId": key})
                body = r.get("body") or ""
                text = base64.b64decode(body).decode("utf-8", "replace") if r.get("base64Encoded") else body
                s["source"] = s.get("source") or "body"
                self._ssex_feed(key, text + ("\n\n" if text and not text.endswith("\n\n") else ""))
        except Exception as e:
            if s is not None:
                s["notes"].append(f"body del stream no disponible: {str(e).splitlines()[0][:120]}")
        finally:
            self._ssex_emit(key)

    def _ssex_emit(self, key):
        s = self.ssex.pop(key, None)
        self._ssex_streaming.discard(key)
        left = self._ssex_buf.pop(key, "")
        if s is None:
            return
        try:
            if left.strip() and parse_sse is not None:
                evs, _ = parse_sse(left + "\n\n", max_data=10**9)
                for ev in evs:
                    ev["incomplete"] = True
                    self._ssex_add(s, ev)
            if not s.get("source"):
                s["source"] = "headers_only"
                s["notes"].append("solo se detectó el endpoint SSE (URL y headers); los eventos no estaban disponibles")
            self.ws_sse["sse_streams"] += 1
            self.ws_sse["sse_events"] += s["events_total"]
            srcs = self.ws_sse["sse_sources"]
            srcs[s["source"]] = srcs.get(s["source"], 0) + 1
            out = dict(s)
            if not out["notes"]:
                out.pop("notes")
            if not self.args.keep_secrets:
                out["url"] = redact_url(out.get("url") or "") or None
                out["request_headers"] = redact_headers(out.get("request_headers"))
                out["response_headers"] = redact_headers(out.get("response_headers"))
            out["redacted"] = not self.args.keep_secrets
            self._ws_sse_write(out)
        except Exception as e:
            log("WARN escribir stream SSE:", e)

    def _ws_sse_finalize(self):
        """Write connections/streams still open at the end of the run (state stays 'open')."""
        try:
            for key in list(self.wsx):
                self._wsx_emit(key)
            for key in list(self.ssex):
                self._ssex_emit(key)
        except Exception as e:
            log("WARN cierre de captura WS/SSE:", e)
        try:
            if self.ws_sse_out:
                self.ws_sse_out.close()
                self.ws_sse_out = None
        except Exception:
            pass

    # -------- flushing
    async def drain(self, timeout=30):
        end = time.monotonic() + timeout
        while self.pending and time.monotonic() < end:
            await asyncio.wait(list(self.pending), timeout=max(0.1, end - time.monotonic()))

    def _clean(self, rec):
        out = {k: v for k, v in rec.items() if not k.startswith("_")}
        if not self.args.keep_secrets:
            out["url"] = redact_url(out.get("url") or "")
            if out.get("redirected_to"):
                out["redirected_to"] = redact_url(out["redirected_to"])
            out["request_headers"] = redact_headers(out.get("request_headers"))
            if "response_headers" in out:
                out["response_headers"] = redact_headers(out["response_headers"])
            if out.get("post_data"):
                out["post_data"] = redact_post_data(out["post_data"], (out.get("request_headers") or {}).get("content-type"))
            out["redacted"] = True
        return out

    def flush(self, final=False):
        n = 0
        for key, rec in sorted(self.records.items(), key=lambda kv: kv[1]["seq"]):
            if key in self.written:
                continue
            if not final and (rec["state"] == "pending" or rec.get("_busy")):
                continue
            if final and rec["state"] == "pending":
                rec["state"] = "incomplete"
            if self._is_child_duplicate(key, rec):
                self.written.add(key)
                self.auto_attach["duplicates_skipped"] += 1
                continue
            self.req_out.write(json.dumps(self._clean(rec), ensure_ascii=False) + "\n")
            self.written.add(key)
            n += 1
        self.req_out.flush()
        # free memory for written records
        for key in list(self.written):
            if key in self.records and self.records[key]["state"] != "pending":
                self.records.pop(key, None)
        return n

    def _is_child_duplicate(self, key, rec) -> bool:
        """A child-target record that is the same request the main session already reported."""
        try:
            if "|" not in str(key):
                return False
            raw = str(key).split("|", 1)[1].split("#", 1)[0]
            if raw in self._main_rids:
                return True
            if rec.get("target_type") == "service_worker" and (rec.get("method"), rec.get("url")) in self._sw_served:
                # the page-side request (from_service_worker=true) is already recorded; keep the SW's
                # own network fetch out of requests.jsonl to avoid double counting
                return True
        except Exception:
            pass
        return False

    def close(self):
        self._ws_sse_finalize()
        self.req_out.close()
        if self.ws_out:
            self.ws_out.close()


def _ext_for(mime: str | None, path: str) -> str:
    m = (mime or "").lower()
    table = [("json", ".json"), ("graphql", ".json"), ("html", ".html"), ("javascript", ".js"), ("css", ".css"),
             ("xml", ".xml"), ("svg", ".svg"), ("png", ".png"), ("jpeg", ".jpg"), ("gif", ".gif"), ("webp", ".webp"),
             ("csv", ".csv"), ("text/plain", ".txt"), ("event-stream", ".txt"), ("woff2", ".woff2"), ("font", ".font"),
             ("protobuf", ".pb")]
    mm = re.search(r"\.([A-Za-z0-9]{1,5})$", path)
    path_ext = "." + mm.group(1).lower() if mm else None
    for k, ext in table:
        if k in m:
            if path_ext == ext or (ext == ".html" and path_ext in (".htm", ".html")) or (ext == ".jpg" and path_ext == ".jpeg"):
                return ""  # path slug already ends with the extension
            return ext
    return "" if path_ext else ".bin"


def capabilities_info(cap=None) -> dict:
    """Describe optional capabilities of this build (recorded in run_meta.json)."""
    def has(mod):
        try:
            __import__(mod)
            return True
        except Exception:
            return False
    aa = (cap.auto_attach if cap is not None else {}) or {}
    return {
        "auto_attach_child_targets": aa.get("status") == "ok",
        "auto_attach_mode": aa.get("mode"),
        "body_decoding": ["gzip", "deflate"] + (["br"] if has("brotli") else []) + (["zstd"] if has("zstandard") else []),
        "body_kind_detection": ["json", "grpc", "protobuf"],
        "ws_sse_capture": bool(getattr(cap, "ws_enabled", False)) if cap is not None else True,
        "session_cache": load_session is not None,
        "analysis": ["graphql_persisted_queries", "auth_flow", "endpoint_roles", "pagination_confirmation",
                     "rate_limit", "anti_bot", "openapi_export"],
    }


# ============================================================ robots

class Robots:
    def __init__(self, ua: str, enabled: bool):
        self.ua = ua
        self.enabled = enabled
        self.cache: dict[str, RobotFileParser | None] = {}

    def _get(self, url):
        o = origin(url)
        if o not in self.cache:
            rp = None
            try:
                r = httpx.get(o + "/robots.txt", headers={"User-Agent": self.ua}, timeout=10, follow_redirects=True)
                if r.status_code == 200 and "html" not in r.headers.get("content-type", ""):
                    rp = RobotFileParser()
                    rp.parse(r.text.splitlines())
            except Exception as e:
                log(f"robots.txt fetch failed for {o}: {e}")
            self.cache[o] = rp
        return self.cache[o]

    def allowed(self, url) -> bool:
        if not self.enabled:
            return True
        rp = self._get(url)
        return True if rp is None else rp.can_fetch(self.ua, url)

    def crawl_delay(self, url) -> float:
        if not self.enabled:
            return 0.0
        rp = self._get(url)
        try:
            d = rp.crawl_delay(self.ua) if rp else None
        except Exception:
            d = None
        return float(d or 0)


# ============================================================ actions

def load_actions(path: str | None, start_url: str) -> list[dict]:
    """Actions file formats:
       [ {step}, ... ]                                   -> run on the start page only
       [ {"match": "<url regex>", "steps": [...]}, ...]  -> run on every page whose URL matches
       {"steps": [...], "match": "..."}                  -> single rule
    """
    if not path:
        return []
    data = json.loads(Path(path).read_text())
    if isinstance(data, dict):
        data = [data]
    if data and all(isinstance(x, dict) and "action" in x for x in data):
        return [{"match": None, "exact": start_url, "steps": data}]
    rules = []
    for r in data:
        rules.append({"match": r.get("match"), "exact": None if r.get("match") else start_url,
                      "steps": r.get("steps", [])})
    return rules


async def wait_idle(page, timeout_ms):
    try:
        await page.wait_for_load_state("networkidle", timeout=timeout_ms)
        return True
    except Exception:
        return False


async def do_scroll(page, times, pause_ms, idle_ms):
    stable = 0
    js_h = "() => (document.scrollingElement || document.body || document.documentElement).scrollHeight"
    done = 0
    for _ in range(times):
        h1 = await page.evaluate(js_h)
        await page.evaluate("() => window.scrollTo(0, (document.scrollingElement || document.body).scrollHeight)")
        try:
            await page.mouse.wheel(0, 4000)
        except Exception:
            pass
        await wait_idle(page, idle_ms)
        await page.wait_for_timeout(pause_ms)
        done += 1
        h2 = await page.evaluate(js_h)
        if h2 <= h1:
            stable += 1
            if stable >= 2:
                break
        else:
            stable = 0
    return done


async def run_steps(page, steps, args, errors: list):
    for i, st in enumerate(steps):
        a = (st.get("action") or "").lower()
        sel = st.get("selector")
        tmo = int(st.get("timeout", 10000))
        rep = int(st.get("repeat", 1))
        for n in range(rep):
            try:
                if a == "click":
                    await page.click(sel, timeout=tmo)
                elif a == "fill":
                    await page.fill(sel, str(st.get("value", "")), timeout=tmo)
                elif a == "type":
                    await page.type(sel, str(st.get("value", "")), delay=int(st.get("delay", 40)), timeout=tmo)
                elif a == "press":
                    await page.press(sel or "body", st["key"], timeout=tmo)
                elif a == "select":
                    await page.select_option(sel, st.get("value"), timeout=tmo)
                elif a == "hover":
                    await page.hover(sel, timeout=tmo)
                elif a == "check":
                    await page.check(sel, timeout=tmo)
                elif a == "wait":
                    await page.wait_for_timeout(int(st.get("ms", 1000)))
                elif a == "wait_for_selector":
                    await page.wait_for_selector(sel, timeout=tmo)
                elif a == "wait_for_idle":
                    await wait_idle(page, tmo)
                elif a == "scroll":
                    await do_scroll(page, int(st.get("times", 5)), args.scroll_pause, args.idle_timeout)
                elif a == "evaluate":
                    await page.evaluate(st["script"])
                elif a == "goto":
                    await page.goto(st["url"], timeout=args.timeout)
                elif a == "screenshot":
                    await page.screenshot(path=str(Path(args._run_dir) / st.get("path", f"action_{i}.png")), full_page=True)
                else:
                    raise ValueError(f"unknown action {a!r}")
            except Exception as e:
                msg = f"step {i} ({a} {sel or ''}) #{n + 1}: {str(e).splitlines()[0][:200]}"
                if not (st.get("optional") or n > 0):
                    errors.append(msg)
                log("action:", msg)
                break
            await wait_idle(page, min(args.idle_timeout, 5000))
            await page.wait_for_timeout(int(st.get("after_ms", 300)))


# ============================================================ crawler

def in_scope(url, start, args, inc, exc) -> bool:
    su, uu = urlsplit(start), urlsplit(url)
    if args.same_origin:
        if args.allow_subdomains:
            b = base_host(su.hostname or "")
            h = (uu.hostname or "").lower()
            if not (h == b or h.endswith("." + b)):
                return False
        elif origin(url) != origin(start):
            return False
    if SKIP_EXT.search(uu.path or ""):
        return False
    if inc and not any(r.search(url) for r in inc):
        return False
    if exc and any(r.search(url) for r in exc):
        return False
    return True


def redact_har(path: Path):
    try:
        har = json.loads(path.read_text(encoding="utf-8"))
    except Exception as e:
        log("WARN could not redact HAR:", e)
        return
    for ent in har.get("log", {}).get("entries", []):
        for part in ("request", "response"):
            o = ent.get(part) or {}
            for h in o.get("headers", []):
                if is_sensitive_header(h.get("name", "")):
                    h["value"] = REDACTED
            for c in o.get("cookies", []):
                c["value"] = REDACTED
            if part == "request":
                o["url"] = redact_url(o.get("url", ""))
                for q in o.get("queryString", []):
                    if is_sensitive_field(q.get("name", "")):
                        q["value"] = REDACTED
                pd = o.get("postData")
                if pd and pd.get("text"):
                    pd["text"] = redact_post_data(pd["text"], pd.get("mimeType"))
                for prm in (pd or {}).get("params", []) or []:
                    if is_sensitive_field(prm.get("name", "")):
                        prm["value"] = REDACTED
    path.write_text(json.dumps(har, ensure_ascii=False), encoding="utf-8")


# ============================================================ session cache (login / captcha reuse)

_CHALLENGE_STATUSES = (401, 403, 407, 429, 503)


def _fmt_age(sec) -> str:
    try:
        sec = int(sec or 0)
        d, rem = divmod(sec, 86400)
        h, rem = divmod(rem, 3600)
        m, s_ = divmod(rem, 60)
        return f"{d}d {h}h" if d else (f"{h}h {m:02d}m" if h else f"{m}m {s_:02d}s")
    except Exception:
        return "?"


def _state_fingerprint(st) -> str:
    """Hash (never the values themselves) of cookies + localStorage, to detect a changed session."""
    import hashlib
    try:
        ck = sorted((c.get("name"), c.get("value"), c.get("domain"), c.get("path")) for c in (st or {}).get("cookies") or [])
        ls = sorted((o.get("origin"), i.get("name"), i.get("value")) for o in (st or {}).get("origins") or []
                    for i in o.get("localStorage") or [])
        return hashlib.sha256(json.dumps([ck, ls], default=str).encode()).hexdigest()
    except Exception:
        return ""


def _session_prepare(start, args, ctx_kw, sess):
    """--session-cache: load a valid cached storage_state into the new context. Never raises."""
    try:
        if load_session is None:
            sess["status"] = "unavailable"
            return
        dom = session_domain(start)
        sess.update(domain=dom, ttl_s=session_ttl())
        if args.storage_state:
            sess.update(status="skipped", note="--storage-state explícito tiene prioridad sobre la caché")
            log("caché de sesión: se usa el --storage-state explícito; la caché no se carga (se actualizará al final)")
            return
        info = load_session(dom)
        sess["status"] = info.get("status")
        sess["path"] = info.get("path")
        for k in ("age_s", "saved_iso", "expired_cookies_dropped", "error"):
            if k in info:
                sess[k] = info[k]
        if info.get("status") == "hit":
            ctx_kw["storage_state"] = info["storage_state"]
            summ = info.get("summary") or {}
            sess["loaded"] = True
            sess["loaded_summary"] = summ
            sess["_loaded_fp"] = _state_fingerprint(info["storage_state"])
            log(f"caché de sesión: HIT para {dom} (edad {_fmt_age(info.get('age_s'))}, {summ.get('cookies', 0)} cookies, "
                f"{summ.get('local_storage_keys', 0)} claves localStorage) <- {info.get('path')}")
        else:
            why = {"miss": "no hay sesión guardada",
                   "expired": f"sesión expirada (edad {_fmt_age(info.get('age_s'))}, TTL {_fmt_age(info.get('ttl_s'))})",
                   "corrupt": "archivo de caché ilegible, se ignora",
                   "empty": "la sesión guardada no tiene cookies vigentes"}.get(info.get("status"), info.get("status"))
            log(f"caché de sesión: {str(info.get('status')).upper()} para {dom} ({why}); se inicia sin sesión")
    except Exception as e:
        sess.update(status="error", error=str(e)[:200])
        log("WARN caché de sesión (carga):", e)


async def _human_pause(page, args, info, sess):
    """--human-pause: let a human solve login/captcha on the first page before crawling on."""
    try:
        if sess.get("loaded") and info.get("status") not in _CHALLENGE_STATUSES:
            sess["human_pause"] = "omitida: sesión válida cargada desde la caché"
            log("pausa humana omitida: se cargó una sesión válida desde la caché")
            return
        if not args.headed:
            log("AVISO: --human-pause sin --headed; no hay ventana visible para resolver login/captcha")
        secs = args.human_pause or 0
        if secs > 0:
            log(f"pausa humana: resuelve el login/captcha en el navegador; se continúa en {secs:g} s...")
            await page.wait_for_timeout(secs * 1000)
        elif sys.stdin is not None and sys.stdin.isatty():
            log("pausa humana: resuelve el login/captcha en la ventana del navegador y presiona Enter aquí para continuar...")
            await asyncio.get_running_loop().run_in_executor(None, sys.stdin.readline)
        else:
            log("pausa humana: stdin no es interactivo; se esperan 60 s")
            await page.wait_for_timeout(60000)
        await wait_idle(page, args.idle_timeout)
        sess["human_step"] = True
        sess["human_pause"] = "completada"
        info["human_pause"] = True
    except Exception as e:
        log("WARN pausa humana:", e)


async def _session_finish(context, start, args, pages, sess):
    """--session-cache: save the resolved session at the end of the run when it is worth it. Never raises."""
    try:
        if save_session is None:
            return
        st = await context.storage_state()
        summ = session_summary(st)
        sess["final_summary"] = {k: summ.get(k) for k in ("cookies", "origins", "local_storage_keys")}
        last = next((p for p in reversed(pages) if not p.get("skipped")), None)
        last_status = (last or {}).get("status")
        reason = skip = None
        if not summ.get("cookies") and not summ.get("local_storage_keys"):
            skip = "no hay cookies ni localStorage que guardar"
        elif sess.get("human_step"):
            reason = "login/captcha resuelto por el humano (--human-pause)"
        elif last is None or last_status in _CHALLENGE_STATUSES:
            skip = f"la última página respondió {last_status}: parece un login/desafío sin resolver"
            if sess.get("loaded"):
                sess["note"] = "la sesión en caché podría estar vencida en el servidor (usa --human-pause para renovarla)"
        elif sess.get("loaded") and _state_fingerprint(st) == sess.get("_loaded_fp"):
            skip = "la sesión no cambió; se conserva la marca de tiempo original"
        elif sess.get("loaded"):
            reason = "sesión renovada (cookies/localStorage actualizados en esta corrida)"
        elif args.storage_state:
            reason = "importada desde --storage-state"
        else:
            reason = "sesión nueva obtenida en esta corrida"
        if skip:
            sess.update(saved=False, save_skipped=skip)
            log(f"caché de sesión: no se guarda ({skip})")
            return
        r = save_session(sess.get("domain") or session_domain(start), st,
                         extra={"start_url": redact_url(start), "reason": reason,
                                "human_step": bool(sess.get("human_step")), "saved_by": "mapper.py"})
        if r.get("ok"):
            sess.update(saved=True, save_reason=reason, path=r.get("path"), saved_iso=r.get("saved_iso"))
            log(f"caché de sesión: guardada ({reason}; {summ.get('cookies', 0)} cookies) -> {r.get('path')}")
        else:
            sess.update(saved=False, save_error=r.get("error"))
            log("WARN caché de sesión: no se pudo guardar:", r.get("error"))
    except Exception as e:
        sess.update(saved=False, save_error=str(e)[:200])
        log("WARN caché de sesión (guardado):", e)


async def crawl(args):
    start = norm_link(args.url)
    if not start:
        raise SystemExit("start URL must be http(s)")
    guard_target(start, "url")
    host = urlsplit(start).hostname or "site"
    if args.out:
        run_dir = Path(args.out).resolve()
    else:
        run_dir = Path(args.out_root).resolve() / f"{slugify(host)}-{datetime.now().strftime('%Y%m%d-%H%M%S')}"
    run_dir.mkdir(parents=True, exist_ok=True)
    args._run_dir = str(run_dir)
    if args.screenshots:
        (run_dir / "screenshots").mkdir(exist_ok=True)
    log("run dir:", run_dir)

    inc = [re.compile(x) for x in args.include or []]
    exc = [re.compile(x) for x in args.exclude or []]
    rules = load_actions(args.actions, start)
    stop = {"flag": False}

    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, lambda: (stop.__setitem__("flag", True), log("stop requested; finishing current page...")))
        except (NotImplementedError, RuntimeError):
            pass

    cap = Capture(run_dir, args)
    pages: list[dict] = []
    meta = {"tool": "web-network-mapper", "start_url": start, "started_at": now_iso(),
            "args": {k: v for k, v in vars(args).items() if not k.startswith("_")}}
    t_start = time.monotonic()
    sess = {"enabled": bool(getattr(args, "session_cache", False))}

    async with async_playwright() as pw:
        launch_kw = {"headless": not args.headed}
        if args.proxy:
            launch_kw["proxy"] = {"server": args.proxy}
        if args.browser_channel:
            launch_kw["channel"] = args.browser_channel
        browser = await pw.chromium.launch(**launch_kw)
        ctx_kw = {"ignore_https_errors": args.ignore_https_errors,
                  "viewport": {"width": args.viewport[0], "height": args.viewport[1]}}
        if not args.no_har:
            ctx_kw["record_har_path"] = str(run_dir / "network.har")
            ctx_kw["record_har_content"] = args.har_content
        if args.user_agent:
            ctx_kw["user_agent"] = args.user_agent
        if args.storage_state:
            ctx_kw["storage_state"] = args.storage_state
        if args.locale:
            ctx_kw["locale"] = args.locale
        extra = parse_header_args(args.header)
        if extra:
            ctx_kw["extra_http_headers"] = extra
        if sess["enabled"]:
            _session_prepare(start, args, ctx_kw, sess)
        try:
            context = await browser.new_context(**ctx_kw)
        except Exception as e:
            if not sess.get("loaded"):
                raise
            log("WARN caché de sesión: Playwright rechazó el storage_state guardado; se continúa sin sesión:",
                str(e).splitlines()[0][:200])
            ctx_kw.pop("storage_state", None)
            sess.update(status="invalid", loaded=False, error=str(e).splitlines()[0][:200])
            context = await browser.new_context(**ctx_kw)
        if args.cookies:
            cks = load_cookies_file(args.cookies)
            await context.add_cookies(cks)
            log(f"loaded {len(cks)} cookies from {args.cookies}")
        if args.block:
            blocked = {x.strip() for x in args.block.split(",") if x.strip()}

            async def _route(route):
                if route.request.resource_type in blocked:
                    await route.abort()
                else:
                    await route.continue_()
            await context.route("**/*", _route)

        page = await context.new_page()

        async def _popup(p):
            if p is not page:
                log("closing popup/new tab:", p.url)
                try:
                    await p.close()
                except Exception:
                    pass
        context.on("page", lambda p: asyncio.ensure_future(_popup(p)))
        await cap.attach(page)
        ua = args.user_agent or await page.evaluate("navigator.userAgent")
        meta["user_agent"] = ua
        robots = Robots(ua, not args.ignore_robots)
        if not robots.allowed(start):
            log("start URL is disallowed by robots.txt; use --ignore-robots if you are permitted to crawl it")
            await context.close()
            await browser.close()
            cap.close()
            return run_dir, 2

        queue: list[tuple[str, int]] = [(start, 0)]
        seen = {start}
        visited = 0
        try:
            while queue and visited < args.max_pages and not stop["flag"]:
                if args.max_time and time.monotonic() - t_start > args.max_time:
                    log("max-time reached")
                    break
                url, depth = queue.pop(0)
                if not robots.allowed(url):
                    log("robots.txt disallows", url)
                    pages.append({"url": url, "depth": depth, "skipped": "robots.txt"})
                    continue
                if visited > 0:
                    d = max(args.delay, min(robots.crawl_delay(url), 30.0))
                    await asyncio.sleep(d)
                visited += 1
                log(f"[{visited}/{args.max_pages}] depth={depth} {url}")
                info = {"url": url, "depth": depth, "visited_at": now_iso()}
                cap.current_page = url
                seq_before = cap.seq
                t0 = time.monotonic()
                try:
                    resp = await page.goto(url, wait_until="load", timeout=args.timeout)
                    info["status"] = resp.status if resp else None
                    info["mime_type"] = (resp.headers.get("content-type") if resp else None)
                except Exception as e:
                    info["error"] = str(e).splitlines()[0][:300]
                    log("  navigation error:", info["error"])
                    if page.is_closed():
                        page = await context.new_page()
                        await cap.attach(page)
                if "error" not in info or not page.is_closed():
                    await wait_idle(page, args.idle_timeout)
                    if visited == 1 and getattr(args, "human_pause", None) is not None:
                        await _human_pause(page, args, info, sess)
                    if args.wait:
                        await page.wait_for_timeout(args.wait)
                    errors: list[str] = []
                    for r in rules:
                        if (r["exact"] and r["exact"] == url) or (r["match"] and re.search(r["match"], url)):
                            await run_steps(page, r["steps"], args, errors)
                    if errors:
                        info["action_errors"] = errors
                    if args.scroll:
                        info["scrolls"] = await do_scroll(page, args.scroll, args.scroll_pause, args.idle_timeout)
                        await wait_idle(page, args.idle_timeout)
                    try:
                        info["final_url"] = page.url
                        fu = norm_link(page.url)
                        if fu and fu != url:
                            seen.add(fu)  # don't re-visit redirect targets
                        info["title"] = await page.title()
                        hrefs = await page.eval_on_selector_all("a[href]", "els => els.map(e => e.href)")
                    except Exception as e:
                        hrefs = []
                        info.setdefault("error", f"extract failed: {e}"[:300])
                    if args.screenshots:
                        try:
                            upath = urlsplit(url).path
                            shot = f"screenshots/{visited:03d}_{slugify(upath, 60) if upath.strip('/') else 'root'}.png"
                            await page.screenshot(path=str(run_dir / shot), full_page=True)
                            info["screenshot"] = shot
                        except Exception as e:
                            log("  screenshot failed:", e)
                    links, in_scope_links = [], []
                    for h in hrefs:
                        n = norm_link(h)
                        if n and n not in links:
                            links.append(n)
                    for n in links:
                        if in_scope(n, start, args, inc, exc):
                            in_scope_links.append(n)
                            if n not in seen and depth + 1 <= args.depth:
                                seen.add(n)
                                queue.append((n, depth + 1))
                    info["links_total"] = len(links)
                    info["links_in_scope"] = len(in_scope_links)
                    info["links"] = (in_scope_links if not args.keep_all_links else links)[:1000]
                await cap.drain()
                info["load_ms"] = round((time.monotonic() - t0) * 1000)
                info["requests_seq_range"] = [seq_before + 1, cap.seq]
                cap.flush()
                pages.append(info)
                log(f"  status={info.get('status')} title={info.get('title', '')[:60]!r} links={info.get('links_in_scope', 0)} "
                    f"requests={cap.seq - seq_before} queue={len(queue)}")
        finally:
            await cap.drain(10)
            cap.current_page = None
            if sess["enabled"]:
                await _session_finish(context, start, args, pages, sess)
            if args.save_storage_state:
                try:
                    await context.storage_state(path=args.save_storage_state)
                    log("saved storage state ->", args.save_storage_state)
                except Exception as e:
                    log("WARN could not save storage state:", e)
            try:
                await context.close()   # writes the HAR
            except Exception as e:
                log("WARN context close:", e)
            await browser.close()
            cap.flush(final=True)
            cap.close()

    if not args.no_har and not args.keep_secrets and (run_dir / "network.har").exists():
        redact_har(run_dir / "network.har")
    if not args.keep_secrets:
        for p in pages:
            for k in ("url", "final_url"):
                if p.get(k):
                    p[k] = redact_url(p[k])
    (run_dir / "pages.json").write_text(json.dumps(pages, indent=2, ensure_ascii=False))
    meta.update({"finished_at": now_iso(), "elapsed_s": round(time.monotonic() - t_start, 1),
                 "pages_visited": visited, "queue_remaining": len(queue), "stats": cap.stats,
                 "redacted": not args.keep_secrets})
    try:
        meta["auto_attach"] = cap.auto_attach
        meta["capabilities"] = capabilities_info(cap)
    except Exception as e:
        meta["capabilities_error"] = str(e)[:200]
    try:
        meta["ws_sse"] = cap.ws_sse
        meta["session_cache"] = {k: v for k, v in sess.items() if not k.startswith("_")}
    except Exception as e:
        meta["ws_sse_error"] = str(e)[:200]
    (run_dir / "run_meta.json").write_text(json.dumps(meta, indent=2, ensure_ascii=False))
    log("building api map...")
    summary = analyze.build(run_dir, include_documents=args.map_documents, emit_curl=args.emit_curl,
                            curl_redact=args.curl_redact)
    log(f"done: {visited} pages, {cap.stats['requests']} requests, {cap.stats['bodies_saved']} bodies, "
        f"{summary['endpoints']} endpoints ({summary['data_endpoints']} likely data) -> {run_dir}")
    if summary.get("curls_file"):
        log("curl commands for all requests:", summary["curls_file"])
    print(str(run_dir))
    return run_dir, 0


def build_parser():
    ap = argparse.ArgumentParser(
        prog="mapper.py",
        description="Crawl pages with headless Chromium, capture DevTools Network traffic via CDP, and build a site map + API map.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    ap.add_argument("url", help="start URL")
    g = ap.add_argument_group("crawl")
    g.add_argument("--max-pages", type=int, default=20, help="max pages to visit")
    g.add_argument("--depth", type=int, default=2, help="max link depth from start URL (0 = start page only)")
    g.add_argument("--same-origin", dest="same_origin", action="store_true", default=True, help="only follow links on the start origin")
    g.add_argument("--no-same-origin", dest="same_origin", action="store_false", help="follow links to any host (bounded by --max-pages)")
    g.add_argument("--allow-subdomains", action="store_true", help="with --same-origin, also allow subdomains of the start host")
    g.add_argument("--include", action="append", metavar="REGEX", help="only follow links matching (repeatable)")
    g.add_argument("--exclude", action="append", metavar="REGEX", help="never follow links matching (repeatable)")
    g.add_argument("--delay", type=float, default=1.5, help="seconds between page loads (politeness)")
    g.add_argument("--ignore-robots", action="store_true", help="do not honour robots.txt (Disallow / Crawl-delay)")
    g.add_argument("--max-time", type=float, default=0, help="stop crawling after N seconds (0 = no limit)")
    g.add_argument("--keep-all-links", action="store_true", help="store all links in pages.json, not just in-scope ones")
    g = ap.add_argument_group("page behaviour")
    g.add_argument("--wait", type=int, default=1000, help="extra ms to wait after networkidle on each page")
    g.add_argument("--idle-timeout", type=int, default=10000, help="max ms to wait for networkidle")
    g.add_argument("--timeout", type=int, default=30000, help="navigation timeout ms")
    g.add_argument("--scroll", type=int, nargs="?", const=10, default=0, metavar="N",
                   help="scroll to bottom up to N times per page to trigger lazy loading (flag alone = 10)")
    g.add_argument("--scroll-pause", type=int, default=800, help="ms to pause after each scroll")
    g.add_argument("--actions", metavar="FILE", help="JSON file of clicks/typing to run (see README)")
    g.add_argument("--screenshots", action="store_true", help="save a full-page screenshot per page")
    g.add_argument("--block", metavar="TYPES", help="abort resource types, e.g. image,font,media")
    g = ap.add_argument_group("browser / session")
    g.add_argument("--headed", action="store_true", help="show the browser window (needs a display)")
    g.add_argument("--user-agent", help="override User-Agent")
    g.add_argument("--header", action="append", metavar="'Name: value'", help="extra HTTP header on every request (repeatable)")
    g.add_argument("--cookies", metavar="FILE", help="cookies JSON (list / extension export / storage state) or Netscape cookies.txt")
    g.add_argument("--storage-state", metavar="FILE", help="Playwright storage_state JSON (cookies + localStorage)")
    g.add_argument("--save-storage-state", metavar="FILE", help="write cookies+localStorage at the end (for replay --storage-state)")
    g.add_argument("--proxy", help="proxy server, e.g. http://host:3128")
    g.add_argument("--locale", help="browser locale, e.g. en-US")
    g.add_argument("--viewport", type=int, nargs=2, default=[1366, 900], metavar=("W", "H"))
    g.add_argument("--ignore-https-errors", action="store_true")
    g.add_argument("--disable-cache", action="store_true", help="disable browser cache (Network.setCacheDisabled)")
    g.add_argument("--browser-channel", help="use installed browser channel, e.g. chrome (default: bundled chromium)")
    g.add_argument("--no-auto-attach", dest="auto_attach", action="store_false", default=True,
                   help="do not auto-attach to iframes/workers/service workers (capture main page session only)")
    g.add_argument("--session-cache", dest="session_cache", action="store_true", default=False,
                   help="reutilizar/guardar la sesión resuelta (cookies + storage_state) por dominio en "
                        "~/.cache/wnm/sessions/ (TTL: env WNM_SESSION_TTL, 24h por defecto)")
    g.add_argument("--no-session-cache", dest="session_cache", action="store_false",
                   help="no usar la caché de sesión (comportamiento por defecto)")
    g.add_argument("--human-pause", type=float, nargs="?", const=0, default=None, metavar="SECONDS",
                   help="tras cargar la primera página, pausar para que un humano resuelva login/captcha "
                        "(solo el flag = esperar Enter; N = esperar N s). Se omite si hubo HIT de caché")
    g = ap.add_argument_group("capture / output")
    g.add_argument("--out-root", default=str(TOOL_DIR / "runs"), help="parent dir for run folders")
    g.add_argument("--out", help="exact output dir (overrides --out-root naming)")
    g.add_argument("--max-body-bytes", type=int, default=5_000_000, help="cap per saved body (0 = save none, -1 = unlimited)")
    g.add_argument("--body-types", default=DEFAULT_BODY_TYPES, help="CDP resource types whose bodies are saved (JSON-ish mimes always saved)")
    g.add_argument("--all-bodies", action="store_true", help="save bodies of every response (scripts, css, images ...)")
    g.add_argument("--no-bodies", action="store_true", help="do not save any response bodies")
    g.add_argument("--max-ws-payload", type=int, default=65536, help="cap per WebSocket/SSE message stored")
    g.add_argument("--max-ws-frames", type=int, default=5000,
                   help="máximo de frames WebSocket / eventos SSE guardados por conexión en ws_sse.jsonl (0 = sin límite)")
    g.add_argument("--no-ws", action="store_true",
                   help="no capturar WebSocket ni SSE (ni ws_sse.jsonl ni websockets.jsonl)")
    g.add_argument("--har-content", choices=["embed", "omit"], default="embed", help="HAR response content mode")
    g.add_argument("--no-har", action="store_true", help="skip HAR recording")
    g.add_argument("--map-documents", action="store_true", help="also list HTML document requests in api_map")
    g.add_argument("--emit-curl", nargs="?", const="all", choices=["all", "api", "nonstatic"], metavar="SCOPE",
                   help="write curls.sh with every captured request as a one-line curl (dedup). SCOPE: all (default) | api | nonstatic")
    g.add_argument("--curl-redact", action="store_true",
                   help="with --keep-secrets: still use $VARIABLE placeholders in generated curl commands")
    g.add_argument("--keep-secrets", action="store_true",
                   help="do NOT redact Authorization/Cookie/token values in saved outputs or generated curl commands (needed for replay of authed APIs)")
    return ap


def main(argv=None):
    args = build_parser().parse_args(argv)
    if args.max_pages < 1:
        raise SystemExit("--max-pages must be >= 1")
    _run_dir, code = asyncio.run(crawl(args))
    sys.exit(code)


if __name__ == "__main__":
    main()
