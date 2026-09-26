#!/usr/bin/env python3
"""Local fixture site for self-tests: XHR JSON with auth header, GraphQL POST with cursor pagination,
form POST, uuid/numeric ids, JSON-LD, robots.txt, and a tiny WebSocket echo endpoint.
Usage: fixture_server.py [port]   (default 8765, binds 127.0.0.1)"""
import base64
import hashlib
import json
import socketserver
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

TOKEN = "Bearer secret-token-123"
USERS = [{"id": i, "name": f"user{i}", "email": f"u{i}@example.test"} for i in range(1, 26)]

INDEX = """<!doctype html><html><head><title>Fixture Home</title></head><body>
<h1>Fixture</h1><a href="/products/42">p42</a> <a href="/products/43">p43</a> <a href="/private/x">private</a>
<a href="https://example.org/offsite">offsite</a> <a href="/file.pdf">pdf</a>
<ul id="items"></ul><button id="more" onclick="loadMore()">more</button>
<script>
let page = 1;
async function loadMore(){
  const r = await fetch('/api/v1/items?page=' + page + '&limit=5', {headers: {'Authorization': '%s', 'X-Client': 'fixture'}});
  const j = await r.json(); page++;
  j.items.forEach(i => { const li = document.createElement('li'); li.textContent = i.title; document.getElementById('items').appendChild(li); });
}
loadMore();
fetch('/graphql', {method: 'POST', headers: {'Content-Type': 'application/json'},
  body: JSON.stringify({operationName: 'ListUsers', query: 'query ListUsers($first: Int, $after: String) { users(first: $first, after: $after) { edges { node { id name } } pageInfo { hasNextPage endCursor } } }', variables: {first: 10, after: null}})});
fetch('/api/login', {method: 'POST', headers: {'Content-Type': 'application/x-www-form-urlencoded'}, body: 'user=bob&password=hunter2'});
const ws = new WebSocket('ws://' + location.host + '/ws'); ws.onopen = () => ws.send('ping from page');
</script></body></html>""" % TOKEN

PRODUCT = """<!doctype html><html><head><title>Product %(id)s</title>
<script type="application/ld+json">{"@type": "Product", "name": "P%(id)s"}</script></head><body>
<a href="/">home</a><script>
fetch('/api/v1/products/%(id)s').then(r => r.json());
fetch('/api/v1/orders/3f2b8c1e-9a4d-4e2f-8b6a-1c2d3e4f5a6b?session_token=abc123').then(r => r.json());
</script></body></html>"""


class H(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):
        pass

    def _send(self, code, body, ctype="application/json"):
        if not isinstance(body, (bytes, str)):
            body = json.dumps(body)
        if isinstance(body, str):
            body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Set-Cookie", "sid=very-secret-session; Path=/")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        u = urlsplit(self.path)
        q = parse_qs(u.query)
        if u.path == "/ws" and self.headers.get("Upgrade", "").lower() == "websocket":
            return self._ws()
        if u.path == "/":
            return self._send(200, INDEX, "text/html")
        if u.path == "/robots.txt":
            return self._send(200, "User-agent: *\nDisallow: /private\n", "text/plain")
        if u.path.startswith("/products/"):
            return self._send(200, PRODUCT % {"id": u.path.split("/")[-1]}, "text/html")
        if u.path == "/api/v1/items":
            if self.headers.get("Authorization") != TOKEN:
                return self._send(401, {"error": "unauthorized"})
            page = int(q.get("page", ["1"])[0])
            limit = int(q.get("limit", ["5"])[0])
            items = [{"id": (page - 1) * limit + i, "title": f"Item {(page - 1) * limit + i}", "price": {"amount": i * 1.5, "cur": "USD"},
                      "tags": ["a", "b"]} for i in range(1, limit + 1)] if page <= 4 else []
            return self._send(200, {"items": items, "page": page, "has_more": page < 4, "total": 4 * limit})
        if u.path.startswith("/api/v1/products/"):
            return self._send(200, {"id": u.path.split("/")[-1], "name": "Widget", "stock": 3})
        if u.path.startswith("/api/v1/orders/"):
            return self._send(200, {"order": u.path.split("/")[-1], "lines": [{"sku": "a", "qty": 1}, {"sku": "b", "qty": 2}]})
        return self._send(404, {"error": "not found"})

    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0))
        raw = self.rfile.read(n).decode()
        u = urlsplit(self.path)
        if u.path == "/graphql":
            b = json.loads(raw)
            v = b.get("variables") or {}
            first = int(v.get("first") or 10)
            after = int(v.get("after") or 0)
            chunk = USERS[after:after + first]
            end = after + len(chunk)
            return self._send(200, {"data": {"users": {"edges": [{"node": x} for x in chunk],
                                                       "pageInfo": {"hasNextPage": end < len(USERS), "endCursor": str(end)}}}})
        if u.path == "/api/login":
            return self._send(200, {"ok": True, "token": "jwt-abc"})
        return self._send(404, {"error": "not found"})

    def _ws(self):
        key = self.headers["Sec-WebSocket-Key"]
        acc = base64.b64encode(hashlib.sha1((key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode()).digest()).decode()
        self.send_response(101)
        self.send_header("Upgrade", "websocket")
        self.send_header("Connection", "Upgrade")
        self.send_header("Sec-WebSocket-Accept", acc)
        self.end_headers()
        self.wfile.flush()

        def send(txt):
            d = txt.encode()
            self.wfile.write(bytes([0x81, len(d)]) + d)
            self.wfile.flush()
        send("hello from server")
        try:
            hdr = self.rfile.read(2)
            ln = hdr[1] & 0x7F
            mask = self.rfile.read(4)
            data = bytes(b ^ mask[i % 4] for i, b in enumerate(self.rfile.read(ln)))
            send("echo: " + data.decode())
            self.rfile.read(2)  # wait for close / EOF
        except Exception:
            pass
        self.close_connection = True


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8765
    socketserver.TCPServer.allow_reuse_address = True
    ThreadingHTTPServer.daemon_threads = True
    srv = ThreadingHTTPServer(("127.0.0.1", port), H)
    print(f"fixture on http://127.0.0.1:{port}", flush=True)
    srv.serve_forever()
