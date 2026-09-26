#!/usr/bin/env python3
"""Assertions over a mapper run against tests/fixture_server.py."""
import json
import sys
from pathlib import Path

run = Path(sys.argv[1])
m = json.loads((run / "api_map.json").read_text())
keys = {e["key"]: e for e in m["endpoints"]}
fails = []


def check(cond, msg):
    print(("ok   " if cond else "FAIL ") + msg)
    if not cond:
        fails.append(msg)


host = next(iter(keys)).split(" ")[1].split("/")[0]
items = keys.get(f"GET {host}/api/v1/items")
check(items is not None, "items endpoint found")
check(items and items["calls"] == 3, "items called 3 times (initial + 2 clicks)")
check(items and "page" in items["pagination_params"], "page detected as pagination param")
check(items and items["response_records"]["path"] == "items", "records path = items")
check(items and "authorization" in items["auth_headers"], "authorization listed in auth headers")
check(items and items["replay"]["headers"].get("authorization") == "[REDACTED]", "authorization value redacted")
check(f"GET {host}/api/v1/products/{{id}}" in keys, "numeric id normalised to {id}")
check(f"GET {host}/api/v1/orders/{{id}}" in keys, "uuid normalised to {id}")
gql = keys.get(f"POST {host}/graphql [op:ListUsers]")
check(gql is not None and "GRAPHQL" in gql["flags"], "GraphQL op detected")
check(gql and "--cursor-param body:variables.after" in gql["suggested_replay_args"], "cursor pagination suggested")
login = keys.get(f"POST {host}/api/login")
check(login and login["request_body"]["fields"]["password"] == "[REDACTED]", "form password redacted")
check(m["websockets"] and m["websockets"][0]["frames_received"] >= 1, "websocket frames captured")
pages = json.loads((run / "pages.json").read_text())
check(any(p.get("skipped") == "robots.txt" for p in pages), "robots.txt disallow honoured")
check(not any("example.org" in p["url"] for p in pages), "off-origin link not followed")
check(any("json-ld" in (p.get("embedded_data") or []) for p in pages), "JSON-LD detected")
reqs = (run / "requests.jsonl").read_text()
check("secret-token-123" not in reqs.split('"post_data"')[0] and '"authorization": "Bearer' not in reqs, "no bearer token in requests.jsonl headers")
har = json.loads((run / "network.har").read_text())
hdrs = [h for e in har["log"]["entries"] for h in e["request"]["headers"] if h["name"].lower() == "authorization"]
check(hdrs and all(h["value"] == "[REDACTED]" for h in hdrs), "HAR authorization redacted")
check(any(Path(run / p).exists() for e in m["endpoints"] for p in e["sample_bodies"]), "bodies saved")
check(items and '"Authorization: ${AUTHORIZATION}"' in items["curl"], "curl uses $AUTHORIZATION placeholder")
check(items and "AUTHORIZATION" in items["curl_env"], "curl_env lists AUTHORIZATION")
check(gql and "--data-raw" in gql["curl"] and "-X POST" in gql["curl"], "GraphQL curl has -X POST and --data-raw")
check(login and "${PASSWORD}" in login["curl"], "form password placeholder in curl")
curls = (run / "curls.sh").read_text() if (run / "curls.sh").exists() else ""
check("secret-token-123" not in curls and "hunter2" not in curls, "curls.sh contains no secrets")
sys.exit(1 if fails else 0)
