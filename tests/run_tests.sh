#!/usr/bin/env bash
# Self-test. Offline part uses a local fixture site; pass --online to also hit quotes.toscrape.com.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PY="$HERE/.venv/bin/python"
PORT="${PORT:-8765}"
OUT="$HERE/runs/_selftest"
rm -rf "$OUT" "$OUT-replay"
"$PY" "$HERE/tests/fixture_server.py" "$PORT" >/dev/null 2>&1 &
SRV=$!
trap 'kill $SRV 2>/dev/null || true' EXIT
sleep 1
echo "== mapper on fixture"
"$HERE/wnm-map" "http://127.0.0.1:$PORT/" --out "$OUT" --delay 0.2 --wait 500 \
  --actions "$HERE/tests/fixture_actions.json" --emit-curl >/dev/null
echo "== assertions"
"$PY" "$HERE/tests/check_fixture.py" "$OUT"
echo "== replay (auth header supplied manually because capture was redacted)"
"$HERE/wnm-replay" "$OUT" "api/v1/items" --paginate page --max-pages 0 --delay 0 \
  --header "Authorization: Bearer secret-token-123" --out "$OUT/extracts/items" >/dev/null
test "$(wc -l < "$OUT/extracts/items.csv")" -eq 21 && echo "ok items.csv has 20 rows"
"$HERE/wnm-replay" "$OUT" "graphql" --cursor-param body:variables.after \
  --cursor-path data.users.pageInfo.endCursor --max-pages 0 --delay 0 --out "$OUT/extracts/users" >/dev/null
test "$(wc -l < "$OUT/extracts/users.csv")" -eq 26 && echo "ok users.csv has 25 rows"
echo "== generated curl commands actually work"
"$PY" - "$OUT" <<'PYEOF'
import json, os, subprocess, sys
m = json.load(open(sys.argv[1] + "/api_map.json"))
env = dict(os.environ, AUTHORIZATION="Bearer secret-token-123", COOKIE="sid=x", PASSWORD="pw")
for e in m["endpoints"]:
    out = subprocess.run(["bash", "-c", e["curl_oneline"]], capture_output=True, text=True, env=env, timeout=30).stdout
    json.loads(out)  # must be JSON
    assert "error" not in out, (e["key"], out)
print(f"ok {len(m['endpoints'])} endpoint curls return JSON (placeholders filled from env)")
lines = [l for l in open(sys.argv[1] + "/curls.sh") if l.startswith("curl ")]
assert len(lines) == len(set(lines)) and lines, "curls.sh empty or has duplicates"
print(f"ok curls.sh has {len(lines)} unique commands")
PYEOF
if [ "${1:-}" = "--online" ]; then
  echo "== online: quotes.toscrape.com/scroll"
  RUN=$("$HERE/wnm-map" https://quotes.toscrape.com/scroll --depth 0 --scroll 5 2>/dev/null | tail -1)
  grep -q 'GET quotes.toscrape.com/api/quotes' "$RUN/api_map.md" && echo "ok api_map.md lists /api/quotes"
  "$HERE/wnm-replay" "$RUN" "api/quotes" --paginate page --max-pages 3 --delay 1 --out "$RUN/extracts/quotes" >/dev/null
  test "$(wc -l < "$RUN/extracts/quotes.csv")" -ge 31 && echo "ok quotes.csv has >=30 rows"
  awk '/^```bash/{f=1;next} /^```$/{if(f){exit}} f' "$RUN/api_map.md" | bash | "$PY" -c \
    "import json,sys; d=json.load(sys.stdin); assert d['quotes']; print('ok curl block from api_map.md returns JSON')"
fi
echo "ALL TESTS PASSED"
