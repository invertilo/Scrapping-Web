---
name: Web network mapper
description: >-
  Use this when the user wants to scrape or map a website by intercepting its
  browser DevTools Network traffic: discover the XHR/fetch/GraphQL APIs a site
  calls, reconstruct the full end-to-end request flow (page load to final data,
  flagging steps that need a human such as a captcha), build a site map and API
  endpoint map, get a ready-to-run curl for each endpoint and each flow step, and
  extract the data (JSON/CSV) by replaying those endpoints with pagination. Also
  does passive recon on a target domain (subdomains, Cloudflare detection,
  historical origin IP). Government sites (.gob/.gov/.mil) are blocked by default.
---
# Web network mapper

Captures what the DevTools Network tab sees (Playwright + Chrome DevTools Protocol `Network` domain), crawls the site, reconstructs the **complete request flow from start to finish**, maps its API endpoints, emits a ready-to-run `curl` for each step, then replays an endpoint to extract data.

Tool folder: `/home/box/tools/web-network-mapper/` (full flag list in its `README.md`).

## Safety: government domains blocked by default
`wnm-map`, `wnm-replay` and `wnm-recon` refuse to run against `.gob` / `.gov` / `.mil` domains (and their country variants like `gob.bo`, `gov.co`) to prevent misuse against official government systems. If the user has explicit authorization to test such a site, they must re-run with the env var `WNM_ALLOW_RESTRICTED=1`. Never set that flag on the user's behalf without their explicit say-so.

## Steps
1. **Setup (idempotent):** `T=/home/box/tools/web-network-mapper; $T/setup.sh` if `$T/.venv` is missing or imports fail.
2. **Clarify scope only if needed:** start URL, how deep/how many pages, whether login is required, what data they want. Default to a small polite crawl.
3. **Login / interactive flows (optional):** for logged-in sites or forms (search, captcha), run `$T/wnm-login <url>` (headed; the user completes login/captcha on the desktop) to save a storage state, or capture with `--headed` and `--actions FILE`. Pass state later with `--storage-state` / `--cookies`.
4. **Capture and map:**
   `RUN=$($T/wnm-map <url> [--depth N] [--max-pages N] [--scroll] [--actions FILE] [--include REGEX] [--block image,font] [--emit-curl api] | tail -1)`
   - `--scroll` for infinite scroll/lazy loading, `--actions FILE` for clicks/typing that trigger loads (see `examples/`), `--headed` to watch or let the user fill a form/captcha.
   - Run dir contains `requests.jsonl`, `network.har`, `bodies/`, `pages.json` (site map), `api_map.json`, `api_map.md`, `flow.md`, `flow.sh`, and `curls.sh` when `--emit-curl` is used.
   - Also `openapi.json` (when first-party endpoints exist) and `run_meta.json` (now with `auto_attach` and `capabilities`). Iframes/workers/service workers are captured by default; `--no-auto-attach` limits capture to the main page session.
   - New outputs: `ws_sse.jsonl` (WebSocket/SSE), `schemas/` + `schemas.json` (JSON Schema draft 2020-12), `postman_collection.json` (Postman v2.1.0), `report.html` (browsable report), `replay.sh` (auto extraction script); and, from `wnm-scan`, `security_report.md` / `security_findings.json`.
5. **Review the end-to-end flow (`flow.md`):** the ordered chain of every real request from the first page load to the final data response, each with its curl. Steps that need a human (a captcha image to read, a one-time challenge) are marked 🧑. `flow.sh` is a runnable version of that chain in a single cookie jar that **pauses and asks the user to type the captcha** where needed. This is the answer to "how do I automate the whole thing including the query": you get every step, not just the last API, and the tool is honest that captcha steps require a person.
6. **Review the endpoint map (`api_map.md`):** endpoints flagged DATA / RECORDS / PAGINATED / GRAPHQL are extraction candidates; each shows the records path, keys, pagination params, a ready **curl** block (secrets shown as `${VARS}` to export first) and a replay command. Dump every request as curl with `$T/wnm-analyze $RUN --emit-curl` → `$RUN/curls.sh`.
   - Also check the `## Autenticación / tokens`, `## Protección anti-bot detectada` and `## Rate limit` sections, and each endpoint's `role` / `confirmed_paginator`. For a machine-readable summary: `$T/wnm-analyze $RUN --json` (JSON only on stdout).
7. **Extract:** `$T/wnm-replay $RUN --list`, then
   `$T/wnm-replay $RUN/api_map.json <index|key|substring> --paginate <param> --max-pages 0 --format both`
   - Cursor APIs: `--cursor-param` + `--cursor-path`; next-link APIs: `--next-url-path`; explicit values: `--values a,b,c`; override params with `--param K=V`. Use `--dry-run` or `--curl` to preview. Output goes to `$RUN/extracts/`.
8. **Report:** summarize the flow (with any human steps), endpoints (method, path, data, pagination), site map size, extracted row count; attach `flow.md`, `api_map.md` and the CSV.

## End-to-end flow output (`flow.md` / `flow.sh`)
- `flow.md`: ordered table + per-step detail (method, URL, status, redirects, form fields, curl) covering the whole journey, not just the final API. Human-required steps (captcha/challenge) are flagged 🧑 with a note explaining why they can't be automated unattended.
- `flow.sh`: runs the chain in one cookie jar (`JAR`), downloads captcha images and `read`s the solution from the user, and substitutes the captured captcha value with `$CAPTCHA` in the form POST. One-time tokens (ViewState, CSRF, JSESSIONID) that expire are called out with TODO notes to re-extract from the previous response.
- Regenerate anytime with `$T/wnm-analyze $RUN` (rebuilds `flow.md`, `flow.sh`, `api_map.*`).

## curl output
- Each endpoint's curl has method, full URL with example query, captured headers, and body (`--data-raw`) for POST/GraphQL; `accept-encoding` becomes `--compressed`.
- Redacted by default: Authorization/Cookie/token header values, sensitive query params and body fields become `${VARS}` with an export note. `--keep-secrets` at capture keeps real values; `analyze --curl-secrets` emits them if saved; `--curl-redact` forces placeholders.
- `wnm-replay … --curl` prints the exact request replay would send.

## Domain recon (passive, for authorized non-gov targets)
Reusable recon on any allowed domain: pull subdomains from the c99 subdomain finder and crt.sh; resolve A/AAAA with `dig`; flag Cloudflare (CF ranges/CNAME/NS); look for a historical/origin IP from before Cloudflare; for a candidate origin IP, `ping` it and `curl -I --resolve <domain>:443:<ip>` to check it still serves the real site. See `runs/recon-*/report.md`.

## Analyze: new outputs and flags
- **Body decoding:** gzip/deflate/brotli/zstd bodies decoded automatically (by `content-encoding` or magic bytes). gRPC/protobuf detected → flags `GRPC` / `PROTOBUF` (not decoded). GraphQL persisted queries → flag `PERSISTED_QUERY` with `hash` / `version` / `operationName`. Curls for binary bodies use `--data-binary @<(printf ...)`.
- **Iframes / workers / service workers:** CDP `Target.setAutoAttach` (`flatten=false`). Child requests tagged `target_type` (`page`/`iframe`/`worker`/`service_worker`), `target_id`, `target_url`, `frame_id`; deduplicated. `run_meta.json` has `auto_attach` and `capabilities`.
- **Auth / token flow:** `auth_flow` in `api_map.json` and `## Autenticación / tokens` in `api_map.md` — who issues each token, who uses it, and transport (cookies, JSON `access_token`/`id_token`/`jwt`, headers, hidden CSRF / JSF ViewState fields). `flow.sh` has helpers `wnm_json`, `wnm_hidden`, `wnm_urlenc` that extract a token/field from one step and feed it to the next. With `--keep-secrets` the token→calls link is confirmed (otherwise inferred).
- **Classification:** `role` = `SEARCH` / `LIST` / `DETAIL` (fallback `ACTION` / `OTHER`). `pagination_confirmed` / `confirmed_paginator` when two calls differ in a single parameter. Rate limit from `429` + `retry-after` / `x-ratelimit-*` → `rate_limit`, flag `RATE_LIMIT`, section `## Rate limit`.
- **Anti-bot:** `detect_anti_bot()` in `wnm_common.py` (shared with recon): Cloudflare, hCaptcha, reCAPTCHA, Akamai, PerimeterX, DataDome, Imperva, generic 403/503 challenge, "Captcha propio (servidor)". Output: `anti_bot` in `api_map.json`, `## Protección anti-bot detectada` in `api_map.md`, with a suggested strategy in Spanish. Detection/advice only — hand challenges to the user.
- **OpenAPI:** `openapi.json` (OpenAPI 3.0.3, validated with openapi-spec-validator) when first-party endpoints exist.

| Command | Flag | Effect |
|---|---|---|
| `wnm-map` | `--no-auto-attach` | Skip iframes/workers/service workers |
| `wnm-analyze` | `--openapi` (default on) / `--no-openapi` | Write / skip `openapi.json` |
| `wnm-analyze` | `--json` | Print only the JSON summary (`openapi_file`, `auth_tokens`, `anti_bot`, `rate_limited_endpoints`, `roles`, `api_map_json`, `api_map_md`) |

## Recon: new sources, flags and sections
- **Historical IPs by API key:** SecurityTrails (`SECURITYTRAILS_API_KEY` / `--securitytrails-key`), Shodan (`SHODAN_API_KEY` / `--shodan-key`), Censys (`CENSYS_API_ID` + `CENSYS_API_SECRET` / `--censys-id` + `--censys-secret`). No key → skipped with note "no configurado". Only use keys the user provides; never ask them to paste keys in chat — use env vars.
- **Favicon hash:** Shodan-style `mmh3` hash + Shodan `http.favicon.hash` search (needs Shodan key) + body-hash comparison vs edge.
- **Extra DNS:** MX, TXT/SPF, `_dmarc`, common subdomains (`mail`, `smtp`, `ftp`, `cpanel`, `webmail`, `direct`, `origin`, `server`) → `## Registros DNS de infraestructura (correo, etc.)`.
- **Robust verification:** match on body hash OR title; rejects `server: cloudflare`; tries ports 8080/8443. Table shows served port/scheme + body-match.
- **Range scan (opt-in):** `--scan-range`, `--range-prefix` (default 24), `--range-max` (default 256) → `## Escaneo de rango /N alrededor del origen`. Slow and active; only for authorized targets and when the user asks.
- **Verdict:** all sources feed `bypass_verdict`. High confidence when a historical/favicon candidate is also verified ("Corroborado por: ..."); new medium branch `POSIBLE` when historical/favicon IPs exist only at DNS level. New sections `## Fuentes historicas / pasivas y favicon`, `## Proteccion anti-bot`.
- `--json` dumps `recon.json` to stdout; the run dir is still the last line (`tail -1`).

## `wnm` — unified CLI (new)
A single entrypoint (`cli.py`) wraps every step. `wnm --help` is in Spanish.

| Subcommand | Equivalent | What it does |
|---|---|---|
| `wnm map <url>` | `wnm-map` | Crawl + CDP capture |
| `wnm analyze <run>` | `wnm-analyze` | Build the maps / flow / outputs |
| `wnm replay <run> …` | `wnm-replay` | Extract data from an endpoint |
| `wnm recon <domain>` | `wnm-recon` | Passive recon + bypass verdict |
| `wnm watch <url\|run\|api_map.json>` | `wnm-watch` | Snapshot + diff endpoints |
| `wnm login <url>` | `wnm-login` | Headed login → storage state |
| `wnm all <url>` | — | Chain `map → analyze → (recon) → (watch)` |

Aliases: `mapper` (map), `analyse` (analyze), `diff` (watch).

### `wnm all <url>` — one-shot pipeline
Runs `map`, then `analyze`, optionally `recon` and `watch`. The **last line printed is the run dir** (so `RUN=$(wnm all <url> | tail -1)`).

| Flag (`wnm all`) | Effect |
|---|---|
| `--recon` | Also run recon after analyze |
| `--recon-domain <domain>` | Recon this domain instead of the mapped host |
| `--recon-args "<args>"` | Extra args passed through to recon |
| `--watch` | Also take a watch snapshot/diff at the end |

```bash
RUN=$(wnm all https://example.com/ --recon --watch | tail -1)
```

## Mapper — new: session cache & WebSocket/SSE capture

### Reusable session / captcha cache
Optionally reuse a solved login/captcha across runs. **Off by default.**

| Flag (`wnm-map`) | Effect |
|---|---|
| `--session-cache` | Reuse (and update) a cached session for the domain |
| `--no-session-cache` | Never read/write the cache (default) |
| `--human-pause [SECONDS]` | After loading, pause so you can solve login/captcha by hand |

- Cookies + `storage_state` are saved **per domain** at `~/.cache/wnm/sessions/<domain>.json` — **outside the tool folder** (perms `0600`/`0700`) so secrets never leak into the run zip.
- TTL via `WNM_SESSION_TTL` (default `24h`; accepts `s`/`m`/`h`/`d`). Cache dir via `WNM_SESSION_CACHE_DIR`.
- State is recorded under the `session_cache` block in `run_meta.json`.

### WebSocket & Server-Sent-Events capture
A new file **`ws_sse.jsonl`** is written in the run dir (`requests.jsonl` is unchanged). It records:
- **WebSocket** connections: handshake, frames sent/received, text or binary (base64).
- **SSE** streams: `event` / `data` / `id` events.
- Captured even inside iframes/workers/service workers, deduplicated. Secrets are redacted unless `--keep-secrets`.

| Flag (`wnm-map`) | Default | Effect |
|---|---|---|
| `--no-ws` | — | Disable WebSocket/SSE capture |
| `--max-ws-frames` | `5000` | Cap on captured frames |
| `--max-ws-payload` | — | Cap on per-frame payload size |

State is recorded under `ws_sse` in `run_meta.json`; `capabilities` gains `ws_sse_capture` and `session_cache`.

## Analyze — new: schemas, data param, replay script, protobuf, Postman, HTML

### JSON Schema inference
For each data endpoint, a JSON Schema (**draft 2020-12**) is inferred → `schemas/<endpoint>.schema.json` plus a combined `schemas.json`.

| Flag (`wnm-analyze`) | Effect |
|---|---|
| `--json-schema` / `--no-json-schema` | Write / skip schemas (default: on) |

### Data-parameter detection
Each endpoint gets a `data_param` — the field that carries the actual query value (a plate, an id, a search term) — plus an **"Extracción sugerida"** line in `api_map.md`. Applies to `SEARCH` / `DETAIL` / `LIST` roles; excludes pagination, captcha, ViewState and GraphQL-wrapper params.

### Auto-generated extraction script (`replay.sh`)
`replay.sh` is generated: it calls `wnm-replay` with pagination already wired, and takes the input value as a variable (e.g. `$PRODUCT_ID`). `./replay.sh N` runs endpoint N.

| Flag (`wnm-analyze`) | Effect |
|---|---|
| `--replay-script` / `--no-replay-script` | Write / skip `replay.sh` (default: on) |

> **Note:** for POST endpoints with one-time tokens (ViewState/captcha, e.g. RUAT), `replay.sh` warns you must go through `flow.sh` first — it is **not** automatic bulk extraction.

### Real protobuf / gRPC decoding (with a schema)
When you supply a schema, protobuf/gRPC bodies are actually decoded (gRPC-web 5-byte framing handled).

| Flag (`wnm-analyze`) | Effect |
|---|---|
| `--proto <file\|dir>` | Use `.proto` file(s) (needs `grpcio-tools`) |
| `--descriptor <fds>` | Use a compiled FileDescriptorSet (needs only `protobuf`) |
| `--proto-message TYPE` | Message type to decode as |

Without a schema it falls back to a generic dump marked *"decodificación genérica sin esquema"*.

### Postman collection export
`postman_collection.json` (schema **v2.1.0**): folders by role, secrets as `{{VAR}}`, `Authorization` as `{{token}}`.

| Flag (`wnm-analyze`) | Effect |
|---|---|
| `--postman` / `--no-postman` | Write / skip `postman_collection.json` (default: on) |

### Browsable HTML report
`report.html` — self-contained (no external network): filterable table, collapsible detail, flow diagram in HTML/CSS plus Mermaid-as-text, and tokens / anti-bot / rate-limit / WS-SSE sections.

| Flag (`wnm-analyze`) | Effect |
|---|---|
| `--html` / `--no-html` | Write / skip `report.html` (default: on) |

### Extended `--json` summary
`--json` now also includes: `json_schema`, `json_schema_count`, `postman_file`, `html_file`, `replay_script`, `data_params`, `protobuf_decoded_endpoints`, `ws_sse_streams`. WS/SSE are read defensively from `ws_sse.jsonl`.

## Replay — new: retries & rate-limit resilience
`wnm-replay` now retries with **exponential backoff + jitter** on network errors and 5xx, and honors rate limits: on `429` / `Retry-After` / `X-RateLimit` it waits and slows down (cap 300s).

| Flag (`wnm-replay`) | Default | Effect |
|---|---|---|
| `--backoff` | `0.5` | Base backoff seconds |
| `--max-backoff` | `60` | Max backoff seconds |
| `--respect-rate-limit` | on | Wait/slow on rate-limit signals |
| `--ignore-rate-limit` | — | Do not slow down on rate-limit signals |
| `--delay` | (existing) | Fixed delay between requests |

Output now reports `rate_limit_waits` / `retries`.

## Recon — new: extra passive sources & TLS verification

### Extra passive sources
| Source | Env var | Flag | No key |
|---|---|---|---|
| VirusTotal | `VIRUSTOTAL_API_KEY` | `--virustotal-key` | skipped ("no configurado") |
| urlscan.io | `URLSCAN_API_KEY` | `--urlscan-key` | public search, reduced quota |
| Netlas | `NETLAS_API_KEY` | `--netlas-key` | skipped ("no configurado") |

New report section: **`## Fuentes pasivas adicionales (VirusTotal / urlscan / Netlas)`**.

### TLS / certificate verification
The presented certificate is read (CN, SAN, issuer, SHA256 fingerprint, validity) with `SNI=domain` and compared against the edge. A SAN match or fingerprint match promotes the IP to **"sirve el sitio" (cert-match)** and raises verdict confidence. New section: **`## Verificación TLS / certificado`**.

All new candidates (`passive:*`, `cert-match`) feed the bypass verdict with `Corroborado por: ...`.

## `wnm-watch` — endpoint watch / diff (new)
Track how a site's API surface changes over time. `wnm-watch <url|run_dir|api_map.json>` takes a snapshot and compares it against the previous one, detecting **added/removed endpoints**, **field/type changes**, and changes in **tokens, anti-bot, rate-limit and websockets**.

| Flag (`wnm-watch`) | Effect |
|---|---|
| `--baseline` | Make this snapshot the baseline (no diff) |
| `--save-only` | Save the snapshot, do not diff |
| `--no-save` | Diff only, do not save the snapshot |
| `--json` | Emit the diff as JSON |
| `--name <name>` | Name this watch series |
| `--watch-dir <dir>` | Where snapshots live |
| `--reanalyze` | Re-run analysis before snapshotting |
| `--include-tracking` | Include tracking/analytics endpoints |
| `--list` | List existing snapshots |

- Snapshots and diffs live in `<tool>/.watch/<name>/snapshot-*.json` plus `diff-*.md` / `diff-*.json`.
- **Exit codes:** `0` no changes / baseline created · `10` changes detected · `1` error/blocked · `2` usage.
- Ideal for a scheduled routine.

## `wnm-scan` — security testing (authorized targets only)

> ⚠️ **Ethics first.** `wnm-scan` (`security.py`) is offensive/defensive security testing. **Only run active tests against systems you own or are explicitly authorized to test.** Active testing is **off by default**; passive analysis never sends requests.

`wnm-scan <run_dir|api_map.json> [--authorized] [options]`

### Two modes
- **Passive (default):** sends **no** requests — it only analyzes what was already captured.
- **Active:** requires `--authorized` / `--i-have-permission`, against authorized targets. Without `--authorized`, `--only active` aborts.

### Passive analysis
- Secret scanning (AWS / Stripe / API keys).
- JWT review (`alg:none`, `exp`, claims).
- Security-header scorecard (CSP / HSTS / XFO / XCTO / Referrer / Permissions + cookie flags).
- Authentication matrix.
- GraphQL surface.

### Active tests (low-impact, same observed method, compared to a baseline)
- Broken auth (no auth / junk credential / minimal headers / expired JWT).
- Incomplete request (drop required params).
- IDOR / BOLA (neighbouring ids).
- Injection probing SQLi / XSS / SSTI (by signal, **not** exploits).
- Session / CORS (reflected `Origin` + credentials, `OPTIONS`/`Allow`).
- Real rate-limit (bounded burst).

### Safeguards
- Active tests off by default.
- Only `GET` / `HEAD` / `OPTIONS` or the observed method; new `PUT` / `PATCH` / `DELETE` are blocked.
- Probe payloads, not exploits.
- `--max-requests` cap (default `100`); `--delay` (default `0.5s`); rate-limit respected (backoff on 429).
- IDOR never runs against restricted hosts.
- The `.gob` / `.gov` / `.mil` block still applies (only with `WNM_ALLOW_RESTRICTED=1`).

### Outputs
- `security_report.md` — executive summary + findings by severity (Crítico / Alto / Medio / Bajo / Info).
- `security_findings.json` — machine-readable findings.

### Flags
| Flag | Effect |
|---|---|
| `--authorized` / `--i-have-permission` | Enable active testing (authorized targets only) |
| `--only passive` / `--only active` | Restrict to one mode (`active` needs `--authorized`) |
| `--out <path>` | Output location |
| `--json` | Emit findings JSON |
| `--max-requests` | Active request cap (default `100`) |
| `--delay` | Delay between requests (default `0.5s`) |
| `--timeout` | Per-request timeout |
| `--insecure` | Skip TLS verification |
| `--header` | Extra header(s) |
| `--cookies` | Cookies to send |
| `--storage-state` | Playwright storage state |
| `--user-agent` | Override UA |
| `--max-idor` | Max IDOR probes (default `3`) |
| `--max-injection` | Max injection probes (default `8`) |
| `--burst` | Rate-limit burst size (default `8`) |
| `--no-auth-test` / `--no-incomplete` / `--no-idor` / `--no-injection` / `--no-session` / `--no-ratelimit` | Disable a specific active test |

## Environment variables
| Variable | Purpose |
|---|---|
| `WNM_ALLOW_RESTRICTED` | Set to `1` to allow `.gob`/`.gov`/`.mil` targets (only with explicit authorization) |
| `WNM_SESSION_TTL` | Session-cache TTL (default `24h`; `s`/`m`/`h`/`d`) |
| `WNM_SESSION_CACHE_DIR` | Session-cache directory (default `~/.cache/wnm/sessions`) |
| `SECURITYTRAILS_API_KEY` | SecurityTrails (recon) |
| `SHODAN_API_KEY` | Shodan (recon) |
| `CENSYS_API_ID` / `CENSYS_API_SECRET` | Censys (recon) |
| `VIRUSTOTAL_API_KEY` | VirusTotal (recon, new) |
| `URLSCAN_API_KEY` | urlscan.io (recon, new; public search without key) |
| `NETLAS_API_KEY` | Netlas (recon, new) |

## Recommended workflow with `wnm all`
```bash
# map → analyze → recon → watch, in one go; last line is the run dir
RUN=$(wnm all https://example.com/ --recon --watch | tail -1)

# then, e.g.
xdg-open "$RUN/report.html"       # browsable report
cat      "$RUN/api_map.md"        # endpoints + suggested extraction
"$RUN"/replay.sh 1                # run the generated extractor for endpoint 1
```

## Dependencies
`brotli>=1.1`, `zstandard>=0.22`, `mmh3>=4.0`, `protobuf>=5.26`, `grpcio-tools>=1.62` (in `requirements.txt`; installed by `setup.sh`). `protobuf` / `grpcio-tools` are only for protobuf decoding (`--descriptor` needs only `protobuf`, `--proto` also needs `grpcio-tools`); if missing, analysis still runs and says so.

## Rules
- Government (.gob/.gov/.mil) domains are blocked; only proceed with `WNM_ALLOW_RESTRICTED=1` when the user explicitly authorizes that specific target.
- Be polite: keep default delays, `--max-pages` limits and robots.txt handling unless the user explicitly asks otherwise and it's their site or authorized.
- Secrets are redacted by default in logs, HAR and curls. Never paste tokens/cookies into chat. Response bodies are not redacted.
- Do not bypass captchas, Cloudflare challenges or paywalls; the flow output marks those as human steps and hands them to the user.
- Anti-bot detection is diagnostic: report the vendor and suggested strategy, but don't try to defeat the protection.
- `--scan-range` is active probing: only on authorized targets and when the user explicitly asks.

## Known limits
Main-frame CDP capture only; links come from `<a href>` only; generated curls use a HeadlessChrome UA some sites block; captured tokens/cookies and captcha text expire (each real query needs a fresh session + captcha); endpoint grouping is heuristic; many historical-IP services need paid API keys.
Update: iframes/workers/service workers are now captured via auto-attach (so "main-frame only" applies only with `--no-auto-attach`); SecurityTrails/Shodan/Censys are queried when keys are supplied; gRPC/protobuf bodies are flagged but not decoded; roles, inferred token links and anti-bot detection are heuristic; a historical IP stays `POSIBLE` until verified.
