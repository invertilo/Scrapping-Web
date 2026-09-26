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
5. **Review the end-to-end flow (`flow.md`):** the ordered chain of every real request from the first page load to the final data response, each with its curl. Steps that need a human (a captcha image to read, a one-time challenge) are marked 🧑. `flow.sh` is a runnable version of that chain in a single cookie jar that **pauses and asks the user to type the captcha** where needed. This is the answer to "how do I automate the whole thing including the query": you get every step, not just the last API, and the tool is honest that captcha steps require a person.
6. **Review the endpoint map (`api_map.md`):** endpoints flagged DATA / RECORDS / PAGINATED / GRAPHQL are extraction candidates; each shows the records path, keys, pagination params, a ready **curl** block (secrets shown as `${VARS}` to export first) and a replay command. Dump every request as curl with `$T/wnm-analyze $RUN --emit-curl` → `$RUN/curls.sh`.
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

## Rules
- Government (.gob/.gov/.mil) domains are blocked; only proceed with `WNM_ALLOW_RESTRICTED=1` when the user explicitly authorizes that specific target.
- Be polite: keep default delays, `--max-pages` limits and robots.txt handling unless the user explicitly asks otherwise and it's their site or authorized.
- Secrets are redacted by default in logs, HAR and curls. Never paste tokens/cookies into chat. Response bodies are not redacted.
- Do not bypass captchas, Cloudflare challenges or paywalls; the flow output marks those as human steps and hands them to the user.

## Known limits
Main-frame CDP capture only; links come from `<a href>` only; generated curls use a HeadlessChrome UA some sites block; captured tokens/cookies and captcha text expire (each real query needs a fresh session + captcha); endpoint grouping is heuristic; many historical-IP services need paid API keys.
