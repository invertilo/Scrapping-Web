<p align="center">
  <a href="https://github.com/invertilo">
    <img src="https://github.com/invertilo.png" width="128" alt="Vinicius" />
  </a>
</p>

<h3 align="center">Vinicius</h3>

<p align="center">
  <a href="https://github.com/invertilo"><strong>@invertilo</strong></a>
  · Santa Cruz de la Sierra
</p>

<p align="center">
  <a href="https://github.com/invertilo/Scrapping-Web">
    <img src="https://img.shields.io/badge/python-3-3776AB?logo=python&logoColor=white" alt="Python 3" />
  </a>
  <a href="https://github.com/invertilo/Scrapping-Web">
    <img src="https://img.shields.io/badge/Playwright-Chromium-2EAD33?logo=playwright&logoColor=white" alt="Playwright" />
  </a>
</p>

---

<h1 align="center">Web Network Mapper</h1>

<p align="center">
  Mapea un sitio leyendo el mismo tráfico que muestra la pestaña <strong>Network</strong> de DevTools.
</p>

Abre el sitio en un Chromium controlado por Playwright y registra cada request y cada respuesta con el protocolo de DevTools de Chrome (CDP). Con esa captura arma el mapa de páginas, el mapa de APIs, el flujo de inicio a fin y un curl por paso. Después puede repetir esas APIs, vigilar si cambian y, en un objetivo autorizado, probar la seguridad de los endpoints.

El uso es en páginas y APIs para las que tienes permiso: un pentest, una auditoría o un sitio propio. Los dominios `.gob`, `.gov` y `.mil` (y variantes como `gob.bo` o `gov.co`) se rechazan solos. Con autorización explícita para ese sitio, antepón `WNM_ALLOW_RESTRICTED=1`.

## La skill

`SKILL.md` guía al agente para correr la herramienta de principio a fin. Esta ronda deja de ser solo captura y curl: un solo comando encadena el mapa, el análisis exporta esquema, Postman y un HTML offline, el replay aguanta rate limit, el recon confirma el origen con el certificado TLS, y `wnm-scan` revisa la seguridad de los endpoints.

| Con la skill | Sin la skill |
|---|---|
| `wnm all` captura, analiza y puede enganchar recon y watch. La última línea es la carpeta del run. | Cada paso se lanza a mano y el resultado queda repartido. |
| Guarda la sesión resuelta por dominio, fuera del zip, y captura WebSocket y SSE. | El captcha se repite en cada corrida y los sockets no entran al mapa. |
| Infiere JSON Schema, detecta el parámetro que lleva el dato y genera `replay.sh` con la paginación cableada. | El campo útil y la paginación se adivinan en cada endpoint. |
| `wnm-watch` compara la superficie de APIs y marca lo agregado, quitado o cambiado. | El diff entre dos capturas se hace a ojo. |
| `wnm-scan` revisa secretos, JWT y headers sin mandar requests. Las pruebas activas solo arrancan con `--authorized`. | Auth rota, IDOR o CORS se prueban a mano, o se disparan sin un tope. |
| El recon suma VirusTotal, urlscan y Netlas, y compara el certificado TLS contra el edge. | Una IP histórica se queda como pista, sin saber si el certificado es el del sitio. |

La detección anti-bot identifica y aconseja. No evade la protección. Las pruebas activas de `wnm-scan` comparan contra la respuesta buena ya capturada: sondeo por señales, sin exploits. Una IP histórica sigue en `POSIBLE` hasta verificarla. Las API keys van en variables de entorno.

## Contenido

- [La skill](#la-skill)
- [Instalación](#instalación)
- [Uso rápido](#uso-rápido)
- [Piezas](#piezas)
- [Sesión, WebSocket y SSE](#sesión-websocket-y-sse)
- [Análisis](#análisis)
- [Replay](#replay)
- [Watch](#watch)
- [Recon](#recon)
- [Seguridad](#seguridad)
- [Archivos de cada corrida](#archivos-de-cada-corrida)
- [Límites](#límites)

## Instalación

```bash
git clone https://github.com/invertilo/Scrapping-Web.git
cd Scrapping-Web
./setup.sh
```

| Paquete | Para qué |
|---|---|
| `playwright>=1.47` | Chromium y CDP |
| `httpx>=0.27` | Replay y pruebas activas |
| `brotli>=1.1` | Cuerpos brotli |
| `zstandard>=0.22` | Cuerpos zstd |
| `mmh3>=4.0` | Hash de favicon estilo Shodan |
| `protobuf>=5.26` | Decodificar protobuf con `--descriptor` |
| `grpcio-tools>=1.62` | Compilar `.proto` para `--proto` |

Si faltan `protobuf` o `grpcio-tools`, el análisis sigue y lo avisa. `--descriptor` solo necesita `protobuf`.

## Uso rápido

```bash
RUN=$(./wnm all https://ejemplo.com/ --depth 1 --max-pages 20 | tail -1)
./wnm-scan "$RUN"
./wnm-scan "$RUN" --authorized
./wnm watch "$RUN"
```

`wnm all` encadena map y analyze. `--recon` y `--watch` son opcionales. La última línea impresa es la carpeta del run.

| Flag de captura | Para qué |
|---|---|
| `--scroll` | Scroll infinito y carga perezosa. |
| `--actions archivo.json` | Clics y escritura. Ver `examples/`. |
| `--headed` | Muestra el navegador para un formulario o un captcha. |
| `--session-cache` | Reutiliza cookies y storage-state del dominio. |
| `--human-pause` | Pausa para resolver login o captcha a mano. |
| `--no-auto-attach` | Solo la página principal, sin iframes ni workers. |
| `--no-ws` | No captura WebSocket ni SSE. |
| `--emit-curl api` | Vuelca las requests como curl en `curls.sh`. |

## Piezas

| Comando | Módulo | Qué hace |
|---|---|---|
| `wnm` | `cli.py` | Entrada única: `map`, `analyze`, `replay`, `recon`, `watch`, `login` y `all`. |
| `wnm-map` | `mapper.py` | Recorre el sitio y captura el tráfico. |
| `wnm-analyze` | `analyze.py` | Endpoints, flujo, esquema, Postman, HTML y `replay.sh`. |
| `wnm-replay` | `replay.py` | Repite un endpoint con paginación, reintentos y rate limit. |
| `wnm-recon` | `recon.py` | Recon del dominio y veredicto de origen. |
| `wnm-watch` | `watch.py` | Snapshot y diff de la superficie de APIs. |
| `wnm-scan` | `security.py` | Revisión de seguridad. Lo activo exige `--authorized`. |
| `wnm-login` | `login.py` | Abre el navegador y guarda la sesión. |

Alias: `wnm mapper`, `wnm analyse`, `wnm diff`.

## Sesión, WebSocket y SSE

`--session-cache` guarda cookies y storage-state por dominio en `~/.cache/wnm/sessions/`, fuera de la herramienta, para que no entren al zip. El TTL sale de `WNM_SESSION_TTL` (por defecto `24h`). El directorio se cambia con `WNM_SESSION_CACHE_DIR`. Viene apagado.

`ws_sse.jsonl` guarda frames de WebSocket y eventos SSE, también dentro de iframes y workers. Los secretos se redactan salvo `--keep-secrets`. Tope por defecto: `--max-ws-frames 5000`.

## Análisis

Sigue decodificando gzip, deflate, brotli y zstd, marcando GraphQL persisted queries, agrupando roles `SEARCH` / `LIST` / `DETAIL`, confirmando el paginador y encadenando tokens en `flow.sh` (cookies, JWT, CSRF, JSF ViewState).

Esta ronda suma:

| Salida | Qué es |
|---|---|
| `schemas/` y `schemas.json` | JSON Schema draft 2020-12 por endpoint. `--no-json-schema` lo omite. |
| `data_param` | El campo que lleva el dato de la consulta, aparte de paginación, captcha y ViewState. |
| `replay.sh` | Llama a `wnm-replay` con la paginación ya cableada. `./replay.sh N` corre el endpoint N. |
| `openapi.json` | OpenAPI 3.0.3. `--no-openapi` lo omite. |
| `postman_collection.json` | Colección Postman v2.1.0. Secretos como `{{VAR}}`. `--no-postman` lo omite. |
| `report.html` | Reporte navegable, sin requests externas. `--no-html` lo omite. |

Protobuf y gRPC se decodifican de verdad con `--proto` o `--descriptor`. Sin esquema, el volcado queda marcado como genérico. Esa decodificación se probó con captura sintética.

```bash
./wnm analyze "$RUN" --json
```

## Replay

Reintenta con backoff y jitter ante errores de red y respuestas 5xx. Ante `429`, `Retry-After` o `X-RateLimit` espera y baja el ritmo, con tope de 300 s. `--ignore-rate-limit` desactiva esa espera. `--backoff` parte de `0.5` y `--max-backoff` de `60`.

## Watch

```bash
./wnm watch https://ejemplo.com/
./wnm watch "$RUN" --json
```

Compara el snapshot nuevo con el anterior: endpoints y campos agregados, quitados o cambiados, más tokens, anti-bot, rate limit y websockets. Los snapshots viven en `.watch/`.

| Código | Significado |
|---|---|
| `0` | Sin cambios, o línea base creada. |
| `10` | Hay cambios. |
| `1` | Error o dominio bloqueado. |
| `2` | Uso incorrecto. |

`--save-only` guarda sin comparar. `--no-save` compara sin avanzar la línea base. `--baseline ARCHIVO` compara contra ese snapshot.

## Recon

```bash
./wnm recon ejemplo.com
```

A las fuentes anteriores (crt.sh, c99, SecurityTrails, Shodan, Censys, favicon `mmh3`, DNS de correo y `--scan-range`) se suman VirusTotal, urlscan.io y Netlas. Sin key, VirusTotal y Netlas se saltan. urlscan puede consultar en público con cupo reducido.

| Fuente | Variable | Flag |
|---|---|---|
| SecurityTrails | `SECURITYTRAILS_API_KEY` | `--securitytrails-key` |
| Shodan | `SHODAN_API_KEY` | `--shodan-key` |
| Censys | `CENSYS_API_ID`, `CENSYS_API_SECRET` | `--censys-id`, `--censys-secret` |
| VirusTotal | `VIRUSTOTAL_API_KEY` | `--virustotal-key` |
| urlscan.io | `URLSCAN_API_KEY` | `--urlscan-key` |
| Netlas | `NETLAS_API_KEY` | `--netlas-key` |

La verificación TLS lee CN, SAN, emisor y fingerprint SHA256 y los compara con el edge. Si el certificado coincide, la IP sube a «sirve el sitio» y el veredicto gana confianza. `--json` vuelca `recon.json`. `--scan-range` sigue siendo opt-in, activo y solo para un objetivo autorizado.

## Seguridad

`wnm-scan` parte de lo ya capturado. Por defecto no manda ningún request.

```bash
./wnm-scan "$RUN"
./wnm-scan "$RUN" --authorized --max-requests 100
```

Pasivo: secretos, JWT (`alg:none`, `exp`), scorecard de headers, matriz de auth, superficie GraphQL y auditoría de lo capturado.

Activo, solo con `--authorized`:

- Sin header de auth, con header basura o con token inválido: ¿la respuesta sigue trayendo los mismos datos?
- Request incompleto: quitar parámetros requeridos uno a uno.
- IDOR sobre ids vecinos, nunca en hosts restringidos.
- Sondeo SQLi, XSS y SSTI por señales (error SQL, reflejo, 500). No lanza exploits.
- CORS, métodos observados y una ráfaga corta de rate limit.

Escribe `security_report.md` y `security_findings.json` con severidad Crítico, Alto, Medio, Bajo e Info. Tope por defecto de 100 requests, espera de `0.5` s, respeta `429` y no inventa métodos destructivos: solo GET, HEAD, OPTIONS o el método ya observado.

## Archivos de cada corrida

| Archivo | Qué es |
|---|---|
| `flow.md` / `flow.sh` | Flujo completo, con curl y encadenado de tokens. |
| `api_map.md` / `api_map.json` | Endpoints, rol, `data_param`, auth, anti-bot y curl. |
| `schemas/` / `schemas.json` | JSON Schema por endpoint. |
| `openapi.json` | OpenAPI 3.0.3. |
| `postman_collection.json` | Colección Postman v2.1.0. |
| `report.html` | Reporte offline. |
| `replay.sh` | Extracción con paginación cableada. |
| `ws_sse.jsonl` | Frames WebSocket y eventos SSE. |
| `security_report.md` / `security_findings.json` | Hallazgos de `wnm-scan`. |
| `pages.json` | Páginas, enlaces y APIs. |
| `network.har` | HAR estándar. |
| `bodies/` | Cuerpos de respuesta. |
| `requests.jsonl` | Una línea por request. |
| `extracts/` | JSON y CSV de `wnm-replay`. |

## Límites

- Los enlaces salen de `<a href>`.
- Los curl usan un user-agent de HeadlessChrome, que algunos sitios rechazan.
- Tokens, cookies y el texto del captcha caducan. La caché de sesión es opt-in y tiene TTL.
- Roles, vínculos de token sin `--keep-secrets` y la detección anti-bot son heurísticos.
- Protobuf real se probó con captura sintética. Sin `--proto` o `--descriptor` el volcado es genérico.
- `replay.sh` avisa cuando el POST depende de un token de un solo uso: ese recorrido pasa antes por `flow.sh`.
- Una IP histórica permanece en `POSIBLE` hasta que el cuerpo o el certificado la confirman.
