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

Abre el sitio en un Chromium controlado por Playwright y registra cada request y cada respuesta con el protocolo de DevTools de Chrome (CDP). Con esa captura arma el mapa de páginas, el mapa de APIs, el flujo de inicio a fin y un curl por paso. Después puede repetir esas APIs con paginación y exportar JSON o CSV.

El uso es en páginas y APIs para las que tienes permiso: un pentest, una auditoría o un sitio propio. Los dominios `.gob`, `.gov` y `.mil` (y variantes como `gob.bo` o `gov.co`) se rechazan solos. Con autorización explícita para ese sitio, antepón `WNM_ALLOW_RESTRICTED=1`.

## La skill

`SKILL.md` es la guía que usa un agente para correr la herramienta de principio a fin en un sitio autorizado. Ahora no se queda en “captura y saca curls”: clasifica los endpoints, sigue el token de un paso al siguiente, marca la protección anti-bot y deja un OpenAPI para repetir el trabajo.

| Con la skill | Sin la skill |
|---|---|
| Captura también iframes, workers y service workers, y decodifica gzip, deflate, brotli y zstd. | Esas llamadas quedan fuera de `requests.jsonl` y los cuerpos comprimidos no se leen. |
| Arma el flujo completo y encadena en `flow.sh` cookies, JWT, CSRF y JSF ViewState. | Hay que copiar cada token a mano entre un paso y el siguiente. |
| Marca cada endpoint como `SEARCH`, `LIST` o `DETAIL`, confirma el paginador y avisa del rate limit. | La paginación se adivina y un `429` se ve tarde. |
| Detecta Cloudflare, hCaptcha, reCAPTCHA, Akamai, PerimeterX, DataDome, Imperva y captcha propio, y sugiere una estrategia. | La protección se descubre cuando la request ya falló. |
| Exporta `openapi.json` y un resumen `--json` para automatizar el pentest. | El mapa queda solo en un markdown que hay que releer. |
| En el recon, junta IP histórica, favicon, DNS de infraestructura y un veredicto `SI` / `POSIBLE` / `NO`. | Cada fuente se consulta por separado y el origen queda en una nota. |

La detección anti-bot identifica y aconseja. No evade la protección. Una IP histórica es una pista: el veredicto se queda en `POSIBLE` hasta que el origen se verifica. Las API keys van en variables de entorno.

## Contenido

- [La skill](#la-skill)
- [Instalación](#instalación)
- [Uso rápido](#uso-rápido)
- [Piezas](#piezas)
- [Mapeo y análisis](#mapeo-y-análisis)
- [Recon](#recon)
- [Archivos de cada corrida](#archivos-de-cada-corrida)
- [Captcha](#captcha)
- [Límites](#límites)

## Instalación

```bash
git clone https://github.com/invertilo/Scrapping-Web.git
cd Scrapping-Web
./setup.sh
```

`setup.sh` crea el entorno virtual e instala Playwright, Chromium y las dependencias de decodificación y favicon.

| Paquete | Para qué |
|---|---|
| `playwright>=1.47` | Chromium y CDP |
| `httpx>=0.27` | Replay de endpoints |
| `brotli>=1.1` | Cuerpos brotli |
| `zstandard>=0.22` | Cuerpos zstd |
| `mmh3>=4.0` | Hash de favicon estilo Shodan |

## Uso rápido

```bash
RUN=$(./wnm-map https://ejemplo.com/ --depth 1 --max-pages 20 | tail -1)
bash $RUN/flow.sh
./wnm-replay $RUN --list
./wnm-replay $RUN/api_map.json 1 --paginate page --max-pages 0 --format both
./wnm-recon ejemplo.com
```

| Flag | Para qué |
|---|---|
| `--scroll` | Scroll infinito y carga perezosa. |
| `--actions archivo.json` | Clics y escritura que disparan requests. Ver `examples/`. |
| `--headed` | Muestra el navegador para un formulario o un captcha. |
| `--emit-curl api` | Vuelca las requests como curl en `curls.sh`. |
| `--no-auto-attach` | Captura solo la página principal, sin iframes ni workers. |
| `--keep-secrets` | Guarda cookies y tokens reales para confirmar el flujo de auth. |

Para un sitio con login: `./wnm-login https://ejemplo.com/login --out estado.json` y luego `--storage-state estado.json`.

## Piezas

| Comando | Módulo | Qué hace |
|---|---|---|
| `wnm-map` | `mapper.py` | Recorre el sitio y captura el tráfico. |
| `wnm-analyze` | `analyze.py` | Agrupa endpoints, arma el flujo, los curl y el OpenAPI. |
| `wnm-replay` | `replay.py` | Repite un endpoint con paginación y guarda JSON/CSV. |
| `wnm-recon` | `recon.py` | Recon del dominio y veredicto de origen. |
| `wnm-login` | `login.py` | Abre el navegador, guarda la sesión. |
| | `wnm_common.py` | Oculta secretos, bloquea dominios restringidos y detecta anti-bot. |
| | `wnm_curl.py` | Arma los curl, también con cuerpo binario. |

## Mapeo y análisis

### Cuerpos, gRPC y GraphQL

Los cuerpos **gzip, deflate, brotli y zstd** se decodifican solos, por `content-encoding` o por magic bytes. **gRPC / protobuf** se marcan `GRPC` / `PROTOBUF` y no se decodifican. Las **GraphQL persisted queries** salen como `PERSISTED_QUERY`, con `hash`, `version` y `operationName`. Los curl de cuerpo binario usan `--data-binary`.

### Iframes, workers y service workers

`wnm-map` se engancha a los targets hijos con CDP `Target.setAutoAttach`. Cada request hija lleva `target_type` (`page`, `iframe`, `worker`, `service_worker`), `target_id`, `target_url` y `frame_id`. `run_meta.json` guarda `auto_attach` y `capabilities`. `--no-auto-attach` vuelve a la sesión de la página principal.

### Auth y tokens

`api_map.json` trae `auth_flow` y `api_map.md` la sección **Autenticación / tokens**: qué request emite cada token, quién lo usa y por dónde viaja (cookies, JWT, headers, CSRF, JSF ViewState). `flow.sh` lo encadena con `wnm_json`, `wnm_hidden` y `wnm_urlenc`. Con `--keep-secrets` esa relación se confirma con los valores reales. Sin ese flag, se infiere.

### Rol, paginación y rate limit

Cada endpoint recibe un `role`: `SEARCH`, `LIST` o `DETAIL` (si no encaja, `ACTION` / `OTHER`). `pagination_confirmed` y `confirmed_paginator` se activan cuando dos llamadas al mismo endpoint cambian un solo parámetro. Un `429` junto con `retry-after` o `x-ratelimit-*` genera `rate_limit`, el flag `RATE_LIMIT` y la sección **Rate limit**.

### Anti-bot

`detect_anti_bot()` reconoce Cloudflare, hCaptcha, reCAPTCHA, Akamai, PerimeterX, DataDome, Imperva, desafíos genéricos 403/503 y captcha propio del servidor. El resultado va en `anti_bot` y en **Protección anti-bot detectada**, con una estrategia sugerida en español. Solo detecta y aconseja.

### OpenAPI y `--json`

Si hay endpoints de primera parte, `wnm-analyze` escribe `openapi.json` (OpenAPI 3.0.3). `--no-openapi` lo omite. `--json` imprime solo el resumen: `openapi_file`, `auth_tokens`, `anti_bot`, `rate_limited_endpoints`, `roles` y las rutas del mapa.

```bash
./wnm-analyze "$RUN" --json
```

## Recon

```bash
./wnm-recon ejemplo.com
```

Subdominios (crt.sh y c99), DNS, Cloudflare y un veredicto de origen. El reporte queda en `runs/recon-<dominio>-<fecha>/report.md`. La última línea de la salida es esa carpeta. `--json` vuelca `recon.json` en stdout.

| Fuente | Variable | Flag |
|---|---|---|
| SecurityTrails | `SECURITYTRAILS_API_KEY` | `--securitytrails-key` |
| Shodan | `SHODAN_API_KEY` | `--shodan-key` |
| Censys | `CENSYS_API_ID`, `CENSYS_API_SECRET` | `--censys-id`, `--censys-secret` |

Sin key, la fuente se salta y el reporte dice «no configurado».

También correlaciona el **favicon** (hash `mmh3`, y `http.favicon.hash` si hay key de Shodan) y el hash del cuerpo contra el edge. Resuelve MX, TXT/SPF, `_dmarc` y subdominios que suelen apuntar al hosting real (`mail`, `smtp`, `ftp`, `cpanel`, `webmail`, `direct`, `origin`, `server`).

Un candidato cuenta como origen si coinciden el hash del cuerpo o el título, si no responde `server: cloudflare`, y tras probar también los puertos **8080** y **8443**. `--scan-range` recorre el rango alrededor de un origen ya verificado (`--range-prefix` 24, `--range-max` 256). Es activo y lento: solo en un objetivo autorizado.

El veredicto junta todas las fuentes. La confianza es alta cuando un candidato histórico o de favicon además se verifica. Si la IP solo existe a nivel DNS, el nivel es **POSIBLE**.

## Archivos de cada corrida

| Archivo | Qué es |
|---|---|
| `flow.md` / `flow.sh` | Flujo completo, con curl, pausa de captcha y encadenado de tokens. |
| `api_map.md` / `api_map.json` | Endpoints, rol, paginación, auth, anti-bot, rate limit y curl. |
| `openapi.json` | OpenAPI 3.0.3 de los endpoints de primera parte. |
| `run_meta.json` | Metadatos, con `auto_attach` y `capabilities`. |
| `curls.sh` | Requests como curl, con `--emit-curl`. |
| `pages.json` | Páginas, enlaces y APIs por página. |
| `network.har` | HAR estándar. |
| `bodies/` | Cuerpos de respuesta. |
| `requests.jsonl` | Una línea por request, con el target que la originó. |
| `extracts/` | JSON y CSV de `wnm-replay`. |

## Captcha

La herramienta detecta el paso, muestra la imagen y espera el texto. Con esa respuesta sigue el flujo. Cada consulta nueva necesita una sesión fresca y un captcha nuevo.

## Límites

- Los enlaces salen de `<a href>`.
- Los curl usan un user-agent de HeadlessChrome, que algunos sitios rechazan.
- Tokens, cookies y el texto del captcha caducan.
- Roles, vínculos de token sin `--keep-secrets`, agrupado de endpoints y detección anti-bot son heurísticos.
- gRPC y protobuf se identifican y no se decodifican.
- Sin `--no-auto-attach`, iframes, workers y service workers entran en `requests.jsonl`.
- Una IP histórica sigue en `POSIBLE` hasta verificarla. Un origen verificado puede cerrarse después.
