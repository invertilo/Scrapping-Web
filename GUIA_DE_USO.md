# Guía de uso — Web network mapper

Herramienta para mapear un sitio web interceptando el tráfico de la pestaña **Network** de DevTools
(Playwright + CDP), reconstruir el **flujo completo de inicio a fin**, sacar el **curl de cada paso**,
y extraer los datos (JSON/CSV) repitiendo las APIs con paginación. Incluye recon pasivo de dominios.

> **Sitios de gobierno bloqueados.** `.gob`, `.gov`, `.mil` (y variantes como `gob.bo`, `gov.co`) se
> rechazan automáticamente. Si tienes autorización explícita para un sitio así, antepón
> `WNM_ALLOW_RESTRICTED=1` al comando.

## 0. Setup (una vez)
```bash
T=/home/box/tools/web-network-mapper
$T/setup.sh          # crea el venv e instala Playwright/Chromium
```

## 1. Capturar y mapear un sitio
```bash
T=/home/box/tools/web-network-mapper
RUN=$($T/wnm-map https://ejemplo.com/ --depth 1 --max-pages 20 | tail -1)
echo "$RUN"          # carpeta con todos los resultados
```
Flags útiles:
- `--scroll` para scroll infinito / carga perezosa.
- `--actions archivo.json` para clics/escritura que disparan requests (ver `examples/`).
- `--headed` para ver el navegador o **llenar un formulario / captcha a mano**.
- `--emit-curl api` para volcar todas las requests como curl en `curls.sh`.
- `--no-auto-attach` para NO capturar iframes / workers / service workers (solo la sesión de la página principal). Por defecto sí se capturan.

## 2. Leer el FLUJO COMPLETO (lo que pediste)
El archivo clave es **`$RUN/flow.md`**: la secuencia ordenada de TODAS las requests, desde que se
abre la página hasta la respuesta final con los datos, con el curl de cada paso. Los pasos que
requieren un humano (captcha, desafío) van marcados con 🧑.

Para ejecutar todo el recorrido en una sola sesión:
```bash
bash $RUN/flow.sh
```
`flow.sh` usa un solo cookie jar, **descarga el captcha y te pide que escribas el texto**, y mete esa
respuesta en el POST junto con los demás campos (placa, etc.). Los tokens de un solo uso (ViewState,
CSRF, JSESSIONID) caducan: el script marca con TODO dónde re-extraerlos de la respuesta anterior si
el servidor los rechaza.

## 3. Ver el mapa de APIs
**`$RUN/api_map.md`**: cada endpoint con sus flags (DATA / RECORDS / PAGINATED / GRAPHQL), parámetros,
ruta de los registros, y un bloque **curl** listo para pegar. Arriba trae un resumen del flujo completo.
Ahora además trae el `role` de cada endpoint (SEARCH / LIST / DETAIL), la paginación confirmada, las
secciones `## Autenticación / tokens`, `## Protección anti-bot detectada` y `## Rate limit` (ver sección 6).

## 4. Extraer datos de un endpoint
```bash
$T/wnm-replay $RUN --list                         # lista endpoints
$T/wnm-replay $RUN/api_map.json 1 --paginate page --max-pages 0 --format both
```
La salida va a `$RUN/extracts/` (JSON y CSV). Usa `--curl` o `--dry-run` para ver la request exacta.

## 5. Recon de un dominio (pasivo, solo sitios autorizados y no-gob)
```bash
$T/wnm-recon ejemplo.com
```
Subdominios (c99 + crt.sh), detección de Cloudflare, e IP de origen histórica para consultar directo
saltando Cloudflare. Reporte en `runs/recon-<dominio>-<fecha>/report.md`.

## 6. Novedades del mapeo / análisis

### 6.1 Decodificación de cuerpos, gRPC/protobuf y GraphQL persisted queries
- Los cuerpos comprimidos con **gzip, deflate, brotli o zstd** se decodifican solos (por el header
  `content-encoding` o detectando los magic bytes).
- **gRPC / protobuf** se detecta y se marca con los flags `GRPC` / `PROTOBUF`. **No se decodifican**
  (no hay esquema); solo se identifican.
- **GraphQL persisted queries** se marcan con el flag `PERSISTED_QUERY`, mostrando `hash`, `version` y
  `operationName`.
- Los curl con **cuerpos binarios** usan `--data-binary @<(printf ...)` para mandar los bytes exactos.

### 6.2 Iframes, workers y service workers
`wnm-map` se engancha a los targets hijos con CDP `Target.setAutoAttach` (`flatten=false`), así que
también captura lo que piden los **iframes, workers y service workers**. Se eliminan duplicados. Cada
request hija lleva:

| Campo | Qué es |
|---|---|
| `target_type` | `page` / `iframe` / `worker` / `service_worker` |
| `target_id` | id del target CDP |
| `target_url` | URL del target que hizo la request |
| `frame_id` | id del frame (cuando aplica) |

`run_meta.json` ahora trae `auto_attach` y `capabilities`. Para desactivarlo: `--no-auto-attach`.

### 6.3 Flujo de autenticación / tokens
- `api_map.json` trae la sección **`auth_flow`** y `api_map.md` la sección **`## Autenticación / tokens`**:
  qué request **emite** cada token, qué requests lo **usan**, y por dónde viaja (cookies, JSON
  `access_token` / `id_token` / `jwt`, headers, campos ocultos CSRF / JSF `ViewState`).
- `flow.sh` incluye helpers de shell que sacan el token o campo de un paso y lo pasan al siguiente:

| Helper | Qué hace |
|---|---|
| `wnm_json ARCHIVO ruta.json` | Imprime un valor de una respuesta JSON (usa `jq` si existe, si no `python3`) |
| `wnm_hidden ARCHIVO campo` | Saca el valor de un `<input type=hidden>` o del ViewState de JSF |
| `wnm_urlenc valor` | URL-encodea un valor para meterlo en un form POST |

- Con `--keep-secrets` al capturar, la relación token → llamadas se **confirma** comparando los valores
  reales (sin eso, se infiere).

### 6.4 Clasificación, paginación confirmada y rate limit
- Campo **`role`** por endpoint: `SEARCH`, `LIST`, `DETAIL` (si no encaja: `ACTION` / `OTHER`).
- **`pagination_confirmed`** / **`confirmed_paginator`**: se marcan cuando dos llamadas al mismo endpoint
  difieren en un solo parámetro (ese es el paginador).
- **Rate limit:** respuestas `429` + headers `retry-after` / `x-ratelimit-*` generan el campo
  `rate_limit`, el flag `RATE_LIMIT` y la sección **`## Rate limit`** en `api_map.md`.

### 6.5 Detección anti-bot
`detect_anti_bot()` en `wnm_common.py` (compartida con el recon) reconoce: Cloudflare, hCaptcha,
reCAPTCHA, Akamai, PerimeterX, DataDome, Imperva, desafíos genéricos 403/503 y **"Captcha propio
(servidor)"**. Sale en `anti_bot` de `api_map.json` y en la sección **`## Protección anti-bot detectada`**
de `api_map.md`, con una **estrategia sugerida en español**.

Ojo: esto **solo detecta y aconseja**. No resuelve captchas ni se salta la protección; si hay que pasar
un desafío, lo hace un humano (ver "Sobre el captcha" más abajo).

### 6.6 OpenAPI
Si hay endpoints first-party, `wnm-analyze` escribe **`openapi.json`** (OpenAPI **3.0.3**, validado con
`openapi-spec-validator`).

| Flag (`wnm-analyze`) | Efecto |
|---|---|
| `--openapi` | Escribe `openapi.json` (activado por defecto) |
| `--no-openapi` | No escribe `openapi.json` |

### 6.7 Salida JSON de `wnm-analyze`
```bash
$T/wnm-analyze $RUN --json | jq .
```
`--json` imprime **solo** el JSON resumen en stdout (las notas van a stderr). Incluye `openapi_file`,
`auth_tokens`, `anti_bot`, `rate_limited_endpoints`, `roles` y las rutas de `api_map` (`api_map_json`,
`api_map_md`).

### Resumen de salidas nuevas
| Salida | Dónde |
|---|---|
| `openapi.json` | carpeta de la corrida |
| `auth_flow` / `## Autenticación / tokens` | `api_map.json` / `api_map.md` |
| `anti_bot` / `## Protección anti-bot detectada` | `api_map.json` / `api_map.md` |
| `rate_limit`, `RATE_LIMIT` / `## Rate limit` | `api_map.json` / `api_map.md` |
| `role`, `pagination_confirmed`, `confirmed_paginator` | por endpoint en `api_map.json` |
| flags `GRPC`, `PROTOBUF`, `PERSISTED_QUERY` | por endpoint en `api_map.*` |
| `target_type`, `target_id`, `target_url`, `frame_id` | por request en `requests.jsonl` |
| `auto_attach`, `capabilities` | `run_meta.json` |
| helpers `wnm_json`, `wnm_hidden`, `wnm_urlenc` | `flow.sh` |

## 7. Novedades del recon

### 7.1 Fuentes históricas de IP (con API key)
| Fuente | Variable(s) de entorno | Flag(s) |
|---|---|---|
| SecurityTrails | `SECURITYTRAILS_API_KEY` | `--securitytrails-key` |
| Shodan | `SHODAN_API_KEY` | `--shodan-key` |
| Censys | `CENSYS_API_ID`, `CENSYS_API_SECRET` | `--censys-id`, `--censys-secret` |

Los flags tienen prioridad sobre las variables. **Sin key, la fuente se salta** y el reporte pone
"no configurado".
```bash
export SHODAN_API_KEY=...            # opcional
export SECURITYTRAILS_API_KEY=...    # opcional
$T/wnm-recon ejemplo.com
```

### 7.2 Correlación por hash del favicon
Se calcula el hash del favicon estilo Shodan (`mmh3`) y, si hay key de Shodan, se busca con
`http.favicon.hash`. También se compara el hash del body del candidato contra el del edge.

### 7.3 Registros DNS extra
MX, TXT/SPF, `_dmarc` y subdominios comunes (`mail`, `smtp`, `ftp`, `cpanel`, `webmail`, `direct`,
`origin`, `server`), que muchas veces apuntan al hosting real. Sale en la sección
**`## Registros DNS de infraestructura (correo, etc.)`**.

### 7.4 Verificación más robusta
Un candidato cuenta como el origen si coincide el **hash del cuerpo O el título** con el edge. Se
rechaza si responde `server: cloudflare`, y se prueban también los puertos alternos **8080 / 8443**. La
tabla muestra el puerto/esquema que sirvió el sitio y si hubo body-match.

### 7.5 Escaneo de rango (opcional)
| Flag (`wnm-recon`) | Por defecto | Efecto |
|---|---|---|
| `--scan-range` | apagado | Escanea el rango alrededor del origen verificado buscando hermanos (lento) |
| `--range-prefix` | `24` | Tamaño del prefijo CIDR |
| `--range-max` | `256` | Máximo de IPs a probar |

Sale en la sección **`## Escaneo de rango /N alrededor del origen`**.

### 7.6 Veredicto y salida JSON
- Todas las fuentes alimentan el `bypass_verdict`. La confianza es **alta** si un candidato
  histórico/favicon **también se verifica** (el veredicto dice `Corroborado por: ...`). Hay una rama
  nueva de confianza media, **`POSIBLE`**, cuando hay IPs históricas/favicon solo a nivel DNS (sin
  verificar).
- `--json` vuelca `recon.json` en stdout; la carpeta de la corrida sigue siendo la **última línea**.

Secciones nuevas del reporte: **`## Fuentes historicas / pasivas y favicon`**, **`## Proteccion anti-bot`**,
**`## Registros DNS de infraestructura (correo, etc.)`** y **`## Escaneo de rango /N alrededor del origen`**.

Siendo honestos: una IP histórica es solo una pista. Sin verificación el veredicto se queda en
`POSIBLE`, y aunque se verifique, el dueño puede cerrar el origen a solo-Cloudflare en cualquier momento.

## Dependencias nuevas
Ya están en `requirements.txt` y las instala `setup.sh`:

| Paquete | Para qué |
|---|---|
| `brotli>=1.1` | Decodificar cuerpos brotli |
| `zstandard>=0.22` | Decodificar cuerpos zstd |
| `mmh3>=4.0` | Hash de favicon estilo Shodan (recon) |

## Archivos que genera cada corrida (`$RUN/`)
| Archivo | Qué es |
|---|---|
| `flow.md` | Flujo completo inicio→fin, paso a paso, con curl y marcas 🧑 de captcha |
| `flow.sh` | Script que ejecuta ese flujo en una sesión y pausa para el captcha |
| `api_map.md` / `.json` | Mapa de endpoints con curl por endpoint |
| `openapi.json` | Especificación OpenAPI 3.0.3 de los endpoints first-party (se omite con `--no-openapi`) |
| `run_meta.json` | Metadatos de la corrida (incluye `auto_attach` y `capabilities`) |
| `curls.sh` | Todas las requests como curl (con `--emit-curl`) |
| `pages.json` | Mapa del sitio (páginas, enlaces, APIs por página) |
| `network.har` | HAR estándar (abrible en DevTools) |
| `bodies/` | Cuerpos de respuesta guardados |
| `requests.jsonl` | Una línea por request capturada |

## Sobre el captcha (por qué no es 100% automático)
El captcha existe justo para impedir el scraping automático. La skill **no lo evita ni lo resuelve
sola**: detecta el paso, te muestra la imagen y espera que un humano escriba el texto, y con eso
completa el resto del flujo. Cada consulta nueva necesita una sesión fresca + un captcha nuevo.

## Seguridad y buenas prácticas
- Secretos (cookies, tokens) se ocultan por defecto como `${VARIABLES}` en logs y curl.
- Respeta delays y `robots.txt` por defecto; sube límites solo en sitios propios o autorizados.
- No se saltan captchas ni Cloudflare: esos pasos se entregan al humano.
- La detección anti-bot solo identifica la protección y sugiere una estrategia; no la evade.
- Las API keys (SecurityTrails, Shodan, Censys) van por variables de entorno o flags; no las pegues en el chat.
