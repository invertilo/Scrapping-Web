# Web Network Mapper

Web Network Mapper mapea un sitio leyendo el mismo tráfico que muestra la pestaña **Network** de DevTools. Abre el sitio en un Chromium controlado por Playwright y registra cada request y cada respuesta con el protocolo de DevTools de Chrome (CDP).

Con esa captura arma cuatro resultados:

- el **mapa de páginas**
- el **mapa de APIs**
- el **flujo completo**, de la carga inicial a la respuesta con los datos
- un **curl listo** para cada paso

Después puede volver a llamar esas APIs con paginación y exportar los datos a JSON o CSV. También hace reconocimiento pasivo de un dominio: subdominios, detección de Cloudflare y posibles IPs de origen.

Está hecha en Python. El código vive en `/home/box/tools/web-network-mapper/`.

## Piezas

| Módulo | Qué hace |
|---|---|
| `mapper.py` | Recorre el sitio y captura el tráfico: HAR, cuerpos de respuesta y un log por request. |
| `analyze.py` | Agrupa las requests en endpoints, detecta paginación y GraphQL, arma el flujo ordenado, marca los pasos de captcha y genera los curl. |
| `replay.py` | Vuelve a llamar un endpoint página por página y guarda los resultados. |
| `recon.py` | Reconocimiento pasivo de un dominio: subdominios, Cloudflare y posibles IPs de origen. |
| `wnm_common.py` | Utilidades compartidas: oculta secretos y bloquea dominios restringidos. |
| `wnm_curl.py` | Arma los comandos curl a partir de las requests capturadas. |

Los comandos de uso son `wnm-map`, `wnm-analyze`, `wnm-replay`, `wnm-recon` y `wnm-login`.

## Instalación

Una sola vez:

```bash
T=/home/box/tools/web-network-mapper
$T/setup.sh
```

`setup.sh` crea el entorno virtual e instala Playwright y Chromium.

## Capturar y mapear

```bash
T=/home/box/tools/web-network-mapper
RUN=$($T/wnm-map https://ejemplo.com/ --depth 1 --max-pages 20 | tail -1)
echo "$RUN"
```

`$RUN` es la carpeta con todos los resultados de esa corrida.

Flags útiles:

- `--scroll` — scroll infinito y carga perezosa.
- `--actions archivo.json` — clics y escritura que disparan requests (ver `examples/`).
- `--headed` — muestra el navegador para llenar un formulario o un captcha a mano.
- `--emit-curl api` — vuelca las requests como curl en `curls.sh`.
- `--include REGEX` — se queda solo con las URLs que coinciden.
- `--block image,font` — descarta tipos de recurso que no aportan al mapa.

Para un sitio con login, primero guarda la sesión:

```bash
$T/wnm-login https://ejemplo.com/login
```

El navegador se abre y la persona completa el acceso. La sesión queda guardada y se reutiliza con `--storage-state` o `--cookies`.

## Flujo de inicio a fin

El archivo central es `$RUN/flow.md`: la secuencia ordenada de todas las requests, desde que se abre la página hasta la respuesta con los datos, con el curl de cada paso. Los pasos que necesitan a una persona (captcha, desafío) van marcados con 🧑.

Para recorrer esa cadena en una sola sesión:

```bash
bash $RUN/flow.sh
```

`flow.sh` usa un solo cookie jar. Cuando hay captcha, descarga la imagen y pide el texto. Ese texto entra en el POST junto con el resto de los campos. Los tokens de un solo uso (ViewState, CSRF, JSESSIONID) caducan: el script marca con `TODO` dónde volver a extraerlos de la respuesta anterior si el servidor los rechaza.

Para regenerar `flow.md`, `flow.sh` y el mapa de APIs:

```bash
$T/wnm-analyze $RUN
```

## Mapa de APIs

`$RUN/api_map.md` lista cada endpoint con sus marcas (`DATA`, `RECORDS`, `PAGINATED`, `GRAPHQL`), los parámetros, la ruta de los registros y un bloque curl listo para pegar. Arriba incluye un resumen del flujo completo.

Para volcar todas las requests como curl:

```bash
$T/wnm-analyze $RUN --emit-curl
```

Eso escribe `$RUN/curls.sh`.

## Extraer datos

```bash
$T/wnm-replay $RUN --list
$T/wnm-replay $RUN/api_map.json 1 --paginate page --max-pages 0 --format both
```

La salida queda en `$RUN/extracts/` (JSON y CSV). `--curl` y `--dry-run` muestran la request exacta sin enviarla.

Otras formas de paginar:

- cursor: `--cursor-param` y `--cursor-path`
- enlace a la página siguiente: `--next-url-path`
- valores explícitos: `--values a,b,c`
- un parámetro concreto: `--param K=V`

## Recon pasivo

```bash
$T/wnm-recon ejemplo.com
```

Consulta subdominios en c99 y crt.sh, resuelve A/AAAA, detecta Cloudflare y busca una IP de origen histórica. El reporte queda en `runs/recon-<dominio>-<fecha>/report.md`.

## Archivos de cada corrida

| Archivo | Qué es |
|---|---|
| `flow.md` | Flujo completo, paso a paso, con curl y marcas 🧑 de captcha. |
| `flow.sh` | Ese mismo flujo en una sesión, con pausa para el captcha. |
| `api_map.md` / `api_map.json` | Endpoints, con curl por endpoint. |
| `curls.sh` | Todas las requests como curl (con `--emit-curl`). |
| `pages.json` | Mapa del sitio: páginas, enlaces y APIs por página. |
| `network.har` | HAR estándar, abrible en DevTools. |
| `bodies/` | Cuerpos de respuesta guardados. |
| `requests.jsonl` | Una línea por request capturada. |
| `extracts/` | JSON y CSV de `wnm-replay`. |

## Curl y secretos

Cada curl lleva método, URL con la query de ejemplo, cabeceras capturadas y cuerpo (`--data-raw`) en POST y GraphQL. `accept-encoding` se traduce a `--compressed`.

Por defecto, cookies, tokens y campos sensibles salen como `${VARIABLES}`, con una nota de qué exportar antes de ejecutar. `--keep-secrets` en la captura guarda los valores reales. `wnm-analyze --curl-secrets` los escribe en el curl si se guardaron. `--curl-redact` fuerza los placeholders.

Los cuerpos de respuesta no se redactan.

## Captcha

El captcha existe para impedir la automatización desatendida. La herramienta detecta ese paso, muestra la imagen y espera a que una persona escriba el texto. Con esa respuesta completa el resto del flujo. Cada consulta nueva necesita una sesión fresca y un captcha nuevo.

## Seguridad

- Los dominios `.gob`, `.gov` y `.mil` (y variantes como `gob.bo` o `gov.co`) se rechazan solos. Con autorización explícita para ese sitio, el comando se antepone con `WNM_ALLOW_RESTRICTED=1`.
- Respeta esperas y `robots.txt`. Los límites solo se suben en sitios propios o autorizados.
- Los secretos se ocultan en logs, HAR y curl. Los tokens y las cookies no se pegan en el chat.
- Los desafíos de captcha, Cloudflare y los muros de pago quedan como pasos humanos.

## Límites

- La captura CDP cubre el frame principal.
- Los enlaces salen de `<a href>`.
- Los curl usan un user-agent de HeadlessChrome, que algunos sitios rechazan.
- Tokens, cookies y el texto del captcha caducan.
- El agrupado de endpoints es heurístico.
- Varios servicios de IP histórica piden una API de pago.
