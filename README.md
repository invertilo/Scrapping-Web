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

Abre el sitio en un Chromium controlado por Playwright y registra cada request y cada respuesta con el protocolo de DevTools de Chrome (CDP). Con esa captura arma cuatro resultados:

| Resultado | Dónde queda |
|---|---|
| Mapa de páginas | `pages.json` |
| Mapa de APIs | `api_map.md` |
| Flujo de inicio a fin | `flow.md` y `flow.sh` |
| Un curl por paso | dentro del flujo y en `curls.sh` |

Después puede volver a llamar esas APIs con paginación y exportar los datos a JSON o CSV. También hace reconocimiento pasivo de un dominio: subdominios, detección de Cloudflare y posibles IPs de origen.

## Contenido

- [Piezas](#piezas)
- [Instalación](#instalación)
- [Capturar y mapear](#capturar-y-mapear)
- [Flujo de inicio a fin](#flujo-de-inicio-a-fin)
- [Mapa de APIs](#mapa-de-apis)
- [Extraer datos](#extraer-datos)
- [Recon pasivo](#recon-pasivo)
- [Archivos de cada corrida](#archivos-de-cada-corrida)
- [Curl y secretos](#curl-y-secretos)
- [Captcha](#captcha)
- [Seguridad](#seguridad)
- [Límites](#límites)

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

```bash
git clone https://github.com/invertilo/Scrapping-Web.git
cd Scrapping-Web
./setup.sh
```

`setup.sh` crea el entorno virtual e instala Playwright y Chromium. En los ejemplos de abajo, `T` es la carpeta del clon.

## Capturar y mapear

```bash
T="$PWD"
RUN=$($T/wnm-map https://ejemplo.com/ --depth 1 --max-pages 20 | tail -1)
echo "$RUN"
```

`$RUN` es la carpeta con todos los resultados de esa corrida.

| Flag | Para qué |
|---|---|
| `--scroll` | Scroll infinito y carga perezosa. |
| `--actions archivo.json` | Clics y escritura que disparan requests. Ver `examples/`. |
| `--headed` | Muestra el navegador para llenar un formulario o un captcha a mano. |
| `--emit-curl api` | Vuelca las requests como curl en `curls.sh`. |
| `--include REGEX` | Se queda solo con las URLs que coinciden. |
| `--block image,font` | Descarta tipos de recurso que no aportan al mapa. |

Para un sitio con login, primero guarda la sesión:

```bash
$T/wnm-login https://ejemplo.com/login
```

El navegador se abre y completas el acceso. La sesión queda guardada y se reutiliza con `--storage-state` o `--cookies`.

## Flujo de inicio a fin

El archivo central es `$RUN/flow.md`: la secuencia ordenada de todas las requests, desde que se abre la página hasta la respuesta con los datos, con el curl de cada paso. Los pasos que necesitan a una persona (captcha, desafío) van marcados con 🧑.

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

| Paginación | Flags |
|---|---|
| Por número de página | `--paginate page` |
| Por cursor | `--cursor-param` y `--cursor-path` |
| Por enlace a la siguiente | `--next-url-path` |
| Por valores explícitos | `--values a,b,c` |
| Un parámetro concreto | `--param K=V` |

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

Los cuerpos de respuesta se guardan tal cual.

## Captcha

La herramienta detecta el paso del captcha, muestra la imagen y espera a que escribas el texto. Con esa respuesta completa el resto del flujo. Cada consulta nueva necesita una sesión fresca y un captcha nuevo.

## Seguridad

- Los dominios `.gob`, `.gov` y `.mil` (y variantes como `gob.bo` o `gov.co`) se rechazan solos. Con autorización explícita para ese sitio, antepón `WNM_ALLOW_RESTRICTED=1`.
- Respeta esperas y `robots.txt`. Los límites se suben en sitios propios o autorizados.
- Los secretos se ocultan en logs, HAR y curl.
- Los desafíos de captcha, Cloudflare y los muros de pago quedan como pasos humanos.

## Límites

- La captura CDP cubre el frame principal.
- Los enlaces salen de `<a href>`.
- Los curl usan un user-agent de HeadlessChrome, que algunos sitios rechazan.
- Tokens, cookies y el texto del captcha caducan.
- El agrupado de endpoints es heurístico.
- Varios servicios de IP histórica piden una API de pago.
