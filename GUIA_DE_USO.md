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

## Archivos que genera cada corrida (`$RUN/`)
| Archivo | Qué es |
|---|---|
| `flow.md` | Flujo completo inicio→fin, paso a paso, con curl y marcas 🧑 de captcha |
| `flow.sh` | Script que ejecuta ese flujo en una sesión y pausa para el captcha |
| `api_map.md` / `.json` | Mapa de endpoints con curl por endpoint |
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
