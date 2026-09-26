#!/usr/bin/env python3
"""cli.py - single `wnm` command with subcommands (thin orchestrator over the existing scripts).

  wnm map <url> [mapper opts]          -> mapper.py
  wnm analyze <run_dir> [opts]         -> analyze.py
  wnm replay <api_map|run_dir> ...     -> replay.py
  wnm recon <domain> [opts]            -> recon.py
  wnm watch <url|run_dir> [opts]       -> watch.py
  wnm login ...                        -> login.py
  wnm all <url> [mapper opts] [--recon] [--recon-domain D] [--watch]
                                       -> map -> analyze (-> recon) (-> watch), prints a final summary

Each subcommand runs the target script by subprocess with the same venv python, forwarding argv
untouched (robust against signature changes in the scripts). Exit code = the script's exit code.
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from datetime import datetime
from pathlib import Path
from urllib.parse import urlsplit

TOOL_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(TOOL_DIR))
from wnm_common import guard_target  # noqa: E402

SCRIPTS = {
    "map": ("mapper.py", "Captura: navega el sitio e intercepta el tráfico (imprime el run dir como última línea)"),
    "analyze": ("analyze.py", "Construye api_map.json/.md, flow.*, openapi.json, curls a partir de un run dir"),
    "replay": ("replay.py", "Re-ejecuta un endpoint con paginación y extrae datos a JSON/CSV"),
    "recon": ("recon.py", "Recon pasivo de un dominio (subdominios, Cloudflare, IP de origen)"),
    "watch": ("watch.py", "Snapshot + diff de la API (endpoints/campos nuevos, eliminados o cambiados)"),
    "login": ("login.py", "Login manual en navegador visible; guarda storage state"),
}
ALIASES = {"mapper": "map", "analyse": "analyze", "diff": "watch"}

# analyze.py flags that change api_map content; forwarded from the map args in `wnm all`
_ANALYZE_FWD_FLAGS = ("--map-documents", "--curl-redact")
_KEY_FILES = [
    ("api_map.md", "mapa de endpoints (legible)"),
    ("api_map.json", "mapa de endpoints (máquina)"),
    ("openapi.json", "especificación OpenAPI 3.0"),
    ("flow.md", "flujo de peticiones / auth (legible)"),
    ("flow.sh", "flujo reproducible con curl"),
    ("curls.sh", "todas las peticiones como curl"),
    ("network.har", "HAR completo"),
    ("requests.jsonl", "tráfico capturado"),
    ("pages.json", "páginas visitadas"),
    ("run_meta.json", "metadatos de la corrida"),
]


def py_exe() -> str:
    v = TOOL_DIR / ".venv" / "bin" / "python"
    return str(v) if v.exists() else sys.executable


def note(*a):
    print(*a, file=sys.stderr, flush=True)


def usage() -> str:
    L = ["uso: wnm <subcomando> [opciones]", "",
         "Orquestador de web-network-mapper. Cada subcomando delega en el script correspondiente",
         "(mismas opciones que el wrapper wnm-<subcomando>; usa 'wnm <subcomando> --help').", "",
         "subcomandos:"]
    for k, (script, desc) in SCRIPTS.items():
        L.append(f"  {k:<9} {desc}  [{script}]")
    L.append(f"  {'all':<9} map -> analyze (-> recon) (-> watch) en secuencia, con resumen final")
    L += ["",
          "wnm all <url> [opciones de mapper] [--recon] [--recon-domain DOMINIO] [--recon-args \"...\"] [--watch]",
          "  --recon            además corre recon sobre el dominio (host sin 'www.' salvo --recon-domain)",
          "  --recon-domain D   dominio para recon (p.ej. el dominio raíz: toscrape.com)",
          "  --recon-args \"..\"  opciones extra para recon.py (entre comillas)",
          "  --watch            al final toma un snapshot/diff de la API con watch.py",
          "  el resto de opciones se pasan a mapper.py (p.ej. --depth 1 --max-pages 3 --scroll 5)",
          "",
          "ejemplos:",
          "  wnm all https://quotes.toscrape.com/scroll --depth 1 --max-pages 3",
          "  RUN=$(wnm all https://ejemplo.com/ | tail -1)     # la última línea es el run dir",
          "  wnm replay $RUN --list",
          "  wnm watch $RUN",
          "  wnm recon ejemplo.com --no-c99",
          "",
          "Dominios de gobierno (.gob/.gov/.mil) bloqueados salvo WNM_ALLOW_RESTRICTED=1 (con autorización explícita).",
          "Códigos de salida: el del script delegado (wnm watch: 0 sin cambios, 10 con cambios)."]
    return "\n".join(L)


def wants_help(args: list[str]) -> bool:
    return any(a in ("-h", "--help") for a in args)


def first_url(args: list[str]) -> str | None:
    for a in args:
        if re.match(r"^https?://", a, re.I):
            return a
    return None


def first_positional(args: list[str]) -> str | None:
    for a in args:
        if not a.startswith("-"):
            return a
    return None


def guard_run_dir(p: str | None) -> None:
    """Guard a run dir / api_map.json by the start_url recorded in it."""
    if not p:
        return
    path = Path(p)
    cands = []
    if path.is_dir():
        cands = [path / "run_meta.json", path / "api_map.json"]
    elif path.is_file():
        cands = [path, path.parent / "run_meta.json"]
    for c in cands:
        try:
            su = json.loads(c.read_text(encoding="utf-8")).get("start_url") if c.exists() else None
        except Exception:
            su = None
        if su:
            guard_target(su, "url")
            return


def pre_guard(sub: str, args: list[str]) -> None:
    """Fail fast on restricted targets (the scripts guard themselves too)."""
    if wants_help(args):
        return
    if sub in ("map", "all"):
        u = first_url(args)
        if u:
            guard_target(u, "url")
    elif sub == "recon":
        d = first_positional(args)
        if d:
            guard_target(d, "domain")
    elif sub in ("analyze", "replay"):
        guard_run_dir(first_positional(args))
    elif sub == "watch":
        t = first_positional(args)
        if t and re.match(r"^https?://", t, re.I):
            guard_target(t, "url")
        elif t and Path(t).exists():
            guard_run_dir(t)


def run_script(sub: str, args: list[str]) -> int:
    script = TOOL_DIR / SCRIPTS[sub][0]
    try:
        return subprocess.call([py_exe(), str(script), *args])
    except KeyboardInterrupt:
        return 130


# ------------------------------------------------------------------ wnm all
def split_all_args(args: list[str]):
    own = {"recon": False, "recon_domain": None, "recon_args": [], "watch": False}
    rest = []
    i = 0
    while i < len(args):
        a = args[i]
        if a == "--recon":
            own["recon"] = True
        elif a == "--watch":
            own["watch"] = True
        elif a in ("--recon-domain", "--recon-args"):
            if i + 1 >= len(args):
                raise SystemExit(f"ERROR: {a} requiere un valor")
            i += 1
            if a == "--recon-domain":
                own["recon_domain"] = args[i]
                own["recon"] = True
            else:
                own["recon_args"] += args[i].split()
                own["recon"] = True
        elif a.startswith("--recon-domain="):
            own["recon_domain"] = a.split("=", 1)[1]
            own["recon"] = True
        elif a.startswith("--recon-args="):
            own["recon_args"] += a.split("=", 1)[1].split()
            own["recon"] = True
        else:
            rest.append(a)
        i += 1
    return own, rest


def analyze_fwd(map_args: list[str]) -> list[str]:
    out = []
    for i, a in enumerate(map_args):
        if a in _ANALYZE_FWD_FLAGS:
            out.append(a)
        elif a == "--emit-curl":
            nxt = map_args[i + 1] if i + 1 < len(map_args) else None
            out += ["--emit-curl"] + ([nxt] if nxt in ("all", "api", "nonstatic") else [])
        elif a.startswith("--emit-curl="):
            out.append(a)
    return out


def human_size(n: int) -> str:
    for u in ("B", "KB", "MB", "GB"):
        if n < 1024 or u == "GB":
            return f"{n:.0f} {u}" if u == "B" else f"{n:.1f} {u}"
        n /= 1024
    return str(n)


def dir_size(p: Path) -> tuple[int, int]:
    files = [f for f in p.rglob("*") if f.is_file()]
    return len(files), sum(f.stat().st_size for f in files)


def cmd_all(args: list[str]) -> int:
    if not args or wants_help(args):
        print(usage())
        return 0
    own, map_args = split_all_args(args)
    url = first_url(map_args)
    if not url:
        raise SystemExit("ERROR: 'wnm all' necesita una URL http(s), p.ej.: wnm all https://quotes.toscrape.com/scroll --depth 1")
    guard_target(url, "url")
    py = py_exe()
    steps = []

    # 1) map
    note(f"== [1/{2 + own['recon'] + own['watch']}] map: {url}")
    try:
        r = subprocess.run([py, str(TOOL_DIR / "mapper.py"), *map_args], stdout=subprocess.PIPE, text=True)
    except KeyboardInterrupt:
        return 130
    lines = [l.strip() for l in (r.stdout or "").splitlines() if l.strip()]
    for l in lines[:-1]:
        print(l)
    run_dir = Path(lines[-1]) if lines else None
    if r.returncode != 0 or not run_dir or not run_dir.is_dir():
        note(f"ERROR: map falló (código {r.returncode}); no se obtuvo run dir. Se detiene la secuencia.")
        return r.returncode or 1
    steps.append(("map", 0, str(run_dir)))

    # 2) analyze
    note(f"== [2/{2 + own['recon'] + own['watch']}] analyze: {run_dir}")
    ar = subprocess.run([py, str(TOOL_DIR / "analyze.py"), str(run_dir), *analyze_fwd(map_args)],
                        stdout=subprocess.PIPE, text=True)
    steps.append(("analyze", ar.returncode, ""))
    if ar.returncode != 0:
        note(f"ERROR: analyze falló (código {ar.returncode}).")

    n = 3
    recon_dir = None
    if own["recon"]:
        host = (urlsplit(url).hostname or "").lower()
        domain = (own["recon_domain"] or (host[4:] if host.startswith("www.") else host)).strip().lower()
        recon_dir = TOOL_DIR / "runs" / f"recon-{domain}-{datetime.now().strftime('%Y%m%d-%H%M%S')}"
        note(f"== [{n}/{2 + own['recon'] + own['watch']}] recon: {domain}")
        n += 1
        try:
            guard_target(domain, "domain")
            rr = subprocess.call([py, str(TOOL_DIR / "recon.py"), domain, "--out", str(recon_dir), *own["recon_args"]])
        except SystemExit as e:
            note(str(e))
            rr = 1
        steps.append(("recon", rr, str(recon_dir)))

    watch_code = None
    if own["watch"]:
        note(f"== [{n}/{2 + own['recon'] + own['watch']}] watch: {run_dir}")
        watch_code = subprocess.call([py, str(TOOL_DIR / "watch.py"), str(run_dir)])
        steps.append(("watch", watch_code, ""))

    # summary
    print()
    print("== Resumen de wnm all")
    for name, code, extra in steps:
        if name == "watch":
            st = {0: "sin cambios / línea base", 10: "HAY CAMBIOS en la API"}.get(code, f"error (código {code})")
        else:
            st = "ok" if code == 0 else f"error (código {code})"
        print(f"   {name:<8} {st}" + (f"  -> {extra}" if extra else ""))
    am_path = run_dir / "api_map.json"
    if am_path.exists():
        try:
            am = json.loads(am_path.read_text(encoding="utf-8"))
            print(f"   páginas visitadas: {am.get('pages_visited')}, peticiones: {am.get('total_requests')}, "
                  f"endpoints: {am.get('endpoint_count')} ({am.get('data_endpoint_count')} de datos)")
            for e in (am.get("endpoints") or [])[:10]:
                if e.get("likely_tracking"):
                    continue
                print(f"     - {e.get('key')}" + (f"  [{e.get('role')}]" if e.get("role") else ""))
            ab = [a.get("vendor") for a in am.get("anti_bot") or [] if isinstance(a, dict)]
            if ab:
                print(f"   anti-bot detectado: {', '.join(ab)}")
        except Exception as e:
            print(f"   (no se pudo leer api_map.json: {e})")
    print("   archivos generados:")
    for fn, desc in _KEY_FILES:
        f = run_dir / fn
        if f.exists():
            print(f"     {fn:<15} {human_size(f.stat().st_size):>9}  {desc}")
    for sub in sorted(p for p in run_dir.iterdir() if p.is_dir()):
        cnt, sz = dir_size(sub)
        print(f"     {sub.name + '/':<15} {human_size(sz):>9}  {cnt} archivos")
    others = sorted(p.name for p in run_dir.iterdir() if p.is_file() and p.name not in dict(_KEY_FILES))
    if others:
        print(f"     otros: {', '.join(others)}")
    if recon_dir and recon_dir.exists():
        print(f"   recon: {recon_dir}")
    print("   siguiente paso: wnm replay <run_dir> --list")
    print(str(run_dir))
    failed = [c for nme, c, _ in steps if nme in ("map", "analyze", "recon") and c != 0]
    return failed[0] if failed else 0


def main(argv=None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv or argv[0] in ("-h", "--help", "help"):
        if len(argv) >= 2 and argv[0] == "help":
            return main([argv[1], "--help"])
        print(usage())
        return 0
    sub, rest = argv[0], argv[1:]
    sub = ALIASES.get(sub, sub)
    if sub == "all":
        return cmd_all(rest)
    if sub not in SCRIPTS:
        note(f"ERROR: subcomando desconocido '{argv[0]}'. Subcomandos: {', '.join(list(SCRIPTS) + ['all'])}. "
             "Usa 'wnm --help'.")
        return 2
    pre_guard(sub, rest)
    return run_script(sub, rest)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\ninterrumpido", file=sys.stderr)
        sys.exit(130)
