#!/usr/bin/env bash
# Idempotent setup for web-network-mapper.
# Creates ./.venv, installs Python deps and the Playwright Chromium browser.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV="$HERE/.venv"
PY="${PYTHON:-python3}"

if [ ! -x "$VENV/bin/python" ]; then
  echo "[setup] creating venv at $VENV"
  if ! "$PY" -m venv "$VENV" 2>/dev/null; then
    echo "[setup] python3-venv missing, trying to install it"
    if command -v apt-get >/dev/null; then
      SUDO=""; [ "$(id -u)" -ne 0 ] && SUDO="sudo"
      $SUDO apt-get update -y && $SUDO apt-get install -y python3-venv
      "$PY" -m venv "$VENV"
    else
      echo "[setup] ERROR: cannot create venv" >&2; exit 1
    fi
  fi
else
  echo "[setup] venv exists"
fi

"$VENV/bin/python" -m pip install --quiet --upgrade pip
"$VENV/bin/python" -m pip install --quiet -r "$HERE/requirements.txt"
echo "[setup] python deps installed"

check_browser() {
  "$VENV/bin/python" - <<'PYEOF' >/dev/null 2>&1
from playwright.sync_api import sync_playwright
with sync_playwright() as p:
    b = p.chromium.launch(headless=True)
    b.new_page().set_content("<p>ok</p>")
    b.close()
PYEOF
}

if check_browser; then
  echo "[setup] chromium already installed and launches"
else
  echo "[setup] installing chromium"
  "$VENV/bin/python" -m playwright install chromium
  if ! check_browser; then
    echo "[setup] chromium needs system deps, installing (may need sudo)"
    SUDO=""; [ "$(id -u)" -ne 0 ] && SUDO="sudo"
    if ! $SUDO "$VENV/bin/python" -m playwright install-deps chromium; then
      echo "[setup] WARN: playwright install-deps failed (unsupported distro?)." >&2
    fi
    check_browser || { echo "[setup] ERROR: chromium still fails to launch" >&2; exit 1; }
  fi
  echo "[setup] chromium OK"
fi
chmod +x "$HERE"/*.sh "$HERE"/*.py 2>/dev/null || true
echo "[setup] done. Run: $HERE/.venv/bin/python $HERE/mapper.py --help"
