#!/usr/bin/env bash
set -eu
SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
cd "$SCRIPT_DIR"
if ! python3 -c 'import tkinter' >/dev/null 2>&1; then
  echo "O Tkinter não está instalado. No Linux Mint, instala-o com: sudo apt install python3-tk" >&2
  exit 2
fi
exec python3 -m netanalyzer.gui
