#!/bin/sh
set -eu

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
SOURCE_DIR="$SCRIPT_DIR"
PYTHON_BIN="${ROOTTRACE_PYTHON:-}"

if [ ! -f "${SOURCE_DIR}/roottrace_collector.py" ]; then
  PARENT_DIR="$(CDPATH= cd -- "${SCRIPT_DIR}/.." && pwd)"
  if [ -f "${PARENT_DIR}/roottrace_collector.py" ] || [ -d "${PARENT_DIR}/compiled" ]; then
    SOURCE_DIR="$PARENT_DIR"
  fi
fi

if [ -z "$PYTHON_BIN" ]; then
  PYTHON_BIN="$(command -v python3 || true)"
fi

if [ -z "$PYTHON_BIN" ]; then
  echo "python3 is required to run the RootTrace collector." >&2
  exit 1
fi

export PYTHONDONTWRITEBYTECODE="${PYTHONDONTWRITEBYTECODE:-1}"
export PYTHONUNBUFFERED="${PYTHONUNBUFFERED:-1}"
export ROOTTRACE_COLLECTOR_SOURCE_DIR="${ROOTTRACE_COLLECTOR_SOURCE_DIR:-$SOURCE_DIR}"

if [ -z "${ROOTTRACE_COLLECTOR_COMPILED_DIR:-}" ] && [ -d "${SOURCE_DIR}/compiled" ]; then
  case "$(uname -m 2>/dev/null | tr 'A-Z' 'a-z')" in
    x86_64|amd64) ROOTTRACE_COLLECTOR_COMPILED_DIR="${SOURCE_DIR}/compiled/linux-x86_64" ;;
    aarch64|arm64) ROOTTRACE_COLLECTOR_COMPILED_DIR="${SOURCE_DIR}/compiled/linux-aarch64" ;;
    *) ROOTTRACE_COLLECTOR_COMPILED_DIR="" ;;
  esac
  if [ -n "$ROOTTRACE_COLLECTOR_COMPILED_DIR" ] && [ -d "$ROOTTRACE_COLLECTOR_COMPILED_DIR" ]; then
    export ROOTTRACE_COLLECTOR_COMPILED_DIR
  else
    unset ROOTTRACE_COLLECTOR_COMPILED_DIR
  fi
fi

exec "$PYTHON_BIN" "$SCRIPT_DIR/roottrace_collector_launcher.py" "$@"
