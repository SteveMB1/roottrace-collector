#!/usr/bin/env python3
from __future__ import annotations

import importlib
import os
import platform
import sys
from pathlib import Path


def _collector_arch_dir() -> str | None:
    arch = os.environ.get("ROOTTRACE_COLLECTOR_ARCH", platform.machine()).lower()
    if arch in {"amd64", "x86_64"}:
        return "linux-x86_64"
    if arch in {"aarch64", "arm64"}:
        return "linux-aarch64"
    return None


def _debug_runtime(message: str) -> None:
    if os.environ.get("ROOTTRACE_COLLECTOR_DEBUG_RUNTIME", "").lower() in {"1", "true", "yes", "on"}:
        print(message, file=sys.stderr, flush=True)


def _remove_path(path: Path) -> None:
    try:
        sys.path.remove(str(path))
    except ValueError:
        pass


def _import_collector():
    install_dir = Path(__file__).resolve().parent
    source_dir = Path(os.environ.get("ROOTTRACE_COLLECTOR_SOURCE_DIR", str(install_dir))).resolve()
    candidate_dirs: list[Path] = []

    explicit_compiled_dir = os.environ.get("ROOTTRACE_COLLECTOR_COMPILED_DIR")
    if explicit_compiled_dir:
        candidate_dirs.append(Path(explicit_compiled_dir).resolve())

    arch_dir = _collector_arch_dir()
    if arch_dir:
        candidate_dirs.append(install_dir / "compiled" / arch_dir)

    for compiled_dir in candidate_dirs:
        if not compiled_dir.is_dir():
            continue
        sys.modules.pop("roottrace_collector", None)
        sys.path.insert(0, str(compiled_dir))
        try:
            return importlib.import_module("roottrace_collector")
        except Exception as exc:
            _remove_path(compiled_dir)
            sys.modules.pop("roottrace_collector", None)
            _debug_runtime(f"RootTrace collector compiled runtime skipped from {compiled_dir}: {exc}")

    sys.path.insert(0, str(source_dir))
    return importlib.import_module("roottrace_collector")


def main() -> int:
    sys.argv[0] = "roottrace_collector"
    collector = _import_collector()
    return int(collector.main())


if __name__ == "__main__":
    raise SystemExit(main())
