"""Release smoke checks for LibertyGSM.

This script intentionally avoids starting the packet engine. It verifies that
the shared code can be parsed and tested on all CI platforms while preserving
the Windows-only WinDivert runtime path.
"""

from __future__ import annotations

import pathlib
import py_compile
import subprocess
import sys


ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
EXCLUDED_DIRS = {
    ".git",
    ".mypy_cache",
    ".pytest_cache",
    "__pycache__",
    "build",
    "dist",
}


def _iter_python_files():
    for path in ROOT.rglob("*.py"):
        if any(part in EXCLUDED_DIRS for part in path.parts):
            continue
        yield path


def compile_sources() -> None:
    for path in _iter_python_files():
        py_compile.compile(str(path), doraise=True)


def run_unittests() -> None:
    subprocess.run(
        [sys.executable, "-m", "unittest", "discover", "-s", "tests"],
        cwd=ROOT,
        check=True,
    )


def validate_engine_metadata() -> None:
    from engines import get_engine_info

    info = get_engine_info()
    if sys.platform == "win32":
        if (
            info.key != "windows_windivert"
            or not info.requires_admin
            or not info.transparent
            or not info.supports_port_diagnostics
        ):
            raise AssertionError(f"unexpected Windows engine metadata: {info}")
    elif sys.platform == "darwin" or sys.platform.startswith("linux"):
        if info.key != "portable_proxy" or not info.supported or info.transparent:
            raise AssertionError(f"unexpected portable proxy metadata: {info}")
    else:
        if info.supported:
            raise AssertionError(f"this platform must not be marked supported yet: {info}")


def validate_release_docs() -> None:
    required = [
        ROOT / "README.md",
        ROOT / "docs" / "PLATFORM_SUPPORT.md",
        ROOT / "docs" / "RELEASE_CHECKLIST.md",
    ]
    for path in required:
        if not path.exists():
            raise AssertionError(f"missing release document: {path}")

    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    if "크로스플랫폼 로드맵" not in readme:
        raise AssertionError("README is missing the cross-platform roadmap section")

    requirements = (ROOT / "requirements.txt").read_text(encoding="utf-8")
    if 'platform_system == "Windows"' not in requirements:
        raise AssertionError("pydivert must remain a Windows-only dependency")

    gitignore = (ROOT / ".gitignore").read_text(encoding="utf-8")
    if "!LibertyGSM.spec" not in gitignore:
        raise AssertionError("LibertyGSM.spec must be tracked as the managed release spec")

    build_script = (ROOT / "build.bat").read_text(encoding="utf-8")
    if "LibertyGSM.spec" not in build_script:
        raise AssertionError("build.bat must build from LibertyGSM.spec")

    spec = (ROOT / "LibertyGSM.spec").read_text(encoding="utf-8")
    for required in ("skip_hidden_prefixes=('pydivert.tests',)", "'pytest'", "'_pytest'", "'numpy'"):
        if required not in spec:
            raise AssertionError(f"LibertyGSM.spec is missing release packaging guard: {required}")


def main() -> int:
    compile_sources()
    run_unittests()
    validate_engine_metadata()
    validate_release_docs()
    print("release_check: OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
