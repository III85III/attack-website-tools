"""Build the standalone Windows app and normalize bundled Qt runtimes."""

from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent


def build() -> Path | None:
    command = [
        sys.executable,
        "-m",
        "PyInstaller",
        "--noconfirm",
        "--clean",
        "--name=OBSIDIAN",
        "--onedir",
        "--noupx",
        "--windowed",
        f"--icon={BASE_DIR / 'assets' / 'obsidian.ico'}",
        f"--paths={BASE_DIR}",
        f"--runtime-hook={BASE_DIR / 'pyi_rth_qt6_dll.py'}",
        f"--add-data={BASE_DIR / 'docs' / 'USER_GUIDE_FA.md'};docs",
        f"--add-data={BASE_DIR / 'docs' / 'USER_GUIDE_EN.md'};docs",
        f"--add-data={BASE_DIR / 'docs' / 'SECURITY_MODEL.md'};docs",
        f"--add-data={BASE_DIR / 'THIRD_PARTY_NOTICES.md'};.",
        f"--add-data={BASE_DIR / 'LICENSE'};.",
        "--hidden-import=PyQt6",
        "--hidden-import=docx",
        "--hidden-import=psutil",
        "--hidden-import=defusedxml",
        "--hidden-import=edge_tts",
        str(BASE_DIR / "main.py"),
    ]
    result = subprocess.run(command, cwd=BASE_DIR, check=False)
    if result.returncode != 0:
        print(f"[-] PyInstaller failed with exit code {result.returncode}")
        return None

    app_dir = BASE_DIR / "dist" / "OBSIDIAN"
    internal = app_dir / "_internal"
    qt_bin = internal / "PyQt6" / "Qt6" / "bin"

    # PyInstaller can collect incompatible ICU 78 files from unrelated PATH
    # entries (for example Poppler). This Qt build uses the system ICU exports.
    for candidate in internal.glob("icu*.dll"):
        candidate.unlink()

    # Keep the MSVC runtime shipped with the bundled Qt build ahead of older
    # copies collected from the build interpreter.
    for pattern in ("VCRUNTIME140*.dll", "MSVCP140*.dll"):
        for runtime in qt_bin.glob(pattern):
            shutil.copy2(runtime, internal / runtime.name)

    print(f"[+] Build succeeded: {app_dir / 'OBSIDIAN.exe'}")
    return app_dir / "OBSIDIAN.exe"


if __name__ == "__main__":
    sys.exit(0 if build() else 1)
