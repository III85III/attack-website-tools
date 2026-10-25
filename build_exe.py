"""Build a native desktop app on Windows, macOS or Linux."""

from __future__ import annotations

import os
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
        "--name=Qolam_Sentinel",
        "--onedir",
        "--noupx",
        "--windowed",
        *([f"--icon={BASE_DIR / 'assets' / 'sentinel.ico'}"] if sys.platform == "win32" else []),
        f"--paths={BASE_DIR}",
        f"--runtime-hook={BASE_DIR / 'pyi_rth_qt6_dll.py'}",
        f"--add-data={BASE_DIR / 'docs' / 'USER_GUIDE_FA.md'}{os.pathsep}docs",
        f"--add-data={BASE_DIR / 'docs' / 'USER_GUIDE_EN.md'}{os.pathsep}docs",
        f"--add-data={BASE_DIR / 'docs' / 'SECURITY_MODEL.md'}{os.pathsep}docs",
        f"--add-data={BASE_DIR / 'THIRD_PARTY_NOTICES.md'}{os.pathsep}.",
        f"--add-data={BASE_DIR / 'LICENSE'}{os.pathsep}.",
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

    app_dir = BASE_DIR / "dist" / "Qolam_Sentinel"
    if sys.platform != "win32":
        binary = (BASE_DIR / "dist" / "Qolam_Sentinel.app" / "Contents" / "MacOS" / "Qolam_Sentinel"
                  if sys.platform == "darwin" else app_dir / "Qolam_Sentinel")
        print(f"[+] Build succeeded: {binary}")
        return binary if binary.is_file() else None
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

    print(f"[+] Build succeeded: {app_dir / 'Qolam_Sentinel.exe'}")
    return app_dir / "Qolam_Sentinel.exe"


if __name__ == "__main__":
    sys.exit(0 if build() else 1)
