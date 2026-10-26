"""Stage a versioned portable package, matching source, licenses and checksums."""
from __future__ import annotations

import hashlib
import importlib.metadata as metadata
import json
import platform
import shutil
from datetime import datetime, timezone
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile

from packaging.requirements import Requirement

import sys
BASE = Path(__file__).resolve().parents[1]
if str(BASE) not in sys.path:
    sys.path.insert(0, str(BASE))
from src.core.config import APP_VERSION


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def collect_licenses(destination: Path) -> list:
    pending = [line.strip() for line in (BASE / "tools" / "requirements" / "runtime.txt").read_text().splitlines()
               if line.strip() and not line.lstrip().startswith("#")]
    pending.append("PyInstaller")
    seen, components = set(), []
    while pending:
        requirement = Requirement(pending.pop())
        if requirement.marker and not requirement.marker.evaluate():
            continue
        key = requirement.name.lower().replace("_", "-")
        if key in seen:
            continue
        seen.add(key)
        distribution = metadata.distribution(requirement.name)
        name = distribution.metadata["Name"]
        copied = []
        for item in distribution.files or []:
            # Preserve only upstream license/notice documents, never module
            # code or arbitrary files from the build interpreter.
            if (item.name.upper().startswith(("LICENSE", "LICENCE", "COPYING", "NOTICE", "THIRDPARTYNOTICES"))
                    or item.name.upper().endswith((".LICENSE", ".LICENCE"))):
                source = Path(distribution.locate_file(item))
                if source.is_file():
                    target = destination / name / str(item).replace("..", "_")
                    target.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copy2(source, target)
                    copied.append(target.relative_to(destination.parent).as_posix())
        components.append({"name": name, "version": distribution.version,
                           "license_expression": distribution.metadata.get("License-Expression"),
                           "license_files": copied})
        pending.extend(distribution.requires or [])
    return sorted(components, key=lambda item: item["name"].lower())


def package() -> Path:
    release = BASE / "release"
    release.mkdir(exist_ok=True)
    name = f"OBSIDIAN_{APP_VERSION}_Windows-x64"
    destination = release / name
    source_zip = release / f"OBSIDIAN_{APP_VERSION}_Source.zip"
    archive = release / f"{name}.zip"
    if any(path.exists() for path in (destination, source_zip, archive)):
        raise FileExistsError("This version already has release artifacts; choose a new version before packaging.")
    build = BASE / "dist" / "OBSIDIAN"
    if not (build / "OBSIDIAN.exe").is_file():
        raise FileNotFoundError("Run python tools/build_exe.py before packaging.")

    with ZipFile(source_zip, "w", ZIP_DEFLATED) as bundle:
        for folder, suffixes in (("src", {".py"}), ("docs", {".md", ".json", ".svg", ".png", ".ico"}), ("tools", {".py", ".cs", ".txt"}), (".github", {".md", ".yml"})):
            for path in sorted((BASE / folder).rglob("*")):
                if path.is_file() and path.suffix in suffixes:
                    bundle.write(path, path.relative_to(BASE).as_posix())
        for filename in ("README.md", "LICENSE", "docs/legal/COPYRIGHT"):
            bundle.write(BASE / filename, filename)

    shutil.copytree(build, destination)
    for filename in ("README.md", "LICENSE"):
        shutil.copy2(BASE / filename, destination / filename)
    for filename in ("COPYRIGHT", "THIRD_PARTY_NOTICES.md"):
        shutil.copy2(BASE / "docs" / "legal" / filename, destination / filename)
    (destination / "docs").mkdir()
    for filename in ("USER_GUIDE_EN.md", "SECURITY_MODEL.md", "RESPONSIBLE_USE.md", "RELEASE_CHECKLIST.md", "DEPTH_COVERAGE_AUDIT.md", "OBSIDIAN_AUDIT.md", f"RELEASE_NOTES_{APP_VERSION}.md"):
        shutil.copy2(BASE / "docs" / filename, destination / "docs" / filename)
    for folder in ("i18n", "images"):
        shutil.copytree(BASE / "docs" / folder, destination / "docs" / folder)
    shutil.copytree(BASE / "docs" / "assets", destination / "docs" / "assets")
    shutil.copytree(BASE / "docs" / "legal", destination / "docs" / "legal")
    (destination / ".github").mkdir()
    for filename in ("CONTRIBUTING.md", "SECURITY.md"):
        shutil.copy2(BASE / ".github" / filename, destination / ".github" / filename)
    (destination / "source").mkdir()
    shutil.copy2(source_zip, destination / "source" / source_zip.name)
    components = collect_licenses(destination / "THIRD_PARTY_LICENSES")
    manifest = {"product_name": "OBSIDIAN", "application_version": APP_VERSION, "built_at_utc": datetime.now(timezone.utc).isoformat(),
                "python_version": platform.python_version(), "platform": platform.platform(),
                "components": components, "source_archive": source_zip.name,
                "license_audit_complete": False, "signed": False, "packaging_revision": 2}
    (destination / "BUILD_MANIFEST.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    (destination / "START_HERE.txt").write_text(
        f"OBSIDIAN {APP_VERSION}\n\n"
        "Double-click OBSIDIAN.exe in THIS folder.\n"
        "Keep _internal beside it; it contains the required runtime.\n\n"
        "Scanner: enter your authorized URL, confirm scope, then review the result.\n"
        "Double-click a finding for evidence and remediation.\n"
        "Export Word/JSON directly under the scan results. Use Reports to choose an older assessment.\n\n"
        "FOLDERS\n_internal: required app runtime; do not move or rename\n"
        "docs: user guide, security model and release notes\nsource: matching GPL application source\n"
        "THIRD_PARTY_LICENSES: upstream license files found in the build dependencies\n\n"
        "BUILD_MANIFEST.json records the build dependencies; FILE_SHA256.json records package file hashes.\n"
        "Read docs/RELEASE_CHECKLIST.md for the remaining public-release checks.\n", encoding="utf-8")
    hashes = {path.relative_to(destination).as_posix(): sha256(path)
              for path in sorted(destination.rglob("*")) if path.is_file()}
    (destination / "FILE_SHA256.json").write_text(json.dumps(hashes, indent=2), encoding="utf-8")
    with ZipFile(archive, "w", ZIP_DEFLATED, compresslevel=6) as bundle:
        for path in sorted(destination.rglob("*")):
            if path.is_file():
                bundle.write(path, path.relative_to(destination).as_posix())
    sums = [f"{sha256(path)}  {path.name}" for path in (archive, source_zip)]
    sums.append(f"{sha256(destination / 'OBSIDIAN.exe')}  {name}/OBSIDIAN.exe")
    (release / f"SHA256SUMS_{APP_VERSION}.txt").write_text("\n".join(sums) + "\n", encoding="ascii")
    print(archive)
    return archive


if __name__ == "__main__":
    package()
