"""Package a verified native build without changing existing releases."""
from __future__ import annotations

import json
import platform
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
from zipfile import ZIP_DEFLATED, ZipFile
from xml.etree import ElementTree

from package_release import collect_licenses, sha256
from src.core.config import APP_VERSION

BASE = Path(__file__).resolve().parent


def package():
    arch = {'amd64': 'x64', 'x86_64': 'x64', 'arm64': 'arm64', 'aarch64': 'arm64'}[platform.machine().lower()]
    system = {'win32': 'Windows', 'darwin': 'macOS', 'linux': 'Linux'}[sys.platform]
    name = f'ATTACK_WEBSITE_TOOLS_{APP_VERSION}_{system}-{arch}'
    output = BASE / 'release-desktop'
    output.mkdir(exist_ok=True)
    destination = output / name
    destination.mkdir() # Refuse to overwrite a previous package.
    source = output / f'ATTACK_WEBSITE_TOOLS_{APP_VERSION}_Source.zip'
    if source.exists():
        raise FileExistsError(source)
    subprocess.run(['git', 'archive', '--format=zip', '-o', str(source), 'HEAD'], cwd=BASE, check=True)
    if sys.platform == 'darwin':
        shutil.copytree(BASE / 'dist/Qolam_Sentinel.app', destination / 'ATTACK WEBSITE TOOLS.app', symlinks=True)
        launch = 'Open ATTACK WEBSITE TOOLS.app. This build is not Developer ID signed or notarized.'
    else:
        shutil.copytree(BASE / 'dist/Qolam_Sentinel', destination / 'app', symlinks=True)
        launch = ('Open app/Qolam_Sentinel.exe.' if sys.platform == 'win32'
                  else 'Run ./app/Qolam_Sentinel from this folder. Requires a graphical desktop and Ubuntu 24.04-compatible runtime libraries.')
    for filename in ('LICENSE', 'COPYRIGHT', 'THIRD_PARTY_NOTICES.md'):
        shutil.copy2(BASE / filename, destination / filename)
    (destination / 'docs').mkdir()
    for filename in ('USER_GUIDE_EN.md', 'SECURITY_MODEL.md', 'DESKTOP_PLATFORMS.md'):
        shutil.copy2(BASE / 'docs' / filename, destination / 'docs' / filename)
    (destination / 'source').mkdir()
    shutil.copy2(source, destination / 'source' / source.name)
    verification = json.loads((BASE / 'desktop-verification.json').read_text(encoding='utf-8'))
    assert verification['version'] == APP_VERSION and verification['gui_constructed'] and verification['api_word_json_persistence']
    suites = ElementTree.parse(BASE / 'desktop-tests.xml').getroot()
    test_summary = {key: sum(int(suite.get(key, '0')) for suite in suites.iter('testsuite'))
                    for key in ('tests', 'failures', 'errors', 'skipped')}
    assert test_summary['tests'] > 0 and test_summary['failures'] == test_summary['errors'] == test_summary['skipped'] == 0
    verification['source_tests'] = test_summary
    (destination / 'VERIFICATION.json').write_text(json.dumps(verification, indent=2), encoding='utf-8')
    components = collect_licenses(destination / 'THIRD_PARTY_LICENSES')
    manifest = {'version': APP_VERSION, 'platform': system, 'architecture': arch,
                'source_commit': subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=BASE, text=True).strip(),
                'python': platform.python_version(), 'build_os': platform.platform(),
                'developer_signed': False, 'notarized': False, 'components': components,
                'license_audit_complete': False}
    (destination / 'BUILD_MANIFEST.json').write_text(json.dumps(manifest, indent=2), encoding='utf-8')
    (destination / 'START_HERE.txt').write_text(f'ATTACK WEBSITE TOOLS {APP_VERSION}\n\n{launch}\n\nKeep the entire extracted folder together. No Python installation is required.\nRead docs/USER_GUIDE_EN.md and docs/DESKTOP_PLATFORMS.md before scanning.\nUse only within written authorization.\n', encoding='utf-8')
    hashes = {p.relative_to(destination).as_posix(): sha256(p) for p in sorted(destination.rglob('*')) if p.is_file() and not p.is_symlink()}
    (destination / 'FILE_SHA256.json').write_text(json.dumps(hashes, indent=2), encoding='utf-8')
    if sys.platform == 'win32':
        archive = output / (name + '.zip')
        with ZipFile(archive, 'w', ZIP_DEFLATED) as bundle:
            for path in sorted(destination.rglob('*')):
                if path.is_file():
                    bundle.write(path, path.relative_to(output).as_posix())
    else:
        archive = output / (name + '.tar.gz')
        with tarfile.open(archive, 'w:gz', dereference=False) as bundle:
            bundle.add(destination, arcname=name)
    (output / (name + '_SHA256SUMS.txt')).write_text(f'{sha256(archive)}  {archive.name}\n{sha256(source)}  {source.name}\n', encoding='ascii')
    shutil.copy2(destination / 'VERIFICATION.json', output / (name + '_VERIFICATION.json'))
    print(archive)


if __name__ == '__main__':
    package()
