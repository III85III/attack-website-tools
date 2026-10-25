"""Fixed-path browser discovery using the host's native trust mechanisms.

macOS requires Apple's code-signature validation and the vendor's designated
requirement. Linux requires a root-owned, non-writable package-managed binary.
Package ownership is not a fresh cryptographic integrity audit of its contents.
Never accept executables from PATH, environment overrides or user downloads.
"""
from __future__ import annotations

import os
from pathlib import Path
import stat
import subprocess
import sys


def _root_owned_path(path: Path) -> bool:
    try:
        resolved = path.resolve(strict=True)
        if not resolved.is_file():
            return False
        # Both the executable and every ancestor must resist unprivileged writes.
        for item in (resolved, *resolved.parents):
            value = item.stat()
            if value.st_uid != 0 or value.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
                return False
        return os.access(resolved, os.X_OK)
    except OSError:
        return False


def _run(command):
    return subprocess.run(command, capture_output=True, text=True, timeout=12, check=False)


def _mac_browser():
    vendors = (
        ('Google Chrome', 'com.google.Chrome', 'EQHXZ8M8AV'),
        ('Microsoft Edge', 'com.microsoft.edgemac', 'UBF8T346G9'),
    )
    for name, identifier, team in vendors:
        app = Path('/Applications') / (name + '.app')
        executable = app / 'Contents' / 'MacOS' / name
        if not executable.is_file():
            continue
        requirement = (f'anchor apple generic and identifier "{identifier}" '
                       f'and certificate leaf[subject.OU] = "{team}"')
        try:
            result = _run(['/usr/bin/codesign', '--verify', '--deep', '--strict',
                           '-R=' + requirement, str(app)])
            if result.returncode == 0:
                return executable
        except (OSError, subprocess.SubprocessError):
            continue
    return None


def _linux_browser():
    candidates = (
        ('/opt/google/chrome/chrome', {'google-chrome-stable', 'google-chrome-beta'}),
        ('/opt/microsoft/msedge/msedge', {'microsoft-edge-stable'}),
        ('/usr/lib/chromium/chromium', {'chromium', 'chromium-browser'}),
        ('/usr/lib64/chromium-browser/chromium-browser', {'chromium', 'chromium-browser'}),
    )
    for filename, packages in candidates:
        path = Path(filename)
        if not _root_owned_path(path):
            continue
        try:
            if Path('/usr/bin/dpkg-query').is_file():
                result = _run(['/usr/bin/dpkg-query', '-S', str(path)])
                owners = {line.split(': ', 1)[0].split(':')[0] for line in result.stdout.splitlines()
                          if line.endswith(': ' + str(path))}
                if result.returncode == 0 and owners & packages:
                    return path.resolve()
            elif Path('/usr/bin/rpm').is_file():
                result = _run(['/usr/bin/rpm', '-qf', '--qf', '%{NAME}', str(path)])
                if result.returncode == 0 and result.stdout.strip() in packages:
                    return path.resolve()
        except (OSError, subprocess.SubprocessError):
            continue
    return None


def trusted_unix_browser():
    if sys.platform == 'darwin':
        return _mac_browser()
    if sys.platform.startswith('linux'):
        return _linux_browser()
    return None
