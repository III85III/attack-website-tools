from pathlib import Path
from types import SimpleNamespace

from src.core.config import user_state_dir
from src.core import browser_trust


def test_native_user_data_paths(tmp_path):
    home = tmp_path.resolve()
    assert user_state_dir('darwin', home, {}) == home / 'Library/Application Support/III85III/Attack Website Tools'
    assert user_state_dir('linux', home, {}) == home / '.local/share/iii85iii/attack-website-tools'
    assert user_state_dir('linux', home, {'XDG_DATA_HOME': 'relative'}) == user_state_dir('linux', home, {})
    assert user_state_dir('linux', home, {'XDG_DATA_HOME': str(home / 'custom')}) == home / 'custom/iii85iii/attack-website-tools'
    assert user_state_dir('win32', home, {}) == home / 'AppData/Local/III85III/Qolam Sentinel'


def test_unix_discovery_unsupported_platform(monkeypatch):
    monkeypatch.setattr(browser_trust.sys, 'platform', 'unsupported')
    assert browser_trust.trusted_unix_browser() is None


def test_linux_browser_requires_root_owned_path(monkeypatch):
    monkeypatch.setattr(browser_trust, '_root_owned_path', lambda _: False)
    monkeypatch.setattr(browser_trust, '_run', lambda _: (_ for _ in ()).throw(AssertionError('must not run')))
    assert browser_trust._linux_browser() is None


def test_macos_vendor_signature_failure_rejects_browser(monkeypatch):
    monkeypatch.setattr(Path, 'is_file', lambda _: True)
    seen = []
    def run(command):
        seen.append(command)
        return SimpleNamespace(returncode=1)
    monkeypatch.setattr(browser_trust, '_run', run)
    assert browser_trust._mac_browser() is None
    assert len(seen) == 2
    assert all(command[0] == '/usr/bin/codesign' and '--strict' in command and '--deep' in command for command in seen)
    assert 'EQHXZ8M8AV' in seen[0][-2]


def test_macos_valid_vendor_signature_accepts_fixed_path(monkeypatch):
    monkeypatch.setattr(Path, 'is_file', lambda _: True)
    monkeypatch.setattr(browser_trust, '_run', lambda _: SimpleNamespace(returncode=0))
    assert browser_trust._mac_browser() == Path('/Applications/Google Chrome.app/Contents/MacOS/Google Chrome')


def test_linux_browser_requires_expected_package_owner(monkeypatch):
    monkeypatch.setattr(browser_trust, '_root_owned_path', lambda _: True)
    monkeypatch.setattr(Path, 'is_file', lambda _: True)
    monkeypatch.setattr(browser_trust, '_run', lambda command: SimpleNamespace(
        returncode=0, stdout='unrelated-package: ' + command[-1]))
    assert browser_trust._linux_browser() is None


def test_linux_browser_accepts_expected_package_owner(monkeypatch):
    monkeypatch.setattr(browser_trust, '_root_owned_path', lambda _: True)
    monkeypatch.setattr(Path, 'is_file', lambda _: True)
    monkeypatch.setattr(browser_trust, '_run', lambda command: SimpleNamespace(
        returncode=0, stdout='google-chrome-stable: ' + command[-1]))
    assert browser_trust._linux_browser() == Path('/opt/google/chrome/chrome').resolve()
