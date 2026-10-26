# Repository layout and build commands

The root keeps the application entry point, runtime dependencies, README and legal notices. Build helpers moved into `tools/`; development/build dependencies moved into `requirements/`. GitHub discovers contribution and security policies in `.github/`. Application modules and persisted data paths are unchanged.

| Previous path | Current path |
|---|---|
| `build_exe.py` | `tools/build_exe.py` |
| `package_release.py` | `tools/package_release.py` |
| `pyi_rth_qt6_dll.py` | `tools/pyi_rth_qt6_dll.py` |
| `StartSentinel.cs` | `tools/StartObsidian.cs` |
| `requirements-dev.txt` | `requirements/dev.txt` |
| `requirements-build.txt` | `requirements/build.txt` |
| `CONTRIBUTING.md` | `.github/CONTRIBUTING.md` |
| `SECURITY.md` | `.github/SECURITY.md` |

From the root, using the activated Python 3.11 environment:

```powershell
python -m pip install -r requirements/dev.txt
python -m pytest tests -q
python -m pip install -r requirements/build.txt
python tools/build_exe.py
python tools/package_release.py
```

Build scripts resolve the root from their own location. Packaging still refuses to overwrite an existing version. Source archives include the tools and requirement files at their current paths. Existing release tags/archives keep their original layout and checksums. This documentation change does not rebuild or replace the published 0.20.0 binary.

Language flags open localized introduction and installation guides. These pages do not translate the program UI. GitHub’s About description is a single repository setting and cannot switch per reader through README links. English technical details and historical audit records remain linked separately.
