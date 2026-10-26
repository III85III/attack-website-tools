# Repository layout

The repository root has five visible project items: `README.md`, `LICENSE`, `src/`, `docs/` and `tools/`. Git configuration and GitHub policies remain in their standard hidden paths.

| Folder | Contents |
|---|---|
| `src/` | Existing application modules and `__main__.py` entry point |
| `docs/` | Guides, language flags, images, audit evidence and legal notices |
| `tools/` | Build and packaging helpers, tests and dependency lists |

From the root, with Python 3.11 on Windows:

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r tools/requirements/runtime.txt
.\.venv\Scripts\python.exe -m src
```

For development and builds, use the same environment:

```powershell
python -m pip install -r tools/requirements/dev.txt
python -m pytest tools/tests -q
python -m pip install -r tools/requirements/build.txt
python tools/build_exe.py
python tools/package_release.py
```

The application architecture, source-state base directory and frozen state resolver remain unchanged. Existing histories and release assets are not moved or rewritten. Historical tagged source archives use their original layout. Current source packages include the relocated files; version overwrite protection remains enabled.

Copyright and third-party attribution remain in `docs/legal/` and are copied into portable packages. GitHub recognizes the root GPL license and `.github/` contribution/security policies. Build paths, CI, localized setup commands and test imports follow the new layout.
