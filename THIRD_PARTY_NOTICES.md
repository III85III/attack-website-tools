# Third-Party Notices — Qolam Sentinel 0.19.0

Qolam Sentinel itself is licensed under GNU GPL-3.0-only; see `LICENSE` and `COPYRIGHT`. Bundled libraries retain their own licenses. License texts collected from the pinned package artifacts are provided in `THIRD_PARTY_LICENSES/` in the portable distribution.

| Component | Version | License | Use |
|---|---:|---|---|
| PyQt6 | 6.11.0 | GPL-3.0-only | Application UI bindings |
| Qt 6 runtime | 6.11.1 | LGPL-3.0 | Qt runtime libraries |
| PyQt6-sip | 13.11.1 | BSD-2-Clause | Python/Qt binding support |
| python-docx | 1.2.0 | MIT | DOCX reporting |
| requests | 2.34.2 | Apache-2.0 | HTTP requests |
| psutil | 7.2.2 | BSD-3-Clause | Local system information |
| defusedxml | 0.7.1 | PSF License | Safe XML parsing |
| edge-tts | 7.3.1 | LGPL-3.0; one source file MIT | Optional online speech synthesis |
| Playwright | 1.64.0 | Apache-2.0 | Browser execution verification and bundled driver |
| PyInstaller | 6.22.2 | GPL-2.0-or-later with bootloader exception | Build tool and bootloader |

The build environment can cause PyInstaller to collect additional transitive Python packages and native runtimes. This release includes their upstream license files where present in the installed artifacts; the complete bundled-component SBOM and native DLL notice audit remain to be finalized before a fully audited distribution. Review each included notice and the Qt/PyQt terms before redistribution or relinking.

Upstream references: [PyQt licensing](https://riverbankcomputing.com/software/pyqt/), [Qt licensing](https://www.qt.io/licensing/), [edge-tts license](https://github.com/rany2/edge-tts/blob/master/LICENSE), [PyInstaller license](https://github.com/pyinstaller/pyinstaller/blob/develop/COPYING.txt).
