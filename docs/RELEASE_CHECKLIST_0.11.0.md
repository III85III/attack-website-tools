# Release Checklist — 0.11.0

## Completed for this package

- [x] Python source files compile.
- [x] PyInstaller onedir Windows build succeeds.
- [x] OWASP ZAP active-scan profile is available with a temporary origin-scoped context, explicit authorization confirmation, progress polling, timeout, and alert import.
- [x] No external network target was scanned while preparing this package.

## Still required before calling this a stable public release

- [ ] Run OWASP ZAP against a controlled test fixture and verify context scoping, timeout stop, alert import, and cleanup against the supported ZAP version.
- [ ] Run a full regression and clean-machine installation/upgrade check on supported Windows versions.
- [ ] Complete the transitive dependency and native DLL license/SBOM audit; independently review security and privacy behavior.
- [ ] Render and visually inspect Word reports on supported Office/Word versions.
- [ ] Publish with a support/security contact and explain that ZAP is an optional separate install.
- [ ] Code-sign and publish checksums through the intended release channel.

This is a packaged release candidate; it has not been uploaded or independently audited. ZAP was not installed in the build environment, so the ZAP end-to-end flow has not been exercised here.
