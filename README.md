<!-- language-selector:start -->
<p align="center">
<a href="README.md" title="English"><img src="docs/i18n/flags/gb.svg" width="30" height="20" alt="English"></a>
<a href="docs/i18n/README.fa.md" title="فارسی"><img src="docs/i18n/flags/ir.svg" width="30" height="20" alt="فارسی"></a>
<a href="docs/i18n/README.es.md" title="Español"><img src="docs/i18n/flags/es.svg" width="30" height="20" alt="Español"></a>
<a href="docs/i18n/README.fr.md" title="Français"><img src="docs/i18n/flags/fr.svg" width="30" height="20" alt="Français"></a>
<a href="docs/i18n/README.de.md" title="Deutsch"><img src="docs/i18n/flags/de.svg" width="30" height="20" alt="Deutsch"></a>
<a href="docs/i18n/README.pt-BR.md" title="Português"><img src="docs/i18n/flags/br.svg" width="30" height="20" alt="Português"></a>
<a href="docs/i18n/README.it.md" title="Italiano"><img src="docs/i18n/flags/it.svg" width="30" height="20" alt="Italiano"></a>
<a href="docs/i18n/README.ru.md" title="Русский"><img src="docs/i18n/flags/ru.svg" width="30" height="20" alt="Русский"></a>
<a href="docs/i18n/README.zh-CN.md" title="简体中文"><img src="docs/i18n/flags/cn.svg" width="30" height="20" alt="简体中文"></a>
<a href="docs/i18n/README.ja.md" title="日本語"><img src="docs/i18n/flags/jp.svg" width="30" height="20" alt="日本語"></a>
<a href="docs/i18n/README.ko.md" title="한국어"><img src="docs/i18n/flags/kr.svg" width="30" height="20" alt="한국어"></a>
<a href="docs/i18n/README.ar.md" title="العربية"><img src="docs/i18n/flags/sa.svg" width="30" height="20" alt="العربية"></a>
<a href="docs/i18n/README.hi.md" title="हिन्दी"><img src="docs/i18n/flags/in.svg" width="30" height="20" alt="हिन्दी"></a>
<a href="docs/i18n/README.bn.md" title="বাংলা"><img src="docs/i18n/flags/bd.svg" width="30" height="20" alt="বাংলা"></a>
<a href="docs/i18n/README.ur.md" title="اردو"><img src="docs/i18n/flags/pk.svg" width="30" height="20" alt="اردو"></a>
<a href="docs/i18n/README.tr.md" title="Türkçe"><img src="docs/i18n/flags/tr.svg" width="30" height="20" alt="Türkçe"></a>
<a href="docs/i18n/README.id.md" title="Bahasa Indonesia"><img src="docs/i18n/flags/id.svg" width="30" height="20" alt="Bahasa Indonesia"></a>
<a href="docs/i18n/README.vi.md" title="Tiếng Việt"><img src="docs/i18n/flags/vn.svg" width="30" height="20" alt="Tiếng Việt"></a>
<a href="docs/i18n/README.th.md" title="ไทย"><img src="docs/i18n/flags/th.svg" width="30" height="20" alt="ไทย"></a>
<a href="docs/i18n/README.pl.md" title="Polski"><img src="docs/i18n/flags/pl.svg" width="30" height="20" alt="Polski"></a>
</p>
<!-- language-selector:end -->

<p align="center"><img src="assets/obsidian-banner.svg" alt="OBSIDIAN — website and API security assessment" width="100%"></p>

<p align="center"><a href="https://github.com/III85III/attack-website-tools/releases/tag/v0.20.0"><strong>Download Windows app</strong></a> · <a href="docs/USER_GUIDE_EN.md">User guide</a> · <a href="docs/OBSIDIAN_AUDIT.md">Coverage and limitations</a></p>

# OBSIDIAN

**Web security assessment for websites and APIs you are authorized to test.**

Enter a URL, run the available checks, inspect the evidence and export a report. OBSIDIAN combines application mapping, JavaScript/API discovery, controlled verification and optional test-account access checks in a Windows desktop application.

## Install and run

1. Download **[OBSIDIAN_0.20.0_Windows-x64.zip](https://github.com/III85III/attack-website-tools/releases/download/v0.20.0/OBSIDIAN_0.20.0_Windows-x64.zip)**.
2. Extract the complete ZIP and open **OBSIDIAN.exe**. Keep `_internal` beside it. Python is not required.
3. Confirm that you have permission, enter the website URL and select **Scan Website**.
4. Review the findings, then export **Word, HTML, Markdown or JSON**.

Right-click the Scan button for optional test-account or OpenAPI setup. Browser confirmation needs a supported signed Edge or Chrome installation; ZAP and Nmap are optional separate tools.

## What you get

| Capability | What it does |
|---|---|
| Application mapping | Connects discovered pages, forms, scripts, API routes and source maps to their discovery evidence. |
| Controlled verification | Compares baselines and controls; browser XSS becomes validated only with matching execution proof. SQL errors remain error-disclosure candidates. |
| Explicit access checks | Uses supplied synthetic identities, declared resources and expected permissions instead of guessing ownership. |
| Useful reports | Keeps severity, confidence, verification status, evidence and coverage limitations separate. |

![OBSIDIAN scanner interface](docs/images/scanner.png)

## Evidence and limits

Version 0.20.0 passed **289 regression tests locally and in GitHub Windows CI**. Frozen-runtime tests verified actual request counts, persistence and report generation/reopening. The small labeled corpora do not establish universal accuracy.

**Unsigned release candidate.** Potential findings are not confirmed vulnerabilities. Stored/blind XSS, complete authentication lifecycles and business workflows need explicit assessment. Visual Word page rendering remains unverified. Only test within written authorization and the agreed scope.

[Verification record](docs/verification/VERIFICATION_0.20.0.json) · [Detailed audit](docs/OBSIDIAN_AUDIT.md) · [Full 0.20.0 technical README](https://github.com/III85III/attack-website-tools/blob/v0.20.0/README.md)

## Run from current source

Windows x64 and Python 3.11:

```powershell
git clone https://github.com/III85III/attack-website-tools.git
cd attack-website-tools
py -3.11 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe main.py
```

Development: install `requirements/dev.txt`, then run `python -m pytest tests -q`. Build: install `requirements/build.txt`, then run `python tools/build_exe.py` and `python tools/package_release.py`. Run these commands from the repository root using the same environment. Published 0.20.0 source archives retain their original layout; the current layout applies to this branch.

## Project layout

`main.py` starts the app. `src/` contains the application, `tests/` its regression tests, `tools/` the build/launcher helpers, `requirements/` development dependencies, and `docs/` the guides and translations. [Build and folder guide](docs/REPOSITORY_LAYOUT.md).

## Privacy and support

Protect API keys, cookies, sessions and customer data. The app stores history locally; active scans contact the selected target. CT discovery contacts its provider, and optional online speech sends selected text to its provider after confirmation.

[Report a bug](https://github.com/III85III/attack-website-tools/issues) · [Security policy](.github/SECURITY.md) · [Contributing](.github/CONTRIBUTING.md)

**GPL-3.0-only.** See [LICENSE](LICENSE), [COPYRIGHT](COPYRIGHT) and [third-party notices](THIRD_PARTY_NOTICES.md).
