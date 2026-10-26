<!-- language-selector:start -->
<p align="center">
<a href="../../README.md" title="English"><img src="flags/gb.svg" width="30" height="20" alt="English"></a>
<a href="README.fa.md" title="فارسی"><img src="flags/ir.svg" width="30" height="20" alt="فارسی"></a>
<a href="README.es.md" title="Español"><img src="flags/es.svg" width="30" height="20" alt="Español"></a>
<a href="README.fr.md" title="Français"><img src="flags/fr.svg" width="30" height="20" alt="Français"></a>
<a href="README.de.md" title="Deutsch"><img src="flags/de.svg" width="30" height="20" alt="Deutsch"></a>
<a href="README.pt-BR.md" title="Português"><img src="flags/br.svg" width="30" height="20" alt="Português"></a>
<a href="README.it.md" title="Italiano"><img src="flags/it.svg" width="30" height="20" alt="Italiano"></a>
<a href="README.ru.md" title="Русский"><img src="flags/ru.svg" width="30" height="20" alt="Русский"></a>
<a href="README.zh-CN.md" title="简体中文"><img src="flags/cn.svg" width="30" height="20" alt="简体中文"></a>
<a href="README.ja.md" title="日本語"><img src="flags/jp.svg" width="30" height="20" alt="日本語"></a>
<a href="README.ko.md" title="한국어"><img src="flags/kr.svg" width="30" height="20" alt="한국어"></a>
<a href="README.ar.md" title="العربية"><img src="flags/sa.svg" width="30" height="20" alt="العربية"></a>
<a href="README.hi.md" title="हिन्दी"><img src="flags/in.svg" width="30" height="20" alt="हिन्दी"></a>
<a href="README.bn.md" title="বাংলা"><img src="flags/bd.svg" width="30" height="20" alt="বাংলা"></a>
<a href="README.ur.md" title="اردو"><img src="flags/pk.svg" width="30" height="20" alt="اردو"></a>
<a href="README.tr.md" title="Türkçe"><img src="flags/tr.svg" width="30" height="20" alt="Türkçe"></a>
<a href="README.id.md" title="Bahasa Indonesia"><img src="flags/id.svg" width="30" height="20" alt="Bahasa Indonesia"></a>
<a href="README.vi.md" title="Tiếng Việt"><img src="flags/vn.svg" width="30" height="20" alt="Tiếng Việt"></a>
<a href="README.th.md" title="ไทย"><img src="flags/th.svg" width="30" height="20" alt="ไทย"></a>
<a href="README.pl.md" title="Polski"><img src="flags/pl.svg" width="30" height="20" alt="Polski"></a>
</p>
<!-- language-selector:end -->

# OBSIDIAN

**한국어**

OBSIDIAN은 웹사이트와 API를 평가하는 Windows 앱입니다. 경로 및 JavaScript 탐색, 통제된 검사, Word·HTML·Markdown·JSON 보고서를 제공합니다. 허가받은 대상에만 사용하세요. 의심되는 결과는 확인된 취약점과 다릅니다.

> 이 페이지는 소개와 설치 안내를 번역한 것이며 앱의 표시 언어는 변경하지 않습니다.

## 필수 환경

Windows x64 · Edge / Chrome

## 설치

Releases에서 OBSIDIAN_0.20.0_Windows-x64.zip을 받아 전체 압축을 풀고 OBSIDIAN.exe를 실행하세요. _internal은 옆에 두어야 하며 Python은 필요 없습니다. 권한을 확인하고 URL을 입력한 뒤 Scan Website, 보고서는 Export Word report를 선택하세요. 서명되지 않은 사전 출시 버전이며 브라우저 검증에는 신뢰할 수 있는 Edge 또는 Chrome이 필요합니다.

[Releases](https://github.com/III85III/attack-website-tools/releases/tag/v0.20.0) · [SHA256SUMS_0.20.0.txt](https://github.com/III85III/attack-website-tools/releases/download/v0.20.0/SHA256SUMS_0.20.0.txt)

## 소스 코드 받기

```bash
git clone https://github.com/III85III/attack-website-tools.git
cd attack-website-tools
```

## 설치 · 실행

**Windows · PowerShell**

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r tools/requirements/runtime.txt
.\.venv\Scripts\python.exe -m src
```

[Coverage](../OBSIDIAN_AUDIT.md) · [Verification](../verification/VERIFICATION_0.20.0.json)

분석은 페이지, 폼, 스크립트, API 경로를 발견 출처와 연결합니다. 헤더, 쿠키, CORS, 입력 반사, 재현 가능한 데이터베이스 오류나 템플릿 계산 징후를 검사합니다. 접근 검사는 명시된 테스트 계정과 규칙이 필요합니다. 보고서는 심각도, 신뢰도, 검증 상태를 구분하고 영향받는 구성 요소, 민감 정보를 가린 증거, 수정 안내와 기록된 재현 단계를 제공합니다. 건너뛰거나 차단되거나 결론이 불명확한 검사도 표시하며, 탐지 결과가 없다고 안전을 입증한 것은 아닙니다.

## 원본 문서 및 기술 정보

[README](../../README.md) · [GitHub](https://github.com/III85III/attack-website-tools)

[LICENSE](../../LICENSE)
