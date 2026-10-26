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

<div dir="rtl">

# OBSIDIAN

**العربية**

OBSIDIAN تطبيق Windows لتقييم أمان المواقع وواجهات API، مع اكتشاف المسارات وJavaScript وفحوص مضبوطة وتقارير Word وHTML وMarkdown وJSON. استخدمه على الأهداف المصرح بها فقط؛ الاشتباه ليس ثغرة مؤكدة.

> تترجم هذه الصفحة التعريف وطريقة التثبيت، ولا تغيّر لغة واجهة التطبيق.

## المتطلبات

Windows x64 · Edge / Chrome

## التثبيت

نزّل OBSIDIAN_0.20.0_Windows-x64.zip من Releases وفك الضغط كاملاً ثم افتح OBSIDIAN.exe. أبقِ _internal بجانبه؛ لا تحتاج Python. أكّد التصريح وأدخل URL ثم Scan Website، وللتقرير Export Word report. هذه نسخة أولية غير موقعة؛ التحقق بالمتصفح يحتاج Edge أو Chrome موثوقاً.

[Releases](https://github.com/III85III/attack-website-tools/releases/tag/v0.20.0) · [SHA256SUMS_0.20.0.txt](https://github.com/III85III/attack-website-tools/releases/download/v0.20.0/SHA256SUMS_0.20.0.txt)

## الحصول على الشيفرة

<div dir="ltr">

```bash
git clone https://github.com/III85III/attack-website-tools.git
cd attack-website-tools
```

</div>

## التثبيت · التشغيل

**Windows · PowerShell**

<div dir="ltr">

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe main.py
```

</div>

[Coverage](../OBSIDIAN_AUDIT.md) · [Verification](../verification/VERIFICATION_0.20.0.json)

## الوثائق الأصلية والتفاصيل التقنية

[README](../../README.md) · [GitHub](https://github.com/III85III/attack-website-tools)

[LICENSE](../../LICENSE)

</div>
