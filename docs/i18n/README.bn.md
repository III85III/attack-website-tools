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

**বাংলা**

OBSIDIAN হলো ওয়েবসাইট ও API নিরাপত্তা মূল্যায়নের Windows অ্যাপ। এতে রুট ও JavaScript অনুসন্ধান, নিয়ন্ত্রিত পরীক্ষা এবং Word, HTML, Markdown ও JSON প্রতিবেদন রয়েছে। শুধু অনুমোদিত লক্ষ্য পরীক্ষা করুন; সম্ভাব্য সমস্যা নিশ্চিত দুর্বলতা নয়।

> এই পাতায় পরিচিতি ও ইনস্টলেশনের অনুবাদ রয়েছে; অ্যাপের ইন্টারফেসের ভাষা বদলায় না।

## প্রয়োজনীয়তা

Windows x64 · Edge / Chrome

## ইনস্টলেশন

Releases থেকে OBSIDIAN_0.20.0_Windows-x64.zip নামিয়ে সম্পূর্ণ ZIP খুলুন এবং OBSIDIAN.exe চালান। _internal পাশে রাখুন; Python লাগে না। অনুমতি নিশ্চিত করে URL লিখুন, Scan Website চাপুন এবং Export Word report দিয়ে প্রতিবেদন নিন। এটি স্বাক্ষরবিহীন prerelease; ব্রাউজার যাচাইয়ে বিশ্বস্ত Edge বা Chrome দরকার।

[Releases](https://github.com/III85III/attack-website-tools/releases/tag/v0.20.0) · [SHA256SUMS_0.20.0.txt](https://github.com/III85III/attack-website-tools/releases/download/v0.20.0/SHA256SUMS_0.20.0.txt)

## সোর্স কোড সংগ্রহ

```bash
git clone https://github.com/III85III/attack-website-tools.git
cd attack-website-tools
```

## ইনস্টলেশন · চালু করুন

**Windows · PowerShell**

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe main.py
```

[Coverage](../OBSIDIAN_AUDIT.md) · [Verification](../verification/VERIFICATION_0.20.0.json)

## মূল নথি ও প্রযুক্তিগত বিবরণ

[README](../../README.md) · [GitHub](https://github.com/III85III/attack-website-tools)

[LICENSE](../../LICENSE)
