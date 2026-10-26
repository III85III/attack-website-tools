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

**简体中文**

OBSIDIAN 是用于评估网站和 API 安全性的 Windows 应用，支持发现路由和 JavaScript、受控检查以及 Word、HTML、Markdown 和 JSON 报告。只能在获得授权的目标上使用；疑似问题不等于已确认的漏洞。

> 本页提供项目介绍和安装说明的翻译，不会改变应用程序的界面语言。

## 环境要求

Windows x64 · Edge / Chrome

## 安装

从 Releases 下载 OBSIDIAN_0.21.0_Windows-x64.zip，完整解压并运行 OBSIDIAN.exe。保留旁边的 _internal 文件夹，无需 Python。确认授权后输入 URL，点击 Scan Website，再用 Export Word report 导出。这是未签名的预发布版；浏览器验证需要可信的 Edge 或 Chrome。

[Releases](https://github.com/III85III/attack-website-tools/releases/tag/v0.20.0) · [SHA256SUMS_0.21.0.txt](https://github.com/III85III/attack-website-tools/releases/download/v0.21.0/SHA256SUMS_0.21.0.txt)

## 获取源码

```bash
git clone https://github.com/III85III/attack-website-tools.git
cd attack-website-tools
```

## 安装 · 运行

**Windows · PowerShell**

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r tools/requirements/runtime.txt
.\.venv\Scripts\python.exe -m src
```

[Coverage](../OBSIDIAN_AUDIT.md) · [Verification](../verification/VERIFICATION_0.20.0.json)

分析将页面、表单、脚本和 API 路由与发现来源关联起来，检查响应头、Cookie、CORS、输入反射，以及可重复的数据库错误或模板计算迹象。访问控制检查需要明确提供测试账户和规则。报告区分严重性、置信度和验证状态，并列出受影响组件、脱敏证据、修复建议以及已记录的复现步骤。跳过、受阻和结论不明确的检查仍会显示；没有发现问题不等于网站已被证明安全。

## 原始文档与技术详情

[README](../../README.md) · [GitHub](https://github.com/III85III/attack-website-tools)

[LICENSE](../../LICENSE)
