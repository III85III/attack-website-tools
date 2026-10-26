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

**日本語**

OBSIDIAN は Web サイトと API を評価する Windows アプリです。ルートと JavaScript の探索、制御された検査、Word・HTML・Markdown・JSON レポートに対応します。許可された対象だけで使用してください。疑わしい結果は確認済みの脆弱性とは異なります。

> このページは概要と導入手順の翻訳です。アプリの表示言語は変わりません。

## 必要な環境

Windows x64 · Edge / Chrome

## インストール

Releases から OBSIDIAN_0.20.0_Windows-x64.zip を取得し、全体を展開して OBSIDIAN.exe を開きます。_internal は隣に残してください。Python は不要です。許可を確認して URL を入力し Scan Website、出力は Export Word report を選びます。未署名のプレリリースです。ブラウザー検証には信頼できる Edge または Chrome が必要です。

[Releases](https://github.com/III85III/attack-website-tools/releases/tag/v0.20.0) · [SHA256SUMS_0.20.0.txt](https://github.com/III85III/attack-website-tools/releases/download/v0.20.0/SHA256SUMS_0.20.0.txt)

## ソースコードの取得

```bash
git clone https://github.com/III85III/attack-website-tools.git
cd attack-website-tools
```

## インストール · 起動

**Windows · PowerShell**

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r tools/requirements/runtime.txt
.\.venv\Scripts\python.exe -m src
```

[Coverage](../OBSIDIAN_AUDIT.md) · [Verification](../verification/VERIFICATION_0.20.0.json)

解析ではページ、フォーム、スクリプト、API ルートを発見元と関連付けます。ヘッダー、Cookie、CORS、入力の反射、再現可能なデータベースエラーやテンプレート計算の兆候を確認します。アクセス検査には明示したテストアカウントと規則が必要です。レポートは深刻度、確信度、検証状態を分け、対象コンポーネント、秘匿処理した証拠、修正案、記録済みの再現手順を示します。未実施、ブロック、不確定の検査も表示し、検出なしを安全の証明とはしません。

## 元のドキュメントと技術情報

[README](../../README.md) · [GitHub](https://github.com/III85III/attack-website-tools)

[LICENSE](../../LICENSE)
