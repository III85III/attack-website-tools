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

**Italiano**

OBSIDIAN è un’applicazione Windows per valutare siti e API: scoperta di percorsi e JavaScript, controlli mirati e rapporti Word, HTML, Markdown e JSON. Usala solo con autorizzazione; un indizio non equivale a una vulnerabilità confermata.

> Questa pagina traduce presentazione e installazione; non cambia la lingua dell’applicazione.

## Requisiti

Windows x64 · Edge / Chrome

## Installazione

Scarica OBSIDIAN_0.21.0_Windows-x64.zip da Releases, estrai l’intero ZIP e apri OBSIDIAN.exe. Mantieni _internal accanto; Python non serve. Conferma l’autorizzazione, inserisci l’URL, premi Scan Website ed esporta con Export Word report. Versione preliminare non firmata; la verifica richiede Edge o Chrome attendibile.

[Releases](https://github.com/III85III/attack-website-tools/releases/tag/v0.20.0) · [SHA256SUMS_0.21.0.txt](https://github.com/III85III/attack-website-tools/releases/download/v0.21.0/SHA256SUMS_0.21.0.txt)

## Scaricare il codice

```bash
git clone https://github.com/III85III/attack-website-tools.git
cd attack-website-tools
```

## Installazione · Avvio

**Windows · PowerShell**

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r tools/requirements/runtime.txt
.\.venv\Scripts\python.exe -m src
```

[Coverage](../OBSIDIAN_AUDIT.md) · [Verification](../verification/VERIFICATION_0.20.0.json)

L’analisi collega pagine, moduli, script e percorsi API alla fonte della scoperta. Esamina intestazioni, cookie, CORS, riflessione degli input e indicatori riproducibili di errori del database o valutazione dei template. I test di accesso richiedono account sintetici e regole dichiarate. I rapporti distinguono gravità, affidabilità e stato di verifica e riportano componenti coinvolti, prove ripulite, correzioni e passaggi di riproduzione se registrati. I controlli saltati, bloccati o inconcludenti restano visibili; nessun risultato non prova la sicurezza.

## Documentazione originale e dettagli tecnici

[README](../../README.md) · [GitHub](https://github.com/III85III/attack-website-tools)

[LICENSE](../../LICENSE)
