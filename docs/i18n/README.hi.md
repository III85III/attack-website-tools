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

**हिन्दी**

OBSIDIAN वेबसाइट और API की सुरक्षा जाँच के लिए Windows ऐप है। इसमें रूट और JavaScript खोज, नियंत्रित जाँच तथा Word, HTML, Markdown और JSON रिपोर्ट हैं। केवल अधिकृत लक्ष्य जाँचें; संभावित समस्या पुष्ट भेद्यता नहीं होती।

> यह पृष्ठ परिचय और इंस्टॉलेशन का अनुवाद है; इससे ऐप की इंटरफ़ेस भाषा नहीं बदलती।

## आवश्यकताएँ

Windows x64 · Edge / Chrome

## इंस्टॉलेशन

Releases से OBSIDIAN_0.21.0_Windows-x64.zip डाउनलोड करके पूरा ZIP निकालें और OBSIDIAN.exe खोलें। _internal साथ रखें; Python आवश्यक नहीं। अनुमति की पुष्टि कर URL भरें, Scan Website दबाएँ और Export Word report से रिपोर्ट निकालें। यह बिना हस्ताक्षर वाला prerelease है; ब्राउज़र जाँच के लिए विश्वसनीय Edge या Chrome चाहिए।

[Releases](https://github.com/III85III/attack-website-tools/releases/tag/v0.20.0) · [SHA256SUMS_0.21.0.txt](https://github.com/III85III/attack-website-tools/releases/download/v0.21.0/SHA256SUMS_0.21.0.txt)

## सोर्स कोड प्राप्त करें

```bash
git clone https://github.com/III85III/attack-website-tools.git
cd attack-website-tools
```

## इंस्टॉलेशन · चलाएँ

**Windows · PowerShell**

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r tools/requirements/runtime.txt
.\.venv\Scripts\python.exe -m src
```

[Coverage](../OBSIDIAN_AUDIT.md) · [Verification](../verification/VERIFICATION_0.20.0.json)

विश्लेषण पेज, फ़ॉर्म, स्क्रिप्ट और API रूट को उनके खोज स्रोत से जोड़ता है। हेडर, कुकी, CORS, इनपुट प्रतिबिंब तथा दोहराए जा सकने वाले डेटाबेस त्रुटि या टेम्पलेट गणना संकेत जाँचे जाते हैं। पहुँच जाँच के लिए घोषित परीक्षण खाते और नियम आवश्यक हैं। रिपोर्ट गंभीरता, विश्वास और सत्यापन स्थिति अलग रखती है तथा प्रभावित घटक, संवेदनशील डेटा हटाए हुए प्रमाण, सुधार और दर्ज पुनरुत्पादन चरण दिखाती है। छोड़ी गई, अवरुद्ध और अनिर्णीत जाँच दिखाई देती हैं; कोई परिणाम न मिलना सुरक्षा का प्रमाण नहीं है।

## मूल दस्तावेज़ और तकनीकी विवरण

[README](../../README.md) · [GitHub](https://github.com/III85III/attack-website-tools)

[LICENSE](../../LICENSE)
