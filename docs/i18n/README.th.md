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

**ไทย**

OBSIDIAN เป็นแอป Windows สำหรับประเมินความปลอดภัยเว็บไซต์และ API มีการค้นหาเส้นทางและ JavaScript การตรวจแบบควบคุม และรายงาน Word, HTML, Markdown, JSON ใช้กับเป้าหมายที่ได้รับอนุญาตเท่านั้น ผลที่น่าสงสัยไม่ใช่ช่องโหว่ที่ยืนยันแล้ว

> หน้านี้แปลคำอธิบายและวิธีติดตั้ง ไม่ได้เปลี่ยนภาษาของส่วนติดต่อแอป

## สิ่งที่ต้องมี

Windows x64 · Edge / Chrome

## การติดตั้ง

ดาวน์โหลด OBSIDIAN_0.21.0_Windows-x64.zip จาก Releases แตก ZIP ทั้งหมดแล้วเปิด OBSIDIAN.exe เก็บ _internal ไว้ข้างกัน ไม่ต้องใช้ Python ยืนยันสิทธิ์ ใส่ URL แล้วเลือก Scan Website และ Export Word report เพื่อส่งออกรายงาน นี่เป็นรุ่นก่อนเผยแพร่ที่ไม่มีลายเซ็น การตรวจด้วยเบราว์เซอร์ต้องใช้ Edge หรือ Chrome ที่เชื่อถือได้

[Releases](https://github.com/III85III/attack-website-tools/releases/tag/v0.20.0) · [SHA256SUMS_0.21.0.txt](https://github.com/III85III/attack-website-tools/releases/download/v0.21.0/SHA256SUMS_0.21.0.txt)

## รับซอร์สโค้ด

```bash
git clone https://github.com/III85III/attack-website-tools.git
cd attack-website-tools
```

## การติดตั้ง · การเรียกใช้

**Windows · PowerShell**

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r tools/requirements/runtime.txt
.\.venv\Scripts\python.exe -m src
```

[Coverage](../OBSIDIAN_AUDIT.md) · [Verification](../verification/VERIFICATION_0.20.0.json)

การวิเคราะห์เชื่อมโยงหน้าเว็บ ฟอร์ม สคริปต์ และเส้นทาง API กับแหล่งที่ค้นพบ ตรวจเฮดเดอร์ คุกกี้ CORS การสะท้อนอินพุต และสัญญาณข้อผิดพลาดฐานข้อมูลหรือการคำนวณเทมเพลตที่ทำซ้ำได้ การทดสอบสิทธิ์ต้องมีบัญชีทดสอบและกฎที่ระบุชัด รายงานแยกความรุนแรง ความเชื่อมั่น และสถานะยืนยัน พร้อมส่วนที่ได้รับผลกระทบ หลักฐานที่ปกปิดข้อมูลละเอียดอ่อน วิธีแก้ และขั้นตอนทดสอบซ้ำที่บันทึกไว้ รายการที่ข้าม ถูกบล็อก หรือยังสรุปไม่ได้ยังแสดงอยู่ การไม่พบปัญหาไม่ได้พิสูจน์ว่าปลอดภัย

## เอกสารต้นฉบับและรายละเอียดทางเทคนิค

[README](../../README.md) · [GitHub](https://github.com/III85III/attack-website-tools)

[LICENSE](../../LICENSE)
