# portsniffer-driver

Windows COM/LPT port trafigini KMDF filter-driver orqali tutib oladigan,
keyin uni HTTP API ga uzatadigan to'liq pipeline. Bu repo bitta loyiha
emas — bir nechta tarixiy snapshotlardan tartibga keltirilgan workspace
bo'lib, ikki **canonical variant**ni saqlaydi:

| Variant            | Maqsad                                                  |
| ------------------ | ------------------------------------------------------- |
| `variants/single-port` | Bitta COM port — sodda oqim, debug uchun qulay      |
| `variants/multi-port`  | Bir vaqtning o'zida 10 tagacha port (multi-port API)|

Har bir variant o'z `README.md`, `LICENSE`, va `src/` papkasiga ega.

## Tarkibi

```
portsniffer-driver/
├── README.md                    ← bu fayl
├── LICENSE                      ← MIT (root)
├── NOTICE                       ← upstream attribution
├── docs/
│   └── version-analysis.md      ← variantlar tarixi
├── variants/
│   ├── single-port/             ← maintained
│   ├── multi-port/              ← maintained
│   ├── test_wcslen_fix.c        ← multi-SZ bug fix uchun standalone test
│   └── test_runner.py           ← Python wrapper: gcc + run
└── archive/
    └── legacy/                  ← eski snapshotlar (canonical emas)
```

## Komponentlar

Har bir variant ichida quyidagilar bor:

- **KMDF driver** (`src/driver/EnlyzePortSniffer.sys`) — serial/parallel
  portga ulanadigan filter driver. KMDF 1.9'da yozilgan, Windows XP'gacha
  compat saqlangan.
- **CLI tool** (`src/tool/PortSniffer-Tool.exe`) — driverni o'rnatadi,
  portga ulaydi, eventlarni stdout'ga chiqaradi va ixtiyoriy ravishda HTTP
  API ga forward qiladi.
- **WinForms launcher** (`src/winforms/`) — CLI ustidan kichik GUI.
- **Flask ingest server** (`src/web/server.py`) — eventlarni qabul
  qiluvchi test server (Python).

## Tezkor ishga tushirish

1. **Driverni o'rnatish (admin):**
   ```
   PortSniffer-Tool /install
   ```

2. **Portni kuzatishni boshlash:**
   ```
   # single-port
   PortSniffer-Tool /monitor COM3 RWC

   # multi-port
   PortSniffer-Tool /monitor COM3 COM4 COM5 RWC
   ```

   `R`=read, `W`=write, `C`=IOCTL.

3. **HTTP API ga uzatish (ixtiyoriy):**
   ```
   PortSniffer-Tool /monitor COM3 RWC /forward http://192.168.1.10:5000/ingest
   ```

4. **Olib tashlash (admin, reboot kerak):**
   ```
   PortSniffer-Tool /uninstall
   ```

## JSON event formati

Driver tutgan har bir read/write/IOCTL event JSON sifatida yuboriladi:

```json
{
  "port": "COM3",
  "timestamp": "2025-09-23T12:34:56.789Z",
  "type": 1,
  "length": 5,
  "data_hex": "48656C6C6F"
}
```

`type`: `1`=READ, `2`=WRITE, `4`=IOCTL.

## Build qilish

Driver KMDF 1.9 ishlatadi, shuning uchun **WDK 7.1.0** build environment
talab qilinadi (Microsoft'dan tegishli ISO):

```
WDK 7.1.0 → "Windows XP x86 Free Build Environment" yoki
            "Windows Server 2003 x64 Free Build Environment"
cd variants/<variant>
build_all
```

Natija `redist_x86\` yoki `redist_AMD64\` papkasida:
`EnlyzePortSniffer.sys`, `PortSniffer-Tool.exe`, `WdfCoInstaller01009.dll`.

Tafsilotlar uchun har variantning o'z README.md fayliga qarang.

## Multi-SZ iteratsiya bug fix

2025'da `installation.c:_DetachFromAllPorts` va
`setup.c:HandleAttachedParameter` funksiyalaridagi multi-SZ string
iteratsiya bug'i to'g'rilangan:

```c
// Eski (BUGGY):
for (p = pResponse->PortNames; *p; p += wcslen(pResponse->PortNames) + 1)

// Yangi (FIXED):
for (p = pResponse->PortNames; *p; p += wcslen(p) + 1)
```

Eski kod port nomlari turli uzunlikda bo'lganda (masalan `COM3` va
`COM10`) iteratsiya stringlarning yarmidan o'qib garbage qaytarardi.

Bug uchun standalone test:

```
# Windows mashinada:
gcc -Wall -o test_fix.exe variants/test_wcslen_fix.c
./test_fix.exe
# Yoki Python wrapper orqali:
python variants/test_runner.py
```

Natija: 12/12 PASS — fix barcha holatlarda ishlaydi.

## Driver Signature Enforcement

64-bit Windows imzosiz drayverlarni rad etadi. Development uchun:

- `shutdown /r /o` → *Troubleshoot → Advanced options → Startup
  Settings → 7* (Disable Driver Signature Enforcement).
- 32-bit Windows'da bu cheklov yo'q.

Production deployment uchun WHQL imzo yoki cross-sign kerak.

## Workspace qoidasi

- Yangi development faqat `variants/single-port` va `variants/multi-port`
  ichida olib boriladi.
- `archive/legacy` — faqat reference; u yerdagi kod **canonical emas**.
- Yangi feature qo'shganda avval qaysi variantga tegishli ekani aniqlanadi.
- Variantlar orasida o'rtak kod paydo bo'lsa, uni qo'lda copy-paste qilish
  o'rniga umumiy joyga (kelajakda `variants/common/`) ko'chirish ko'rib
  chiqiladi.

## Hujjatlar

- `docs/version-analysis.md` — eski papkalar qayerdan kelgani va nima
  uchun aynan shu 2 variant qoldirilgani.
- `variants/single-port/README.md` — single-port variant tafsilotlari.
- `variants/multi-port/README.md` — multi-port variant tafsilotlari.

## Litsenziya

MIT. Qarang `LICENSE`. Bu repository upstream "ENLYZE PortSniffer"
loyihasidan fork qilingan; asl mualliflik xabarlari source fayllar va
`NOTICE` faylida saqlanadi.
