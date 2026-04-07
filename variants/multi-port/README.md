# PortSniffer — Multi Port Variant

KMDF asosidagi Windows filter-driver va CLI vositasi. **Bir nechta** COM yoki
LPT portni bitta proses ichida parallel kuzatadi va eventlarni ixtiyoriy HTTP
API ga uzatadi.

Bitta port yetarli bo'lsa, `../single-port` variantini ishlating — uning
oqimi soddaroq.

## Tarkib

- `src/driver/` — KMDF filter driver (`EnlyzePortSniffer.sys`)
- `src/tool/` — CLI vositasi (`PortSniffer-Tool.exe`, multi-port qo'llab)
- `src/winforms/` — WinForms launcher
- `src/web/` — Logni qabul qiluvchi Flask server (test/dev)
- `src/ioctl.h` — Driver bilan tool o'rtasidagi IOCTL kontrakti

## CLI ishlatish

```
PortSniffer-Tool /install
PortSniffer-Tool /monitor PORT1 [PORT2 ...] TYPES [/forward URL]
PortSniffer-Tool /uninstall
```

- `PORT1 [PORT2 ...]` — masalan `COM3 COM4 COM5`. Bir vaqtning o'zida
  `MAX_MONITORING_PORTS` (10) tagacha port mumkin.
- `TYPES` — `R` (read), `W` (write), `C` (IOCTL) harflarining birikmasi.
- `/forward URL` — har bir tutilgan event JSON sifatida POST qilinadi.

### Misol

```
PortSniffer-Tool /monitor COM3 COM4 COM5 RWC /forward http://192.168.1.10:5000/ingest
```

### JSON payload

```json
{
  "port": "COM4",
  "timestamp": "2025-09-23T12:34:56.789Z",
  "type": 2,
  "length": 5,
  "data_hex": "48656C6C6F"
}
```

`type`: `1` = READ, `2` = WRITE, `4` = IOCTL. Har bir event qaysi portdan
kelganini `port` maydonida olib yuradi, shuning uchun ko'p port bitta API ga
oqsa ham, qabul qiluvchi tomonda ajratish oson.

### Konfiguratsiya fayli

`PortSniffer-Tool.exe` yonidagi `PortSniffer-Tool.config`:

```
forward_url=https://your.api/ingest
```

CLI'da `/forward` berilsa, u config'dan ustun turadi.

## WinForms launcher

`src/winforms/PortSniffer.WinForms` ichidagi mini GUI:

- API URL'ni saqlaydi (`PortSniffer-Tool.config` faylga yozadi)
- Bir nechta portni probel yoki vergul bilan kiritasiz: `COM3 COM4 COM5`
- TYPES tanlaysiz, Start/Stop bosasiz
- CLI chiqishini oynada ko'rsatadi

`PortSniffer-Tool.exe` WinForms `.exe` bilan bitta papkada bo'lishi kerak.

## Flask ingest server (`src/web/server.py`)

Test/dev uchun kichik HTTP server. Eventlarni qabul qiladi, hex'ni textga
o'giradi, port va type bo'yicha filter qiladi, ko'p qisqa eventlarni bitta
qatorga combine qiladi (multi-port ssenariy uchun ayniqsa qulay).

```
pip install flask
python src/web/server.py
```

Endpointlar:

| Method | Path     | Tavsif                                            |
| ------ | -------- | ------------------------------------------------- |
| GET    | `/`      | Health check                                      |
| POST   | `/ingest`| Bitta yoki batch JSON eventlarni qabul qiladi     |
| GET    | `/data`  | Saqlangan eventlar (filter va combine bilan)      |

`/data` query parametrlari: `port`, `type`, `limit`, `combine`. Masalan
`/data?port=COM4&combine=true` faqat COM4 eventlarini birlashtirib qaytaradi.

## Build qilish

Driver KMDF 1.9 bilan yaratilgan — Microsoft'ning **WDK 7.1.0** build
muhitini talab qiladi (Windows XP'gacha compat saqlangan).

1. WDK 7.1.0 ni o'rnating.
2. Build environment oching:
   - `Windows XP x86 Free Build Environment`, yoki
   - `Windows Server 2003 x64 Free Build Environment`.
3. Variant ildiziga o'ting va `build_all` ni chaqiring.

Natijada `redist_x86\` yoki `redist_AMD64\` papkasida:

- `EnlyzePortSniffer.sys`
- `PortSniffer-Tool.exe`
- `WdfCoInstaller01009.dll` (`/install` va `/uninstall` uchun talab qilinadi)

WinForms loyihasini Visual Studio yoki `dotnet build` bilan alohida
yig'asiz va `.exe`'ni `PortSniffer-Tool.exe` yoniga qo'yasiz.

## Driver Signature Enforcement

64-bit Windows imzosiz drayverlarni rad etadi. Test uchun:

- `shutdown /r /o` bilan reboot qiling, *Troubleshoot → Advanced options →
  Startup Settings → 7* (Disable Driver Signature Enforcement).
- 32-bit Windows'da bu cheklov yo'q.

## Multi-SZ iteratsiya bug fix (2025)

`installation.c:_DetachFromAllPorts` va `setup.c:HandleAttachedParameter`
funksiyalaridagi `wcslen(PortNames)` xatosi to'g'rilangan: endi
`wcslen(p)` ishlatiladi. Eski kodda port nomlari turli uzunlikda
bo'lganda (`COM3` va `COM10`, yoki `LPT1` va `COM10`) iteratsiya
stringlarning yarmidan o'qib garbage qaytarardi. Multi-port variantda bu
ayniqsa muhim, chunki real ssenariyda ko'pincha aralash uzunlikdagi nomlar
keladi.

Test (xost mashinada): `../test_wcslen_fix.c`, run: `../test_runner.py`.
Natija: 12/12 PASS.

## Litsenziya

MIT — qarang `LICENSE`. Asl loyiha mualliflari va keyingi forklarning
mualliflik xabarlari saqlanadi.
