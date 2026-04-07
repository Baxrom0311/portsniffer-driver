# PortSniffer — Single Port Variant

KMDF asosidagi Windows filter-driver va CLI vositasi. Bitta COM yoki LPT port
trafigini (read / write / IOCTL) tutib oladi va ixtiyoriy ravishda HTTP API
ga uzatadi.

Bu variant **bitta port** bilan ishlash uchun mo'ljallangan. Bir nechta portni
parallel kuzatish kerak bo'lsa, `../multi-port` variantini ishlating.

## Tarkib

- `src/driver/` — KMDF filter driver (`EnlyzePortSniffer.sys`)
- `src/tool/` — CLI vositasi (`PortSniffer-Tool.exe`)
- `src/winforms/` — Soddalashtirilgan WinForms launcher
- `src/web/` — Logni qabul qiluvchi Flask server (test/dev)
- `src/ioctl.h` — Driver bilan tool o'rtasidagi IOCTL kontrakti

## CLI ishlatish

```
PortSniffer-Tool /install
PortSniffer-Tool /monitor PORT TYPES [/forward URL]
PortSniffer-Tool /uninstall
```

- `PORT` — masalan `COM3`
- `TYPES` — `R` (read), `W` (write), `C` (IOCTL) harflarining birikmasi.
  Masalan `RW` faqat ma'lumot o'qish va yozishni kuzatadi.
- `/forward URL` — har bir tutilgan event JSON sifatida POST qilinadi.

### Misol

```
PortSniffer-Tool /monitor COM3 RWC /forward http://192.168.1.10:5000/ingest
```

### JSON payload

```json
{
  "port": "COM3",
  "timestamp": "2025-09-23T12:34:56.789Z",
  "type": 1,
  "length": 5,
  "data_hex": "48656C6C6F"
}
```

`type`: `1` = READ, `2` = WRITE, `4` = IOCTL. `data_hex` — tutilgan baytlar
hex shaklida.

### Konfiguratsiya fayli

`PortSniffer-Tool.exe` yonidagi `PortSniffer-Tool.config` faylida default URL:

```
forward_url=https://your.api/ingest
```

CLI'da `/forward` berilsa, u config'dan ustun turadi.

## WinForms launcher

`src/winforms/PortSniffer.WinForms` ichidagi mini GUI quyidagilarni qiladi:

- API URL'ni saqlaydi (`PortSniffer-Tool.config` faylga yozadi)
- Port va TYPES tanlab Start/Stop bosadi
- CLI chiqishini oynada ko'rsatadi

`PortSniffer-Tool.exe` WinForms `.exe` bilan bitta papkada bo'lishi kerak.

## Flask ingest server (`src/web/server.py`)

Test/dev uchun kichik HTTP server. Eventlarni qabul qiladi, hex'ni textga
o'giradi, port va type bo'yicha filter qiladi, ko'p qisqa eventlarni bitta
qatorga combine qiladi.

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

`/data` query parametrlari: `port`, `type`, `limit`, `combine`.

## Build qilish

Driver KMDF 1.9 bilan yaratilgan, shuning uchun Microsoft'ning **WDK 7.1.0**
build muhitini talab qiladi (Windows XP'gacha bo'lgan compatibility uchun
saqlangan).

1. WDK 7.1.0 ni o'rnating.
2. Kerakli build environment'ni oching:
   - `Windows XP x86 Free Build Environment`, yoki
   - `Windows Server 2003 x64 Free Build Environment`.
3. Variant ildiziga o'ting va `build_all` ni chaqiring.

Natijada `redist_x86\` yoki `redist_AMD64\` papkasida quyidagilar paydo
bo'ladi:

- `EnlyzePortSniffer.sys`
- `PortSniffer-Tool.exe`
- `WdfCoInstaller01009.dll` (kernel-mode WDF coinstaller — `/install` va
  `/uninstall` uchun talab qilinadi)

WinForms loyihasini Visual Studio yoki `dotnet build` bilan alohida
yig'asiz va `.exe`'ni `PortSniffer-Tool.exe` yoniga qo'yasiz.

## Driver Signature Enforcement

64-bit Windows imzosiz drayverlarni rad etadi. Test uchun:

- `shutdown /r /o` bilan reboot qiling, *Troubleshoot → Advanced options →
  Startup Settings → 7* (Disable Driver Signature Enforcement).
- 32-bit Windows'da bu cheklov yo'q.

Imzolangan release uchun WHQL yoki cross-sign kerak.

## Multi-SZ iteratsiya bug fix (2025)

`installation.c:_DetachFromAllPorts` va `setup.c:HandleAttachedParameter`
funksiyalaridagi `wcslen(PortNames)` xatosi to'g'rilangan: endi
`wcslen(p)` ishlatiladi. Eski kodda port nomlari **turli uzunlikda**
bo'lganda (masalan `COM3` va `COM10`) iteratsiya stringlarning yarmidan
o'qib, garbage qaytarardi. Bir xil uzunlikdagi nomlarda bug tasodifan
sezilmas edi.

Test (xost mashinada): `../test_wcslen_fix.c`, run: `../test_runner.py`.

## Litsenziya

MIT — qarang `LICENSE`. Asl loyiha mualliflari va keyingi forklarning
mualliflik xabarlari saqlanadi.
