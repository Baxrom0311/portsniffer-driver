# Version Analysis

Bu hujjat eski ichma-ich snapshotlarni tozalashdan keyingi qarorni tushuntiradi.

## Faol variantlar

| Current path | Old source | Status | Nima uchun qoldirildi |
| --- | --- | --- | --- |
| `variants/single-port` | `driver/PortSniffer-master_birli/PortSniffer-master` | Active | Single-port oqimi aniq, CLI sodda, bitta COM port ssenariysi uchun mos |
| `variants/multi-port` | `driver/PortSniffer-master` | Active | Multi-port support bor, structure nisbatan toza, experimental branchlarga qaraganda canonical bazaga yaqinroq |

## Arxivga olingan snapshotlar

| Archive path | Old source | Status | Izoh |
| --- | --- | --- | --- |
| `archive/legacy/root-experimental-multi` | `PortSniffer-master` | Archived | Multi-port branchning keyingi eksperimenti. Qo'shimcha config va aggregation bor, lekin kod aralashib ketgan |
| `archive/legacy/yangi-loyha-gaz-monitoring/PortSniffer-master` | `driver/yangi_loyha_gaz_manitoring/PortSniffer-master` | Archived | Multi-port fork. Decoder va web tomonda qo'shimcha tajribalar bor |
| `archive/legacy/yangi-loyha-gaz-monitoring/PortSniffer-master_v1` | `driver/yangi_loyha_gaz_manitoring/PortSniffer-master_v1` | Archived | `v2` bilan amalda bir xil snapshot |
| `archive/legacy/yangi-loyha-gaz-monitoring/PortSniffer-master_v2` | `driver/yangi_loyha_gaz_manitoring/PortSniffer-master_v2` | Archived | `v1` bilan diff chiqmagan duplicate snapshot |
| `archive/legacy/sync-server` | `sync/` | Archived | Alohida Flask transaction server. Current tool payload oqimidan alohida yashab qolgan |
| `archive/legacy/PortSniffer Logs.html` | `driver/PortSniffer Logs.html` | Archived | Export qilingan log artefakt |
| `archive/legacy/PortSniffer-master.rar` | `driver/PortSniffer-master.rar` | Archived | Arxiv nusxa |
| `archive/legacy/main.py.txt` | `driver/main.py.txt` | Archived | Qo'lda saqlangan skript nusxasi |

## Single-port va Multi-port farqi

### Single-port

- Asosiy monitor command: `PortSniffer-Tool /monitor PORT TYPES [/forward URL]`
- Kod oqimi bitta COM portga qaratilgan
- Use case:
  Bir dona dispenser, bitta serial liniya, minimal complexity

### Multi-port

- Asosiy monitor command: `PortSniffer-Tool /monitor PORT1 [PORT2 ...] TYPES [/forward URL]`
- Bir vaqtning o'zida bir nechta COM portni kuzatadi
- Use case:
  Bir nechta dispenser yoki parallel monitoring kerak bo'lgan joy

## Tavsiya

- Yangi feature qo'shish kerak bo'lsa, faqat active variantlarga qo'shing.
- Avval single-port va multi-port o'rtasidagi umumiy qismni aniqlang.
- Arxivdagi snapshotlardan kod ko'chirishdan oldin farqni tekshirib, keyin maqsadli variantga toza tarzda merge qiling.
