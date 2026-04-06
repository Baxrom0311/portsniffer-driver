# PortSniffer Driver Workspace

Bu workspace tartibga keltirildi va endi faqat 2 ta asosiy variant bilan ishlaydi:

- `variants/single-port`: bitta COM port uchun soddaroq variant
- `variants/multi-port`: bir nechta COM port bilan ishlaydigan variant

Qolgan barcha snapshot, test nusxa va eksperimental branchlar `archive/legacy` ichiga ko'chirildi.

## Tuzilma

- `variants/single-port`
  Single-port build. CLI oqimi bitta portga qaratilgan va debug qilish osonroq.
- `variants/multi-port`
  Multi-port build. Bir proses ichida bir nechta COM portni monitoring qiladi.
- `docs/version-analysis.md`
  Qaysi eski papka qayerga o'tgani va nima uchun aynan shu 2 variant qoldirilgani.
- `archive/legacy`
  Eski snapshotlar, HTML loglar, `.rar`, Python test server va boshqa reference materiallar.

## Qaysi variantni ishlatish kerak

- Agar sizda bitta uskuna yoki bitta COM port bo'lsa, `variants/single-port` ni ishlating.
- Agar bir nechta dispenser yoki bir nechta COM portni parallel kuzatish kerak bo'lsa, `variants/multi-port` ni ishlating.

## Workspace qoidasi

- Kundalik development faqat `variants/single-port` va `variants/multi-port` ichida olib boriladi.
- `archive/legacy` faqat reference uchun. U yerdagi kod endi canonical emas.
- Yangi o'zgarish kiritilganda avval qaysi variantga tegishli ekani aniqlanadi, keyin faqat o'sha variant ichida ishlanadi.

## Qo'shimcha hujjat

Versiyalar tahlili: `docs/version-analysis.md`
