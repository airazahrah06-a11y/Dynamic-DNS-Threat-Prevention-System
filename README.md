# Dynamic DNS-Based Threat Prevention System

Sistem pencegahan ancaman berasaskan DNS yang memantau trafik DNS melalui **Pi-hole**, mengesan domain mencurigakan menggunakan analisis tingkah laku dan model AI, dan menyekat ancaman secara dinamik. Projek Tahun Akhir (FYP).

## Ciri-ciri

- **Default-deny**: semua domain disekat kecuali yang telah disahkan dan di-whitelist oleh admin
- **Pemantauan DNS masa nyata** dari log Pi-hole
- **Pengesanan ancaman** melalui peraturan (rule-based), analisis tingkah laku dan AI
- **Pangkalan data MySQL** untuk simpan log dan keputusan pengesanan
- **Dashboard web** (port 8501) untuk admin semak domain, whitelist/blacklist dan lihat log
- **Notifikasi amaran** bila ancaman dikesan

## Seni Bina

```
Pengguna -> Pi-hole (DNS) -> dns_monitor.py -> detector_engine.py
                                                   |-- behavior_analysis.py
                                                   |-- ai_engine.py
                                                   v
                                              db_writer.py -> MySQL
                                                   |
                                      dashboard.py + notifikasi amaran
```

## Struktur Fail

| Fail | Fungsi |
|------|--------|
| `main.py` | Titik mula, jalankan semua modul |
| `dns_monitor.py` | Baca dan pantau log DNS dari Pi-hole |
| `detector_engine.py` | Enjin pengesanan utama |
| `behavior_analysis.py` | Analisis corak tingkah laku domain/pengguna |
| `ai_engine.py` | Pengelasan domain menggunakan AI |
| `db_writer.py` | Simpan data ke MySQL |
| `dashboard.py` | Dashboard admin |
| `telegram_alert.py` | Modul notifikasi |

## Keperluan

- Pi-hole v6 (dalam VM / server berasingan)
- Python 3.x
- MySQL Server
- Pakej Python dalam `requirements.txt`

## Pemasangan

```bash
git clone https://github.com/airazahrah06-a11y/Dynamic-DNS-Threat-Prevention-System.git
cd Dynamic-DNS-Threat-Prevention-System

python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### Konfigurasi

1. Cipta pangkalan data MySQL: `[nama database]`
2. Set kelayakan (credentials) melalui environment variable atau fail `.env`:

```
DB_HOST=[...]
DB_USER=[...]
DB_PASSWORD=[...]
DB_NAME=[...]
```

3. Pastikan peranti pengguna menggunakan IP Pi-hole sebagai DNS server.

## Cara Menjalankan

```bash
# Jalankan enjin pengesanan
python main.py

# Jalankan dashboard (terminal lain)
streamlit run dashboard.py
```

Dashboard boleh diakses di `http://[IP-server]:8501`.

## Cara Ia Berfungsi

1. Pengguna cuba akses sesuatu domain.
2. Pi-hole sekat domain tersebut secara lalai.
3. Admin semak domain di dashboard, kemudian whitelist jika selamat.
4. Enjin pengesanan terus memantau dan menyekat domain yang dikesan berbahaya.



## Pembangun

[Nur Zahrah Ainaa,Puteri Syuhada,Damia Husna] - Projek Tahun Akhir, 2026
