# Telegram Block Checker Bot (OONI API)

Bot Telegram untuk memantau link yang diblokir di Indonesia.
Menggunakan data dari **OONI (Open Observatory of Network Interference)** — jaringan global yang mengukur internet censorship di seluruh dunia, termasuk Indonesia.

## Cara Pakai

1. Install dependencies:
```bash
pip install -r requirements.txt
```

2. Set bot token (pilih salah satu):
```bash
# Environment variable (direkomendasikan):
export BOT_TOKEN="123456:ABC-DEF..."

# Atau edit BOT_TOKEN langsung di bot.py
```

3. Jalankan (bisa dari mana saja, tidak harus Indonesia):
```bash
python bot.py
```

4. Buka Telegram, cari bot, dan kirim `/start`

## Deploy ke Railway (Gratis, 24/7, No Credit Card)

1. Fork/upload repo ini ke GitHub
2. Buka [railway.com](https://railway.com) → Login with GitHub
3. **New Project** → **Deploy from GitHub repo**
4. Pilih repo `telegram-block-checker`
5. Set environment variable: `BOT_TOKEN` = token bot-mu
6. Railway auto-deploy → bot jalan 24/7

## Perintah

| Perintah | Deskripsi |
|----------|-----------|
| `/add <url>` | Tambah link ke pantauan |
| `/remove <url>` | Hapus link dari pantauan |
| `/list` | Lihat link yang dipantau |
| `/check` | Cek semua link sekarang |
| `/status <url>` | Cek status link tertentu |
| `/help` | Bantuan |

## Cara Kerja

1. **OONI API** (primary) — Query ke OONI untuk data pengukuran web_connectivity dari ISP Indonesia
   - `confirmed=true` → website dikonfirmasi diblokir
   - `anomaly=true` → kemungkinan diblokir
   - `blocking_general > 0.5` → skor blokir tinggi
2. **DNS Check** (fallback) — Jika OONI tidak punya data:
   - Resolve domain via DNS lokal vs DNS internasional
   - Jika IP beda → DNS poisoning → diblokir
   - Jika IP masuk range TRUI/Kominfo → diblokir

## Cache & Notifikasi

- OONI result di-cache 1 jam (configurable via `OONI_CACHE_TTL`)
- Notifikasi otomatis dikirim saat status berubah:
  - Aman → Diblokir 🔴
  - Diblokir → Aman 🟢
- Background check tiap 1 jam (configurable via `CHECK_INTERVAL`)

## File

| File | Keterangan |
|------|------------|
| `bot.py` | Kode utama bot |
| `links_db.json` | Database link per chat (auto-generated) |
| `status_cache.json` | Cache status untuk notifikasi (auto-generated) |
| `requirements.txt` | Dependencies Python |
| `railway.toml` | Konfigurasi deploy Railway |

## Spesifikasi OONI API

Endpoint: `https://api.ooni.io/api/v1/measurements`
Parameters:
- `probe_cc=ID` — Filter hanya pengukuran dari Indonesia
- `test_name=web_connectivity` — Jenis tes web connectivity
- `input=<url>` — URL yang ingin dicek
- `limit=10` — Maksimal 10 pengukuran terbaru

Response:
- `results[].anomaly` — True jika ada anomali
- `results[].confirmed` — True jika dikonfirmasi diblokir (blockpage terdeteksi)
- `results[].scores` — Skor blocking (0-1)

## Credits

- [OONI](https://ooni.org/) — Open Observatory of Network Interference
- [python-telegram-bot](https://python-telegram-bot.org/) — Telegram Bot Framework
