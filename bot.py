"""
Telegram Bot - Blocked Link Checker for Indonesia
Menggunakan OONI API (Open Observatory of Network Interference) sebagai sumber data utama.
Data berasal dari OONI Probe yang tersebar di berbagai ISP Indonesia.
Bot bisa dijalankan dari mana saja (tidak harus dari Indonesia).
"""
import os
import re
import json
import time
import logging
from urllib.parse import urlparse
from datetime import datetime, timedelta

import dns.resolver
import httpx
from telegram import Update, BotCommand
from telegram.ext import (
    Application,
    CommandHandler,
    ContextTypes,
)

# ─── Konfigurasi ───────────────────────────────────────────────────────────
BOT_TOKEN = os.environ.get("BOT_TOKEN", "ISI_TOKEN_KAMU_DI_SINI")
CHECK_INTERVAL_SECONDS = int(os.environ.get("CHECK_INTERVAL", "3600"))  # 1 jam
OONI_CACHE_TTL = int(os.environ.get("OONI_CACHE_TTL", "3600"))  # cache 1 jam

# DNS resolver internasional untuk fallback check
CLEAN_DNS = ["8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1"]

# IP range milik TRUI / Kominfo yang biasa dipakai untuk halaman blokir
BLOCKED_IP_PATTERNS = [
    "103.77.208.",   # TRUI / Kominfo block page
    "103.77.209.",
    "103.77.210.",
    "103.77.211.",
    "103.24.24.",
    "180.178.94.",
    "103.129.220.",
    "103.129.221.",
    "45.118.112.",
]

# Logging
logging.basicConfig(
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    level=logging.INFO,
)
logger = logging.getLogger(__name__)


# ─── OONI API Client ────────────────────────────────────────────────────────
OONI_API_BASE = "https://api.ooni.io/api/v1"

# Cache untuk hasil OONI (dengan TTL)
_ooni_cache: dict[str, dict] = {}  # domain -> {"result": ..., "timestamp": ...}


def ooni_check(domain: str) -> dict:
    """
    Cek blokir via OONI API.
    Mengembalikan dict dengan keys:
      - found: bool (apakah ada data OONI)
      - blocked: bool (apakah diblokir)
    """
    url = f"https://{domain}" if not domain.startswith(("http://", "https://")) else domain
    
    # Cek cache
    now = time.time()
    if domain in _ooni_cache:
        cached = _ooni_cache[domain]
        if now - cached["timestamp"] < OONI_CACHE_TTL:
            logger.debug(f"OONI cache hit for {domain}")
            return cached["result"]
    
    result = {
        "found": False,
        "blocked": False,
        "confirmed": False,
        "anomaly": False,
        "reason": "",
        "measurement_count": 0,
        "latest_measurement": None,
    }
    
    try:
        resp = httpx.get(
            f"{OONI_API_BASE}/measurements",
            params={
                "probe_cc": "ID",
                "test_name": "web_connectivity",
                "input": url,
                "limit": 10,
                "order_by": "measurement_start_time",
                "order": "desc",
            },
            timeout=15,
        )
        
        if resp.status_code == 429:
            result["reason"] = "OONI rate limit — coba lagi nanti"
            return result
        
        resp.raise_for_status()
        data = resp.json()
        
        measurements = data.get("results", [])
        if not measurements:
            result["reason"] = "Tidak ada data OONI untuk domain ini"
            return result
        
        result["found"] = True
        result["measurement_count"] = len(measurements)
        
        # Analisis hasil pengukuran
        anomaly_count = 0
        confirmed_count = 0
        failure_count = 0
        
        for m in measurements:
            if m.get("anomaly"):
                anomaly_count += 1
            if m.get("confirmed"):
                confirmed_count += 1
            if m.get("failure"):
                failure_count += 1
        
        # Ambil pengukuran terbaru
        latest = measurements[0]
        result["latest_measurement"] = latest.get("measurement_start_time", "unknown")
        
        # Scores dari pengukuran terbaru
        scores = latest.get("scores", {})
        blocking_general = scores.get("blocking_general", 0)
        blocking_country = scores.get("blocking_country", 0)
        blocking_isp = scores.get("blocking_isp", 0)
        
        # Decision logic
        if confirmed_count > 0:
            result["blocked"] = True
            result["confirmed"] = True
            result["reason"] = f"Dikonfirmasi diblokir ({confirmed_count}/{len(measurements)} pengukuran)"
        elif anomaly_count > 0 or blocking_general > 0.5:
            result["blocked"] = True
            result["anomaly"] = True
            if blocking_country > 0.5:
                result["reason"] = f"Blokir tingkat negara terdeteksi (skor: {blocking_country:.2f})"
            elif blocking_isp > 0.5:
                result["reason"] = f"Blokir tingkat ISP terdeteksi (skor: {blocking_isp:.2f})"
            else:
                result["reason"] = f"Anomali terdeteksi ({anomaly_count}/{len(measurements)} pengukuran)"
        else:
            result["blocked"] = False
            if failure_count == len(measurements):
                result["reason"] = "Semua pengukuran gagal (mungkin domain mati)"
            else:
                result["reason"] = f"Tidak diblokir ({len(measurements)} pengukuran dari ISP Indonesia)"
    
    except httpx.TimeoutException:
        result["reason"] = "OONI API timeout"
    except Exception as e:
        logger.error(f"OONI API error for {domain}: {e}")
        result["reason"] = f"Error: {str(e)}"
    
    # Simpan ke cache
    _ooni_cache[domain] = {"result": result, "timestamp": now}
    
    return result


# ─── DNS Check (Fallback / Optional) ────────────────────────────────────────
def extract_domain(text: str) -> str | None:
    """Ambil domain dari URL atau teks biasa."""
    text = text.strip()
    if not text.startswith(("http://", "https://")):
        text = "https://" + text
    parsed = urlparse(text)
    return parsed.hostname


def resolve_dns(domain: str, nameservers: list[str] | None = None) -> list[str]:
    """Resolve A record, kembalikan list IP."""
    resolver = dns.resolver.Resolver()
    if nameservers:
        resolver.nameservers = nameservers
    try:
        answers = resolver.resolve(domain, "A", lifetime=5)
        return [str(r) for r in answers]
    except Exception:
        return []


def is_blocked_ip(ip: str) -> bool:
    """Cek apakah IP termasuk range block page Kominfo."""
    return any(ip.startswith(prefix) for prefix in BLOCKED_IP_PATTERNS)


def dns_check(domain: str) -> dict:
    """Cek blokir via DNS resolution. Hanya akurat jika dijalankan dari Indonesia."""
    local_ips = resolve_dns(domain)
    clean_ips = resolve_dns(domain, CLEAN_DNS)
    
    result = {
        "domain": domain,
        "local_ips": local_ips,
        "clean_ips": clean_ips,
        "blocked": False,
        "reason": "",
    }
    
    if not local_ips and not clean_ips:
        result["blocked"] = True
        result["reason"] = "Tidak bisa resolve (domain mati atau blokir total)"
        return result
    
    if not local_ips and clean_ips:
        result["blocked"] = True
        result["reason"] = "DNS lokal gagal resolve, internasional sukses → kemungkinan diblokir"
        return result
    
    for ip in local_ips:
        if is_blocked_ip(ip):
            result["blocked"] = True
            result["reason"] = f"IP lokal mengarah ke block page: {ip}"
            return result
    
    if local_ips and clean_ips and set(local_ips) != set(clean_ips):
        result["blocked"] = True
        result["reason"] = (
            f"DNS poisoning! Lokal: {', '.join(local_ips)} | "
            f"Internasional: {', '.join(clean_ips)}"
        )
        return result
    
    result["reason"] = "Tidak diblokir (DNS lokal dan internasional sama)"
    return result


# ─── Combined Check ─────────────────────────────────────────────────────────
def check_block(domain: str, use_dns: bool = False) -> dict:
    """
    Cek blokir gabungan: OONI API (primary) + DNS (optional).
    """
    result = {
        "domain": domain,
        "ooni": None,
        "dns": None,
        "blocked": False,
        "reason": "",
    }
    
    # 1. Cek via OONI API
    ooni_result = ooni_check(domain)
    result["ooni"] = ooni_result
    
    if ooni_result["found"]:
        result["blocked"] = ooni_result["blocked"]
        result["reason"] = f"[OONI] {ooni_result['reason']}"
        return result
    
    # 2. Fallback ke DNS jika OONI tidak punya data
    if use_dns:
        dns_result = dns_check(domain)
        result["dns"] = dns_result
        result["blocked"] = dns_result["blocked"]
        result["reason"] = f"[DNS] {dns_result['reason']}"
        return result
    
    # 3. Tidak ada data
    result["reason"] = "Tidak ada data OONI. Coba aktifkan DNS check atau cek manual."
    return result


# ─── Database sederhana via file ────────────────────────────────────────────
DB_PATH = os.path.join(os.path.dirname(__file__), "links_db.json")


def load_db() -> dict:
    """Load database link. Format: {chat_id_str: [link1, link2, ...]}"""
    if not os.path.exists(DB_PATH):
        return {}
    try:
        with open(DB_PATH, "r") as f:
            data = json.load(f)
            return {str(k): v for k, v in data.items()}
    except Exception:
        return {}


def save_db(db: dict):
    """Save database link."""
    with open(DB_PATH, "w") as f:
        json.dump(db, f, indent=2)


def get_chat_links(chat_id: int) -> list[str]:
    db = load_db()
    return db.get(str(chat_id), [])


def add_link(chat_id: int, link: str) -> bool:
    db = load_db()
    cid = str(chat_id)
    if cid not in db:
        db[cid] = []
    if link in db[cid]:
        return False
    db[cid].append(link)
    save_db(db)
    return True


def remove_link(chat_id: int, link: str) -> bool:
    db = load_db()
    cid = str(chat_id)
    if cid not in db or link not in db[cid]:
        return False
    db[cid].remove(link)
    if not db[cid]:
        del db[cid]
    save_db(db)
    return True


# ─── Status tracking untuk notifikasi ───────────────────────────────────────
STATUS_PATH = os.path.join(os.path.dirname(__file__), "status_cache.json")


def load_status_cache() -> dict:
    if not os.path.exists(STATUS_PATH):
        return {}
    try:
        with open(STATUS_PATH, "r") as f:
            return json.load(f)
    except Exception:
        return {}


def save_status_cache(cache: dict):
    with open(STATUS_PATH, "w") as f:
        json.dump(cache, f, indent=2)


# ─── Telegram Command Handlers ───────────────────────────────────────────────
async def cmd_start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text(
        "🛡️ *Blocked Link Checker Bot*\n\n"
        "Bot ini memantau link dan memberitahu kalau diblokir.\n"
        "Menggunakan data dari OONI Probe di Indonesia.\n\n"
        "📌 *Perintah:*\n"
        "/add <url>      - Tambah link ke pantauan\n"
        "/remove <url>   - Hapus link dari pantauan\n"
        "/list           - Lihat link yang dipantau\n"
        "/check          - Cek semua link sekarang\n"
        "/status <url>   - Cek status link tertentu\n"
        "/help           - Bantuan\n\n"
        f"⏱ Cek otomatis setiap {CHECK_INTERVAL_SECONDS // 3600} jam.\n\n"
        "🌍 Data dari OONI (Open Observatory of Network Interference)\n"
        "🤖 Bot bisa jalan 24/7 dari cloud (Railway/Render)",
        parse_mode="Markdown",
    )


async def cmd_help(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text(
        "📖 *Cara Pakai:*\n\n"
        "1. Tambah link:\n"
        "   `/add https://example.com`\n"
        "   `/add example.com`\n\n"
        "2. Hapus link:\n"
        "   `/remove https://example.com`\n\n"
        "3. Cek manual:\n"
        "   `/check` — cek semua link\n"
        "   `/status example.com` — cek link tertentu\n\n"
        "4. Lihat daftar:\n"
        "   `/list`\n\n"
        "🤖 Bot otomatis cek tiap jam dan kirim notifikasi saat status berubah.\n\n"
        "📊 *Cara Kerja:*\n"
        "• Query ke OONI API untuk data pengukuran dari ISP Indonesia\n"
        "• Jika confirmed=true → diblokir\n"
        "• Jika anomaly=true → kemungkinan diblokir\n"
        "• DNS check sebagai fallback",
        parse_mode="Markdown",
    )


async def cmd_add(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.args:
        await update.message.reply_text("⚠️ Gunakan: `/add <url>`\nContoh: `/add https://reddit.com`", parse_mode="Markdown")
        return

    raw = context.args[0]
    domain = extract_domain(raw)
    if not domain:
        await update.message.reply_text("❌ URL tidak valid.")
        return

    link = raw.strip()
    added = add_link(update.effective_chat.id, link)
    if added:
        result = ooni_check(domain)
        status_icon = "🔴" if result["blocked"] else "🟢"
        source = "OONI" if result["found"] else "Tidak ada data"
        await update.message.reply_text(
            f"✅ Link ditambahkan!\n\n"
            f"{status_icon} `{domain}`\n"
            f"Status: {result['reason']}\n"
            f"Source: {source}",
            parse_mode="Markdown",
        )
    else:
        await update.message.reply_text("⚠️ Link sudah ada di daftar pantauan.")


async def cmd_remove(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.args:
        await update.message.reply_text("⚠️ Gunakan: `/remove <url>`", parse_mode="Markdown")
        return

    link = context.args[0].strip()
    removed = remove_link(update.effective_chat.id, link)
    if removed:
        await update.message.reply_text(f"🗑️ Link dihapus: `{link}`", parse_mode="Markdown")
    else:
        await update.message.reply_text("❌ Link tidak ditemukan di daftar pantauan.")


async def cmd_list(update: Update, context: ContextTypes.DEFAULT_TYPE):
    links = get_chat_links(update.effective_chat.id)
    if not links:
        await update.message.reply_text("📭 Belum ada link yang dipantau. Tambah dengan `/add <url>`", parse_mode="Markdown")
        return

    text = "📋 *Link yang Dipantau:*\n\n"
    for i, link in enumerate(links, 1):
        text += f"{i}. `{link}`\n"
    await update.message.reply_text(text, parse_mode="Markdown")


async def cmd_status(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.args:
        await update.message.reply_text("⚠️ Gunakan: `/status <url>`\nContoh: `/status reddit.com`", parse_mode="Markdown")
        return

    raw = context.args[0]
    domain = extract_domain(raw)
    if not domain:
        await update.message.reply_text("❌ URL tidak valid.")
        return

    await update.message.reply_text(f"🔍 Mengecek `{domain}` via OONI...", parse_mode="Markdown")
    result = ooni_check(domain)

    status_icon = "🔴 DIBLOKIR" if result["blocked"] else "🟢 AMAN"
    text = (
        f"📊 *Hasil Cek OONI*\n\n"
        f"🌐 Domain: `{domain}`\n"
        f"Status: {status_icon}\n"
        f"📝 Alasan: {result['reason']}\n"
    )
    if result["found"]:
        text += (
            f"📏 Pengukuran: {result['measurement_count']}\n"
            f"🕐 Terbaru: {result['latest_measurement']}\n"
        )
    
    await update.message.reply_text(text, parse_mode="Markdown")


async def cmd_check(update: Update, context: ContextTypes.DEFAULT_TYPE):
    links = get_chat_links(update.effective_chat.id)
    if not links:
        await update.message.reply_text("📭 Belum ada link yang dipantau.", parse_mode="Markdown")
        return

    await update.message.reply_text(f"🔍 Mengecek {len(links)} link via OONI...", parse_mode="Markdown")

    blocked = []
    clean = []
    no_data = []
    
    for link in links:
        domain = extract_domain(link)
        if not domain:
            continue
        result = ooni_check(domain)
        if not result["found"]:
            no_data.append(link)
        elif result["blocked"]:
            blocked.append((link, result))
        else:
            clean.append(link)

    text = "📊 *Hasil Cek Manual*\n\n"
    if blocked:
        text += "🔴 *DIBLOKIR:*\n"
        for link, res in blocked:
            text += f"• `{link}` — {res['reason']}\n"
        text += "\n"
    if clean:
        text += "🟢 *AMAN:*\n"
        for link in clean:
            text += f"• `{link}`\n"
        text += "\n"
    if no_data:
        text += "⚪ *TIDAK ADA DATA:*\n"
        for link in no_data:
            text += f"• `{link}`\n"

    await update.message.reply_text(text, parse_mode="Markdown")


# ─── Background Scheduler ────────────────────────────────────────────────────
async def periodic_check(context: ContextTypes.DEFAULT_TYPE):
    """Cek berkala semua link di semua chat."""
    db = load_db()
    if not db:
        return

    status_cache = load_status_cache()
    notifications = []

    for chat_id_str, links in db.items():
        for link in links:
            domain = extract_domain(link)
            if not domain:
                continue
            try:
                result = ooni_check(domain)
                cache_key = f"{chat_id_str}:{link}"
                prev = status_cache.get(cache_key)

                if result["blocked"]:
                    if prev != "blocked":
                        notifications.append((int(chat_id_str), link, result))
                    status_cache[cache_key] = "blocked"
                elif result["found"]:
                    if prev == "blocked":
                        # Link baru saja tidak diblokir lagi
                        notifications.append((int(chat_id_str), link, result))
                    status_cache[cache_key] = "clean"
                else:
                    status_cache[cache_key] = "no_data"
            except Exception as e:
                logger.error(f"Error checking {link}: {e}")

    save_status_cache(status_cache)

    # Kirim notifikasi
    for chat_id, link, result in notifications:
        try:
            status_icon = "🔴 DIBLOKIR" if result["blocked"] else "🟢 TIDAK DIBLOKIR LAGI"
            await context.bot.send_message(
                chat_id=chat_id,
                text=(
                    f"⚠️ *Notifikasi Perubahan*\n\n"
                    f"🔗 `{link}`\n"
                    f"Status: {status_icon}\n"
                    f"📝 [OONI] {result['reason']}"
                ),
                parse_mode="Markdown",
            )
        except Exception as e:
            logger.error(f"Failed to notify chat {chat_id}: {e}")


async def on_startup(application: Application):
    """Set commands dan info startup."""
    commands = [
        BotCommand("start", "Mulai bot"),
        BotCommand("add", "Tambah link ke pantauan"),
        BotCommand("remove", "Hapus link dari pantauan"),
        BotCommand("list", "Lihat link yang dipantau"),
        BotCommand("check", "Cek semua link sekarang"),
        BotCommand("status", "Cek status link tertentu"),
        BotCommand("help", "Bantuan"),
    ]
    await application.bot.set_my_commands(commands)
    logger.info("Bot started with OONI API.")


# ─── Main ────────────────────────────────────────────────────────────────────
def main():
    if BOT_TOKEN == "ISI_TOKEN_KAMU_DI_SINI":
        print("=" * 60)
        print("⚠️  BOT_TOKEN belum diisi!")
        print("   Set environment variable BOT_TOKEN atau edit file bot.py")
        print("   Token didapat dari @BotFather di Telegram.")
        print("=" * 60)
        return

    print("🛡️  Blocked Link Checker Bot starting...")
    print(f"⏱  Check interval: {CHECK_INTERVAL_SECONDS}s")
    print(f"🌍 OONI API: {OONI_API_BASE}")
    print(f"📊 Country: ID (Indonesia)")

    app = Application.builder().token(BOT_TOKEN).post_init(on_startup).build()

    # Register handlers
    app.add_handler(CommandHandler("start", cmd_start))
    app.add_handler(CommandHandler("help", cmd_help))
    app.add_handler(CommandHandler("add", cmd_add))
    app.add_handler(CommandHandler("remove", cmd_remove))
    app.add_handler(CommandHandler("list", cmd_list))
    app.add_handler(CommandHandler("status", cmd_status))
    app.add_handler(CommandHandler("check", cmd_check))

    # Periodic check job
    job_queue = app.job_queue
    job_queue.run_repeating(periodic_check, interval=CHECK_INTERVAL_SECONDS, first=10)

    print("🤖 Bot berjalan. Tekan Ctrl+C untuk berhenti.")
    app.run_polling(drop_pending_updates=True)


if __name__ == "__main__":
    main()
