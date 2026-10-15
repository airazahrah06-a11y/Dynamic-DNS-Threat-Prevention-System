"""
telegram_alert.py

Dynamic DNS-Based Threat Prevention System
Telegram Alert Module

Hantar notifikasi Telegram secara automatik bila domain MALICIOUS
dikesan/diblock -- untuk makluman masa nyata (contoh terus ke phone
semasa demo/monitoring).

============================================================
CARA SETUP (sekali sahaja):

1. Buka Telegram, cari bot "@BotFather"
2. Taip /newbot, ikut arahan (bagi nama bot)
3. BotFather akan bagi TOKEN, contoh:
     123456789:ABCdefGHIjklMNOpqrsTUVwxyz
4. Cari bot awak (nama yang awak setkan tadi), tekan "Start"
5. Untuk dapatkan CHAT_ID, buka URL ni dalam browser (gantikan TOKEN):
     https://api.telegram.org/bot<TOKEN>/getUpdates
   Selepas hantar apa-apa mesej ke bot tu dahulu, "chat":{"id": ...}
   akan muncul dalam JSON -- itulah CHAT_ID awak.
6. Tambah dalam fail .env. Boleh letak SATU chat_id, atau BEBERAPA
   (group + individu) dipisahkan koma:
     TELEGRAM_BOT_TOKEN=123456789:ABCdefGHIjklMNOpqrsTUVwxyz
     TELEGRAM_CHAT_ID=987654321
   -- atau untuk multiple (contoh: satu group + dua individu) --
     TELEGRAM_CHAT_ID=-1004450822639,987654321,123123123

Kalau TELEGRAM_BOT_TOKEN/TELEGRAM_CHAT_ID tak disetkan, modul ni
"senyap" (skip) -- sistem tetap jalan normal tanpa Telegram.
============================================================
"""

import os
import logging
from datetime import datetime

import requests
from dotenv import load_dotenv

load_dotenv()

logger = logging.getLogger(__name__)


# ============================================================
# CONFIGURATION
# ============================================================

TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN")

# TELEGRAM_CHAT_ID boleh ada SATU chat_id, atau BEBERAPA dipisahkan
# koma (contoh: satu group + beberapa individu sekali). Kita split
# dan bersihkan whitespace, then buang entry kosong (kalau ada
# trailing comma dalam .env).
_raw_chat_ids = os.getenv("TELEGRAM_CHAT_ID", "")
TELEGRAM_CHAT_IDS = [
    cid.strip() for cid in _raw_chat_ids.split(",") if cid.strip()
]

TELEGRAM_API_URL = (
    f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
    if TELEGRAM_BOT_TOKEN
    else None
)

REQUEST_TIMEOUT = 5

# Hanya hantar alert Telegram untuk classification dalam senarai ni --
# elak spam Telegram untuk setiap domain SAFE/rendah risiko.
#
# NOTA: SUSPICIOUS turut dimasukkan di sini (bukan setakat MALICIOUS)
# atas permintaan projek -- ini bermakna Telegram akan lebih "bising"
# (domain SUSPICIOUS jauh lebih kerap berlaku berbanding MALICIOUS
# yang disahkan, sebab rule-based tandakan SUSPICIOUS dulu SEBELUM AI
# sahkan betul-betul berbahaya atau tidak). Buang "SUSPICIOUS"
# daripada set ni bila-bila kalau nak kembali ke MALICIOUS sahaja.
ALERT_CLASSIFICATIONS = {"MALICIOUS", "SUSPICIOUS"}


# ============================================================
# CHECK CONFIGURATION
# ============================================================

def is_configured():
    """
    Semak sama ada Telegram bot dah disetkan dengan betul.
    """
    return bool(TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_IDS)


# ============================================================
# SEND ALERT
# ============================================================

def send_alert(domain, classification, source, action):
    """
    Hantar notifikasi Telegram bila domain berbahaya dikesan.

    Reka bentuk defensif: kalau bot tak disetkan (.env kosong), atau
    network/API gagal, fungsi ni cuma log amaran dan pulangkan False --
    TIDAK PERNAH lontar exception yang boleh sebabkan
    detection_engine.py crash. Notifikasi Telegram adalah "nice to
    have", bukan keperluan kritikal sistem.
    """

    if not is_configured():
        logger.debug(
            "[Telegram] Bot tidak dikonfigurasi -- alert dilangkau."
        )
        return False

    if classification not in ALERT_CLASSIFICATIONS:
        return False

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    emoji = "🚫" if action == "BLOCKED" else "⚠️"

    # [FIX] Sebelum ini mesej guna format Markdown (*tebal*, `kod`) --
    # tapi domain/classification/source adalah data DINAMIK yang boleh
    # ada underscore (_), asterisk (*), atau backtick (`) bila-bila
    # masa (contoh source="MANUAL_TEST" ada underscore). Markdown
    # Telegram anggap aksara tu sebagai PEMBUKA format (italic/bold),
    # dan bila tiada "penutup" berpasangan, API pulangkan error
    # "can't find end of the entity". Dibetulkan dengan BUANG
    # formatting Markdown sepenuhnya -- mesej plain text sentiasa
    # selamat tak kira apa aksara ada dalam domain/source/classification.
    message = (
        f"{emoji} DNS Threat Detected\n\n"
        f"Domain: {domain}\n"
        f"Classification: {classification}\n"
        f"Source: {source}\n"
        f"Action: {action}\n"
        f"Time: {timestamp}"
    )

    # Hantar ke SETIAP chat_id (group dan/atau individu) secara
    # berasingan. Satu penerima gagal (contoh: individu belum /start
    # bot tu, atau group id salah) TIDAK menghalang penerima lain
    # daripada terima alert -- setiap sendMessage adalah request
    # berasingan yang self-contained.
    any_success = False

    for chat_id in TELEGRAM_CHAT_IDS:
        try:
            response = requests.post(
                TELEGRAM_API_URL,
                json={
                    "chat_id": chat_id,
                    "text": message,
                },
                timeout=REQUEST_TIMEOUT,
            )

            if response.status_code == 200:
                logger.info(
                    f"[Telegram] Alert dihantar untuk {domain} -> {chat_id}"
                )
                any_success = True
            else:
                logger.warning(
                    f"[Telegram] Gagal hantar alert untuk {domain} -> "
                    f"{chat_id}: HTTP {response.status_code} - {response.text}"
                )

        except requests.exceptions.RequestException as e:
            logger.warning(
                f"[Telegram] Ralat network untuk {domain} -> {chat_id}: {e}"
            )

        except Exception as e:
            logger.warning(
                f"[Telegram] Ralat tidak dijangka untuk {domain} -> "
                f"{chat_id}: {e}"
            )

    return any_success


# ============================================================
# TEST
# ============================================================

if __name__ == "__main__":

    print("=" * 50)
    print(" TELEGRAM ALERT - TEST")
    print("=" * 50)

    if not is_configured():
        print("[ERROR] TELEGRAM_BOT_TOKEN / TELEGRAM_CHAT_ID belum")
        print("        disetkan dalam .env. Rujuk komen di atas fail")
        print("        ni untuk cara setup.")
    else:
        print(
            f"[INFO] Menghantar mesej ujian ke {len(TELEGRAM_CHAT_IDS)} "
            f"penerima: {', '.join(TELEGRAM_CHAT_IDS)}..."
        )

        ok = send_alert(
            domain="test-malicious-domain.tk",
            classification="MALICIOUS",
            source="MANUAL_TEST",
            action="BLOCKED",
        )

        if ok:
            print("[OK] Mesej ujian berjaya dihantar. Semak Telegram awak.")
        else:
            print("[ERROR] Gagal hantar mesej ujian. Semak log di atas.")
