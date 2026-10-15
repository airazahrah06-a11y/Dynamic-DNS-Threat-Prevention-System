# ============================================================
# DNS Monitor — Real-Time Live Capture (Fixed Version)
# Library : PyShark + Psutil
# Function:
# - Auto detect network interface
# - Capture DNS traffic (UDP Port 53)
# - Extract Source IP, Destination IP, Domain, Query Type
# - Support IPv4 & IPv6
# - [BAHARU] Simpan setiap query DNS terus ke table dns_logs (MySQL)
#
# Perubahan berbanding versi asal:
#   1. Semakan root/sudo sebelum mula capture
#   2. detect_interface() cross-platform + skip virtual/loopback interface
#      dengan lebih baik, dan beri amaran kalau banyak interface aktif
#   3. Error handling untuk LiveCapture (contoh: tshark tak dipasang)
#   4. flags_response check lebih selamat (guna int() berbanding str match)
#   5. [FIX KRITIKAL] Fail ni SEBELUM INI cuma print() ke skrin, TAK
#      PERNAH simpan ke database langsung -- punca sebenar kenapa
#      dns_logs kekal kosong untuk domain baharu walaupun DNS Monitor
#      "nampak" tangkap trafik dengan betul. Dibetulkan dengan tambah
#      sambungan MySQL + INSERT INTO dns_logs untuk SETIAP query yang
#      ditangkap (selepas dipaparkan ke skrin, macam sebelum ini).
# ============================================================

import os
import sys
import time

import psutil


# ============================================================
# 0. ROOT / PRIVILEGE CHECK
# ============================================================

def require_root():
    """
    pyshark.LiveCapture perlukan akses raw socket. Tanpa root/admin,
    capture akan gagal dengan error yang mengelirukan.
    """

    if os.name == "nt":
        try:
            import ctypes
            is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
        except Exception:
            is_admin = False

        if not is_admin:
            print(
                "[WARNING] Skrip ini mungkin perlukan hak Administrator "
                "untuk capture packet."
            )
        return

    if hasattr(os, "geteuid") and os.geteuid() != 0:
        print("[ERROR] Sila jalankan skrip ini dengan sudo/root.")
        print(f"        sudo {sys.executable} {os.path.abspath(__file__)}")
        sys.exit(1)


require_root()


# pyshark diimport SELEPAS semakan root supaya mesej error di atas jelas
# dan tak tertutup oleh traceback tshark jika ada masalah kebenaran.
import pyshark  # noqa: E402

# [BAHARU] mysql.connector untuk simpan ke dns_logs
import mysql.connector  # noqa: E402
from mysql.connector import Error  # noqa: E402

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass


# ============================================================
# 0.1 [BAHARU] DATABASE CONFIGURATION -- sama pattern/default macam
# modul lain (satu sumber kebenaran melalui env var)
# ============================================================

DB_CONFIG = {
    "host": os.getenv("DB_HOST", "localhost"),
    "user": os.getenv("DB_USER", "fyp_user"),
    "password": os.getenv("DB_PASSWORD", "fyp2026dns"),
    "database": os.getenv("DB_NAME", "dns_monitor_database"),
}

# Sambungan MySQL global -- guna SATU sambungan berterusan untuk
# elak overhead buka/tutup sambungan setiap packet (boleh terima
# beratus-ratus packet sesaat). reconnect() dipanggil bila perlu
# (rujuk get_db_connection() di bawah).
_db_conn = None


def get_db_connection():
    """
    Pulangkan sambungan MySQL yang masih hidup, cuba sambung semula
    kalau terputus. Reka bentuk defensif -- kalau database down,
    fungsi ni pulangkan None dan process_packet() akan skip simpan
    (tapi TERUS papar ke skrin macam biasa) -- capture DNS TAK
    PERNAH terhenti disebabkan masalah database.
    """

    global _db_conn

    try:
        if _db_conn is None or not _db_conn.is_connected():
            _db_conn = mysql.connector.connect(
                **DB_CONFIG,
                connection_timeout=5,
            )
        return _db_conn

    except Error as e:
        print(f"[WARNING] Sambungan database gagal: {e}")
        return None


def save_dns_log(source_ip, destination_ip, query_type, domain, timestamp):
    """
    [BAHARU] Simpan satu rekod query DNS ke table dns_logs.

    Dipanggil oleh process_packet() untuk SETIAP query DNS yang
    ditangkap (selepas dipaparkan ke skrin). Reka bentuk defensif --
    kegagalan simpan (contoh database down sekejap) TAK menghentikan
    proses capture packet seterusnya, cuma dilog sebagai amaran.
    """

    conn = get_db_connection()

    if conn is None:
        return

    try:
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO dns_logs
            (source_ip, destination_ip, query_type, domain_name, timestamp)
            VALUES (%s, %s, %s, %s, %s)
            """,
            (source_ip, destination_ip, query_type, domain, timestamp)
        )
        conn.commit()
        cursor.close()

    except Error as e:
        print(f"[WARNING] Gagal simpan dns_log untuk {domain}: {e}")


# ============================================================
# 1. AUTO DETECT NETWORK INTERFACE
# ============================================================

# Nama interface loopback biasa merentasi platform
LOOPBACK_NAMES = {"lo", "lo0", "loopback"}


def is_loopback_or_virtual(name):
    lname = name.lower()

    if lname in LOOPBACK_NAMES:
        return True

    if "loopback" in lname:
        return True

    return False


def detect_interface():
    """
    Cross-platform: elak loopback (Linux/macOS: 'lo'/'lo0', Windows:
    'Loopback Pseudo-Interface...'). Kalau lebih daripada satu interface
    aktif dijumpai, beri amaran supaya user tahu ia mungkin bukan pilihan
    yang tepat (contoh: VPN/virtual adapter dipilih berbanding interface
    fizikal sebenar).
    """

    candidates = []

    for name, stats in psutil.net_if_stats().items():

        if not stats.isup:
            continue

        if is_loopback_or_virtual(name):
            continue

        candidates.append(name)

    if not candidates:
        return None

    if len(candidates) > 1:
        print(
            "[WARNING] Lebih daripada satu interface aktif dijumpai: "
            f"{candidates}"
        )
        print(f"[WARNING] Menggunakan interface pertama: {candidates[0]}")
        print(
            "[WARNING] Jika ini salah, edit dns_monitor.py dan tetapkan "
            "interface secara manual."
        )

    return candidates[0]


interface_name = detect_interface()


if interface_name is None:
    print("[ERROR] No active network interface found.")
    sys.exit(1)



# ============================================================
# 2. DNS QUERY TYPE MAPPING
# ============================================================

query_type_map = {

    "1": "A",        # IPv4 Address
    "2": "NS",       # Name Server
    "5": "CNAME",    # Canonical Name
    "6": "SOA",      # Start of Authority
    "12": "PTR",     # Pointer
    "15": "MX",      # Mail Exchange
    "16": "TXT",     # Text Record
    "28": "AAAA",    # IPv6 Address
    "33": "SRV",     # Service Locator
    "35": "NAPTR",   # Naming Authority Pointer
    "43": "DS",      # Delegation Signer
    "48": "DNSKEY",  # DNS Key
    "255": "ANY",    # All Records
}



# ============================================================
# 3. DISPLAY HEADER
# ============================================================

def print_header():

    print("=" * 95)
    print("        DNS MONITOR — REAL-TIME TRAFFIC CAPTURE")
    print("=" * 95)

    print(
        f"{'TIMESTAMP':<22}"
        f"{'SOURCE IP':<20}"
        f"{'DESTINATION IP':<20}"
        f"{'TYPE':<10}"
        f"{'DOMAIN'}"
    )

    print("-" * 95)



# ============================================================
# 4. PROCESS DNS PACKET
# ============================================================

def process_packet(packet):

    try:

        # Pastikan packet mempunyai DNS layer
        if not hasattr(packet, "dns"):
            return


        # Hanya ambil DNS Query, bukan response.
        # flags_response boleh jadi '0'/'False'/'1'/'True' bergantung
        # versi pyshark/tshark — guna int() untuk semakan lebih selamat.
        try:
            is_response = int(packet.dns.flags_response) != 0
        except (ValueError, AttributeError):
            is_response = str(packet.dns.flags_response).lower() not in (
                "0",
                "false",
            )

        if is_response:
            return


        # Perlu ada nama domain untuk berguna — skip kalau tiada
        if not hasattr(packet.dns, "qry_name"):
            return


        # Timestamp packet sebenar
        timestamp = packet.sniff_time.strftime(
            "%Y-%m-%d %H:%M:%S"
        )


        # Source & Destination IP — sokong IPv4 dan IPv6
        if hasattr(packet, "ip"):
            source_ip = packet.ip.src
            destination_ip = packet.ip.dst
        elif hasattr(packet, "ipv6"):
            source_ip = packet.ipv6.src
            destination_ip = packet.ipv6.dst
        else:
            source_ip = "Unknown"
            destination_ip = "Unknown"


        # Domain yang dicari
        domain = packet.dns.qry_name

        # Buang "." di hujung domain
        if domain.endswith("."):
            domain = domain[:-1]


        # Query Type
        raw_type = (
            packet.dns.qry_type
            if hasattr(packet.dns, "qry_type")
            else "?"
        )

        query_type = query_type_map.get(
            str(raw_type),
            f"TYPE-{raw_type}"
        )


        # Paparkan hasil
        print(
            f"{timestamp:<22}"
            f"{source_ip:<20}"
            f"{destination_ip:<20}"
            f"{query_type:<10}"
            f"{domain}"
        )

        # [BAHARU] Simpan ke database -- INILAH bahagian yang hilang
        # sebelum ini. Tanpa baris ni, dns_logs kekal kosong untuk
        # SEMUA domain baharu walaupun DNS Monitor "nampak" tangkap
        # trafik dengan betul di skrin.
        save_dns_log(source_ip, destination_ip, query_type, domain, timestamp)


    except AttributeError:
        # Field yang dijangka tiada dalam packet ini — skip senyap
        pass

    except Exception as e:
        # Ralat lain yang tidak dijangka — papar untuk debug
        print(f"[ERROR] {e}")



# ============================================================
# 5. MAIN PROGRAM
# ============================================================

def main():

    print_header()

    print(f"[*] Interface digunakan : {interface_name}")
    print("[*] Filter aktif        : UDP Port 53")
    print("[*] Menunggu DNS traffic...")
    print("[*] Tekan Ctrl + C untuk berhenti\n")

    # [BAHARU] Sahkan sambungan database sebelum mula capture, supaya
    # masalah config (.env salah, DB down) diketahui SERTA-MERTA,
    # bukan senyap sepanjang sesi capture.
    test_conn = get_db_connection()
    if test_conn is not None:
        print("[OK] Sambungan database berjaya -- query DNS akan disimpan.")
    else:
        print(
            "[WARNING] Sambungan database GAGAL -- query DNS akan "
            "dipaparkan sahaja, TIDAK disimpan ke dns_logs."
        )


    # Start live capture
    try:
        capture = pyshark.LiveCapture(
            interface=interface_name,
            bpf_filter="udp port 53"
        )
    except Exception as e:
        print(f"[ERROR] Gagal memulakan capture: {e}")
        print(
            "[HINT] Pastikan 'tshark' dipasang dan boleh dijumpai dalam PATH."
        )
        sys.exit(1)


    try:

        for packet in capture.sniff_continuously():

            process_packet(packet)


    except KeyboardInterrupt:

        print("\n[!] DNS Monitoring dihentikan.")

        if _db_conn is not None and _db_conn.is_connected():
            _db_conn.close()

        sys.exit(0)

    except Exception as e:

        print(f"[ERROR] Capture terhenti secara tidak dijangka: {e}")
        sys.exit(1)



# ============================================================
# ENTRY POINT
# ============================================================

if __name__ == "__main__":

    main()
