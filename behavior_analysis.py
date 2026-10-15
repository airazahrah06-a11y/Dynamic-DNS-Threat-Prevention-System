#!/usr/bin/env python3
"""
behavior_analysis.py
Fasa 3: Behavior Analysis (BA) Module
Dynamic DNS-Based Threat Prevention System Using Pi-hole and Behavioral Analysis

Modul ini membaca data daripada table `dns_logs`, menjalankan analisis tingkah laku
(DGA detection, entropy analysis, unusual query pattern detection), menyimpan
keputusan ke dalam table `behavior_logs`, dan (baharu) menjalankan tindakan
pencegahan (prevention) secara automatik melalui Pi-hole apabila risk_score
sesuatu domain mencapai tahap MALICIOUS.

CATATAN (dikemaskini): BA kini turut menyemak table `domain_cache`, tempat
Detection Engine menyimpan keputusan Threat Intelligence (classification,
threat_category, confidence_score, matched_source) bagi setiap domain.
Keputusan tersebut digabungkan (fusion) dengan DGA Detection + Entropy
Analysis sedia ada untuk menghasilkan risk_score akhir, behavior_type, dan
keputusan blocking yang lebih pintar. Flow keseluruhan sistem:

    dns_logs -> Detection Engine -> domain_cache -> Behavior Analysis
             -> behavior_logs -> Pi-hole
"""

import mysql.connector
from mysql.connector import Error
import math
import re
import time
import logging
import subprocess
import os
from collections import Counter, defaultdict
from datetime import datetime, timedelta

# [FIX BAHARU] Regex ringkas untuk validate format domain -- sama tujuan
# macam valid_domain() dalam detector_engine.py. Digunakan dalam
# process_domain_record() untuk skip domain "invalid" (contoh ada
# http://, path/slash, dll -- data tak bersih daripada dns_logs) SEBELUM
# dihantar ke DGA/Entropy analysis, supaya analysis ni tak jalan atas
# string yang bukan domain sebenar (hasil jadi mengarut kalau tak).
VALID_DOMAIN_PATTERN = re.compile(
    r"^(?=.{1,253}$)"
    r"([a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+"
    r"[a-zA-Z]{2,63}$"
)


def is_valid_domain_format(domain_name):
    """
    [FIX BAHARU] Semak format domain asas. Return False untuk string
    yang ada http://, https://, slash (/), atau format tak sah lain --
    supaya process_domain_record() boleh skip terus tanpa jalankan
    DGA/Entropy analysis atas data yang bukan domain sebenar.
    """
    domain_name = str(domain_name or "").strip()
    if not domain_name:
        return False
    return bool(VALID_DOMAIN_PATTERN.match(domain_name))

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass  # python-dotenv tak dipasang -- OK, env var masih boleh
          # disetkan terus melalui shell/systemd tanpa fail .env

# =========================================================
# KONFIGURASI
# =========================================================

# [FIX] DB_CONFIG sebelum ini hardcode user="root", password="" --
# tak sepadan dengan modul lain (detection_engine.py, dashboard.py,
# main.py, train_model.py) yang semua guna fyp_user/fyp2026dns melalui
# env var. Akaun root@localhost pada kebanyakan setup MySQL/Ubuntu guna
# plugin auth_socket yang TOLAK sambungan password kosong sepenuhnya --
# punca sebenar error "Access denied for user 'root'@'localhost'".
#
# Kini diselaraskan guna os.getenv() dengan default SAMA seperti
# modul lain, supaya SEMUA modul dalam sistem sentiasa guna kredential
# yang sama (satu sumber kebenaran, laraskan melalui .env sahaja).

DB_CONFIG = {
    "host": os.getenv("DB_HOST", "localhost"),
    "user": os.getenv("DB_USER", "fyp_user"),
    "password": os.getenv("DB_PASSWORD", "fyp2026dns"),
    "database": os.getenv("DB_NAME", "dns_monitor_database"),
}

# Tempoh loop (saat) - berapa kerap BA scan dns_logs baru
POLL_INTERVAL_SECONDS = 10

# Threshold untuk DGA / Random Domain Detection
MIN_DOMAIN_LENGTH_FOR_CHECK = 12       # domain lebih pendek daripada ini jarang DGA
LONG_DOMAIN_THRESHOLD = 20             # domain sangat panjang -> lebih mencurigakan
DIGIT_RATIO_THRESHOLD = 0.3            # nisbah digit dalam domain
CONSONANT_RUN_THRESHOLD = 5            # susunan konsonan berturut-turut yang pelik

# Threshold untuk Shannon Entropy
ENTROPY_SUSPICIOUS_THRESHOLD = 3.5     # entropy > ini dianggap SUSPICIOUS

# Threshold untuk Unusual Query Pattern Detection
TIME_WINDOW_MINUTES = 5                # tetingkap masa untuk analisis pattern
MAX_REQUESTS_PER_WINDOW = 50           # terlalu banyak request dalam tetingkap masa
MAX_UNIQUE_DOMAINS_PER_WINDOW = 20     # satu source_ip akses terlalu banyak domain berbeza

# =========================================================
# THRESHOLD UNTUK DNS TUNNELING DETECTION (BAHARU)
# =========================================================
# DNS Tunneling ialah teknik data exfiltration yang sorok data dalam
# DNS query (biasanya guna jenis TXT/NULL), sebab DNS jarang disekat
# firewall. Tanda dikesan melalui kombinasi: jenis query TXT/NULL +
# (kekerapan tinggi ke domain sama ATAU subdomain sangat panjang).

TUNNELING_SUSPICIOUS_QUERY_TYPES = {"TXT", "NULL"}
TUNNELING_MIN_REQUESTS_SAME_DOMAIN = 10    # kekerapan TXT/NULL ke domain sama
TUNNELING_LONG_SUBDOMAIN_THRESHOLD = 50    # panjang subdomain (aksara)

# =========================================================
# THRESHOLD UNTUK AI FEATURE EXTRACTION (BAHARU)
# =========================================================
# Digunakan oleh extract_behavior_features() -- feature per-DOMAIN
# (bukan per-IP macam MAX_REQUESTS_PER_WINDOW/MAX_UNIQUE_DOMAINS_PER_WINDOW
# di atas) yang dihantar ke ai_engine.py (Isolation Forest) sebagai
# sebahagian daripada 8 feature model (rujuk FEATURE_ORDER dalam
# ai_engine.py). Tetingkap masa yang sama (TIME_WINDOW_MINUTES) digunakan
# supaya konsisten dengan detect_unusual_patterns().

AI_FEATURE_REQUEST_THRESHOLD = 20      # domain ni sendiri di-query >= sekian kali -> is_high_request=1
AI_FEATURE_CLIENT_THRESHOLD = 10       # domain ni diakses oleh >= sekian client unik -> is_many_clients=1

# =========================================================
# KONFIGURASI RISK-BASED DECISION SYSTEM (BAHARU)
# =========================================================
# Risk score dikira sebagai integer 0-100 (lihat process_domain_record()
# dan detect_unusual_patterns()).
#
#   0  - 49  -> MONITOR    (tiada tindakan, sekadar log)
#   50 - 79  -> ALERT      (simpan ke behavior_logs sahaja, TIDAK diblock)
#   80 - 100 -> BLOCKED    (diblock secara automatik melalui Pi-hole)

RISK_SCORE_ALERT_THRESHOLD = 50
RISK_SCORE_BLOCK_THRESHOLD = 80

# =========================================================
# KONFIGURASI PI-HOLE (BAHARU)
# =========================================================
# Kaedah blocking guna Pi-hole CLI (`pihole -b <domain>`), yang menambah
# domain terus ke dalam senarai "Exact Blacklist" Pi-hole dan (secara
# default) auto-reload gravity/FTL. BA module perlu dijalankan pada mesin
# yang sama dengan Pi-hole, atau pada akaun yang mempunyai akses `sudo`
# tanpa password khusus untuk command `pihole` (uncomment PIHOLE_CMD_PREFIX
# jika perlu `sudo`).
#
# Jika anda lebih suka guna Pi-hole v6 REST API dan bukan CLI, tukar sahaja
# isi fungsi block_domain_pihole() di bawah - struktur keputusan (True/False)
# yang dipulangkan kekal sama supaya process_domain_record() tidak perlu diubah.

PIHOLE_CMD = "pihole"          # tukar ke path penuh contoh "/usr/local/bin/pihole" jika perlu
PIHOLE_USE_SUDO = True         # True jika akaun yang jalankan script ini perlu sudo untuk pihole
PIHOLE_TIMEOUT_SECONDS = 10    # timeout bagi command pihole supaya BA tidak "hang"

# =========================================================
# LOGGING SETUP
# =========================================================

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler("behavior_analysis.log"),
        logging.StreamHandler()
    ]
)

logger = logging.getLogger("BehaviorAnalysis")


# =========================================================
# DATABASE HELPER FUNCTIONS
# =========================================================

def get_connection():
    """Buat sambungan ke MySQL database."""
    try:
        conn = mysql.connector.connect(**DB_CONFIG)
        return conn
    except Error as e:
        logger.error(f"Gagal sambung ke database: {e}")
        return None


def ensure_behavior_logs_table(conn):
    """
    Pastikan table behavior_logs wujud. Jika tiada, cipta table baru
    (termasuk column 'action' yang baharu).

    Jika table SUDAH wujud daripada versi lama (tanpa column 'action'),
    fungsi ini juga akan cuba tambah column tersebut secara automatik
    supaya anda tidak perlu ALTER TABLE secara manual.
    """
    create_table_query = """
    CREATE TABLE IF NOT EXISTS behavior_logs (
        id INT AUTO_INCREMENT PRIMARY KEY,
        source_ip VARCHAR(45) NOT NULL,
        domain_name VARCHAR(255) NOT NULL,
        behavior_type VARCHAR(50) NOT NULL,
        risk_score INT NOT NULL,
        description TEXT,
        action VARCHAR(20) NOT NULL DEFAULT 'MONITOR',
        processed_dns_log_id INT DEFAULT NULL,
        detected_time DATETIME NOT NULL
    )
    """
    try:
        cursor = conn.cursor()
        cursor.execute(create_table_query)
        conn.commit()
        cursor.close()
        logger.info("Table behavior_logs sedia digunakan.")
    except Error as e:
        logger.error(f"Gagal membuat table behavior_logs: {e}")
        return

    # Jika table sudah wujud sebelum ini (versi lama tanpa 'action'),
    # cuba tambah column secara automatik. Jika column sudah wujud,
    # MySQL akan throw error 1060 (Duplicate column name) - kita abaikan.
    try:
        cursor = conn.cursor()
        cursor.execute(
            "ALTER TABLE behavior_logs ADD COLUMN action VARCHAR(20) NOT NULL DEFAULT 'MONITOR'"
        )
        conn.commit()
        cursor.close()
        logger.info("Column 'action' berjaya ditambah ke behavior_logs sedia ada.")
    except Error as e:
        # Error 1060 = column 'action' already exists -> ini normal, abaikan sahaja
        if getattr(e, "errno", None) != 1060:
            logger.warning(f"Semakan/penambahan column 'action' - nota: {e}")

    # Jika table sudah wujud sebelum ini (versi lama tanpa 'processed_dns_log_id'),
    # cuba tambah column secara automatik supaya get_last_processed_id() boleh
    # menyambung daripada log dns_logs terakhir yang diproses (bukan scan semula
    # semua log setiap kali script restart).
    try:
        cursor = conn.cursor()
        cursor.execute(
            "ALTER TABLE behavior_logs ADD COLUMN processed_dns_log_id INT DEFAULT NULL"
        )
        conn.commit()
        cursor.close()
        logger.info("Column 'processed_dns_log_id' berjaya ditambah ke behavior_logs sedia ada.")
    except Error as e:
        if getattr(e, "errno", None) != 1060:
            logger.warning(f"Semakan/penambahan column 'processed_dns_log_id' - nota: {e}")


def get_last_processed_id(conn):
    """
    Dapatkan id dns_logs terakhir yang telah diproses oleh BA, supaya
    apabila script ini restart, ia menyambung daripada tempat terakhir
    (bukan scan semula semua log dns_logs dari mula).

    Nilai ini disimpan dalam column 'processed_dns_log_id' pada table
    behavior_logs setiap kali satu rekod dns_logs individu diproses oleh
    process_domain_record() (lihat insert_behavior_log()).
    """
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT MAX(processed_dns_log_id) FROM behavior_logs")
        result = cursor.fetchone()
        cursor.close()
        if result and result[0] is not None:
            return result[0]
        return 0
    except Error as e:
        logger.error(f"Gagal dapatkan last processed id: {e}")
        return 0


def fetch_new_dns_logs(conn, last_id):
    """Ambil rekod dns_logs baru yang id > last_id."""
    try:
        cursor = conn.cursor(dictionary=True)
        query = """
            SELECT id, source_ip, destination_ip, query_type, domain_name, timestamp
            FROM dns_logs
            WHERE id > %s
            ORDER BY id ASC
        """
        cursor.execute(query, (last_id,))
        rows = cursor.fetchall()
        cursor.close()
        return rows
    except Error as e:
        logger.error(f"Gagal fetch dns_logs: {e}")
        return []


def fetch_recent_logs_for_pattern(conn):
    """Ambil rekod dns_logs dalam tempoh masa TIME_WINDOW_MINUTES untuk analisis pattern."""
    try:
        cursor = conn.cursor(dictionary=True)
        window_start = datetime.now() - timedelta(minutes=TIME_WINDOW_MINUTES)
        query = """
            SELECT source_ip, domain_name, timestamp
            FROM dns_logs
            WHERE timestamp >= %s
        """
        cursor.execute(query, (window_start,))
        rows = cursor.fetchall()
        cursor.close()
        return rows
    except Error as e:
        logger.error(f"Gagal fetch recent logs untuk pattern analysis: {e}")
        return []


def insert_behavior_log(conn, source_ip, domain_name, behavior_type, risk_score,
                         description, action, processed_dns_log_id=None):
    """
    Simpan satu keputusan analisis ke table behavior_logs.

    Parameter 'action' merekodkan tindakan yang diambil oleh risk-based
    decision system: MONITOR / ALERT / BLOCKED.

    Parameter 'processed_dns_log_id' (baharu) ialah id rekod dns_logs asal
    yang berkaitan dengan keputusan ini (jika ada), supaya
    get_last_processed_id() boleh menyambung pemprosesan daripada id
    terakhir ini selepas restart. Untuk keputusan pattern-based (contoh
    UNUSUAL_QUERY_VOLUME, yang berkaitan dengan banyak rekod dns_logs
    sekaligus), nilai ini dibiarkan None.
    """
    try:
        cursor = conn.cursor()
        query = """
            INSERT INTO behavior_logs
            (source_ip, domain_name, behavior_type, risk_score, description,
             action, processed_dns_log_id, detected_time)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
        """
        cursor.execute(query, (
            source_ip,
            domain_name,
            behavior_type,
            risk_score,
            description,
            action,
            processed_dns_log_id,
            datetime.now()
        ))
        conn.commit()
        cursor.close()
    except Error as e:
        logger.error(f"Gagal simpan behavior_log: {e}")


def check_domain_cache(conn, domain_name):
    """
    Semak table domain_cache untuk keputusan Threat Intelligence yang
    telah disimpan oleh Detection Engine bagi domain ini.

    Return:
        None - jika domain tiada dalam domain_cache
        dict - {"classification", "threat_category", "confidence_score",
                "matched_source"} jika domain wujud
    """
    try:
        cursor = conn.cursor(dictionary=True)
        query = """
            SELECT classification,
                   threat_category,
                   confidence_score,
                   matched_source
            FROM domain_cache
            WHERE domain = %s
            LIMIT 1
        """
        cursor.execute(query, (domain_name,))
        row = cursor.fetchone()
        cursor.close()
        return row
    except Error as e:
        logger.error(f"Gagal query domain_cache untuk '{domain_name}': {e}")
        return None


def is_whitelisted(conn, domain_name):
    """
    [FIX BAHARU] Semak table `whitelist` secara LANGSUNG.

    Sebelum ini, behavior_analysis.py TIDAK PERNAH check table
    `whitelist` -- ia cuma baca `domain_cache.classification` (status
    Threat Intelligence) melalui check_domain_cache(). Bila domain
    ditambah ke whitelist, detector_engine.py/dashboard.py update
    `domain_cache` -> SAFE, jadi `ti_malicious` di process_domain_record()
    memang jadi False -- BETUL.

    TAPI pengiraan DGA (is_random_domain) + Shannon Entropy
    (analyze_domain_entropy) berjalan SEPENUHNYA BERASINGAN daripada
    status TI/whitelist -- ia cuma tengok STRUKTUR nama domain semata-
    mata. Jadi domain yang MEMANG nampak "random" (contoh domain demo
    ujian kita: bqxznrtklmvp.tk, xzqvbnrtklmp.net) akan SENTIASA dapat
    risk_score tinggi dari DGA+Entropy fusion (40+40=80) SETIAP KALI ada
    query DNS baru untuknya -- WALAUPUN dah diwhitelist -- sebab
    risk_score >= 80 terus trigger BLOCKED tanpa peduli whitelist
    langsung. Inilah PUNCA SEBENAR "type balik domain -> block semula".

    Dibetulkan dengan check whitelist table terus di SINI, SEBELUM
    apa-apa DGA/Entropy scoring dikira -- domain whitelisted TERUS
    dianggap NORMAL/ALLOW, tak kira macam mana "random" struktur nama
    dia sekalipun.
    """
    try:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT 1 FROM whitelist WHERE domain = %s LIMIT 1",
            (domain_name,),
        )
        row = cursor.fetchone()
        cursor.close()
        return row is not None
    except Error as e:
        logger.error(f"Gagal query whitelist untuk '{domain_name}': {e}")
        return False


def is_duplicate_behavior_log(conn, source_ip, domain_name, behavior_type):
    """
    Semak sama ada behavior_logs sudah mempunyai rekod (source_ip,
    domain_name, behavior_type) yang sama pada hari ini, supaya BA tidak
    membuat INSERT berulang bagi domain/tingkah laku yang sama dalam
    tempoh sehari.
    """
    try:
        cursor = conn.cursor()
        query = """
            SELECT id
            FROM behavior_logs
            WHERE source_ip=%s
              AND domain_name=%s
              AND behavior_type=%s
              AND DATE(detected_time)=CURDATE()
            LIMIT 1
        """
        cursor.execute(query, (source_ip, domain_name, behavior_type))
        row = cursor.fetchone()
        cursor.close()
        return row is not None
    except Error as e:
        logger.error(f"Gagal semak duplicate behavior_log: {e}")
        return False


# =========================================================
# AI ENGINE INTEGRATION -- extract_behavior_features() (BAHARU)
# =========================================================
#
# [FIX] Fungsi ini SEBELUM INI TIADA dalam behavior_analysis.py,
# menyebabkan ai_engine.py gagal "import" (ImportError) sebab ia
# buat:
#
#     from behavior_analysis import extract_behavior_features
#
# Ditambah di sini supaya rantaian penuh berfungsi:
#     detection_engine.py -> ai_engine.predict() -> extract_features()
#     -> extract_behavior_features() (fungsi ini) -> dns_logs
#
# Return WAJIB dict dengan LIMA key ini (susunan tak penting, tapi
# nama key MESTI sepadan -- ai_engine.py rujuk terus ikut nama):
#
#     request_count    - jumlah DNS query untuk domain ni dalam
#                         tetingkap masa TIME_WINDOW_MINUTES terkini
#     unique_clients   - bilangan source_ip unik yang query domain ni
#                         dalam tetingkap masa yang sama
#     request_rate     - request_count dibahagi TIME_WINDOW_MINUTES
#                         (purata request per minit)
#     is_high_request  - 1 jika request_count >= AI_FEATURE_REQUEST_THRESHOLD,
#                         jika tidak 0
#     is_many_clients  - 1 jika unique_clients >= AI_FEATURE_CLIENT_THRESHOLD,
#                         jika tidak 0

def extract_behavior_features(conn, domain_name):
    """
    Kira feature tingkah laku (behavior) untuk SATU domain, digunakan
    oleh ai_engine.py sebagai sebahagian daripada 8 feature Isolation
    Forest (3 feature berasaskan nama domain dikira dalam ai_engine.py
    sendiri -- entropy, length, digit_ratio -- manakala 5 feature
    tingkah laku di bawah dikira di sini).

    Guna tetingkap masa TIME_WINDOW_MINUTES yang sama seperti
    detect_unusual_patterns(), tetapi dikira KHUSUS untuk domain ini
    sahaja (bukan keseluruhan trafik satu source_ip).
    """

    domain_name = (domain_name or "").strip().lower()

    request_count = 0
    unique_clients = 0

    if domain_name:

        try:
            cursor = conn.cursor()

            window_start = datetime.now() - timedelta(
                minutes=TIME_WINDOW_MINUTES
            )

            cursor.execute(
                """
                SELECT
                    COUNT(*) AS request_count,
                    COUNT(DISTINCT source_ip) AS unique_clients
                FROM dns_logs
                WHERE domain_name = %s
                  AND timestamp >= %s
                """,
                (domain_name, window_start)
            )

            row = cursor.fetchone()
            cursor.close()

            if row:
                request_count = row[0] or 0
                unique_clients = row[1] or 0

        except Error as e:
            logger.error(
                f"Gagal extract_behavior_features untuk "
                f"'{domain_name}': {e}"
            )

    request_rate = (
        round(request_count / TIME_WINDOW_MINUTES, 4)
        if TIME_WINDOW_MINUTES
        else 0
    )

    is_high_request = int(
        request_count >= AI_FEATURE_REQUEST_THRESHOLD
    )

    is_many_clients = int(
        unique_clients >= AI_FEATURE_CLIENT_THRESHOLD
    )

    return {
        "request_count": request_count,
        "unique_clients": unique_clients,
        "request_rate": request_rate,
        "is_high_request": is_high_request,
        "is_many_clients": is_many_clients,
    }


# =========================================================
# 1. RANDOM DOMAIN DETECTION (DGA DETECTION)
# =========================================================

def extract_domain_body(domain_name):
    """Ambil bahagian utama domain (buang TLD seperti .com, .net, dll)."""
    parts = domain_name.lower().strip().split(".")
    if len(parts) >= 2:
        return parts[-2]  # bahagian sebelum TLD
    return parts[0]


def has_long_consonant_run(text):
    """Semak jika terdapat susunan konsonan berturut-turut yang tidak normal."""
    vowels = set("aeiou")
    max_run = 0
    current_run = 0
    for ch in text:
        if ch.isalpha() and ch not in vowels:
            current_run += 1
            max_run = max(max_run, current_run)
        else:
            current_run = 0
    return max_run


def digit_ratio(text):
    """Kira nisbah digit berbanding jumlah karakter dalam domain."""
    if len(text) == 0:
        return 0
    digit_count = sum(ch.isdigit() for ch in text)
    return digit_count / len(text)


def is_random_domain(domain_name):
    """
    Semak sama ada domain kelihatan seperti dijana secara rawak (DGA).
    Mengembalikan (is_suspicious: bool, reasons: list)
    """
    body = extract_domain_body(domain_name)
    reasons = []

    # Domain terlalu pendek jarang DGA, skip pemeriksaan mendalam
    if len(body) < MIN_DOMAIN_LENGTH_FOR_CHECK:
        return False, reasons

    # 1. Domain panjang
    if len(domain_name) >= LONG_DOMAIN_THRESHOLD:
        reasons.append(f"Domain panjang ({len(domain_name)} aksara)")

    # 2. Nisbah digit tinggi (gabungan huruf/nombor pelik)
    d_ratio = digit_ratio(body)
    if d_ratio >= DIGIT_RATIO_THRESHOLD:
        reasons.append(f"Nisbah digit tinggi ({d_ratio:.2f})")

    # 3. Susunan konsonan tidak normal
    consonant_run = has_long_consonant_run(body)
    if consonant_run >= CONSONANT_RUN_THRESHOLD:
        reasons.append(f"Susunan konsonan berturut-turut ({consonant_run} aksara)")

    # 4. Corak alphanumeric bercampur pelik (contoh: x7s9dk21abc)
    if re.search(r'[a-z]+\d+[a-z]+\d+', body):
        reasons.append("Corak alphanumeric bercampur tidak normal")

    is_suspicious = len(reasons) > 0
    return is_suspicious, reasons


# =========================================================
# 2. DOMAIN ENTROPY ANALYSIS (SHANNON ENTROPY)
# =========================================================

def calculate_shannon_entropy(text):
    """Kira Shannon Entropy bagi sesuatu string."""
    if not text:
        return 0.0
    freq = Counter(text)
    length = len(text)
    entropy = 0.0
    for count in freq.values():
        probability = count / length
        entropy -= probability * math.log2(probability)
    return entropy


def analyze_domain_entropy(domain_name):
    """
    Kira entropy domain dan tentukan sama ada SUSPICIOUS.
    Mengembalikan (is_suspicious: bool, entropy_value: float)
    """
    body = extract_domain_body(domain_name)
    entropy_value = calculate_shannon_entropy(body)
    is_suspicious = entropy_value >= ENTROPY_SUSPICIOUS_THRESHOLD
    return is_suspicious, entropy_value


# =========================================================
# 3. UNUSUAL QUERY PATTERN DETECTION
# =========================================================

def detect_unusual_patterns(conn):
    """
    Analisis tingkah laku DNS berdasarkan tetingkap masa:
    - Terlalu banyak request dalam tempoh singkat
    - Satu source_ip mengakses terlalu banyak domain berbeza
    Mengembalikan senarai keputusan (list of dict) untuk disimpan.
    """
    rows = fetch_recent_logs_for_pattern(conn)
    results = []

    if not rows:
        return results

    ip_request_count = Counter()
    ip_domain_set = {}

    for row in rows:
        ip = row["source_ip"]
        domain = row["domain_name"]
        ip_request_count[ip] += 1
        ip_domain_set.setdefault(ip, set()).add(domain)

    for ip, count in ip_request_count.items():
        unique_domains = len(ip_domain_set.get(ip, set()))

        # Corak 1: Terlalu banyak request dalam tempoh singkat
        if count >= MAX_REQUESTS_PER_WINDOW:
            results.append({
                "source_ip": ip,
                "domain_name": "MULTIPLE",
                "behavior_type": "UNUSUAL_QUERY_VOLUME",
                "risk_score": 70,
                "description": (
                    f"{count} DNS request dikesan daripada {ip} dalam "
                    f"{TIME_WINDOW_MINUTES} minit (threshold: {MAX_REQUESTS_PER_WINDOW})"
                )
            })

        # Corak 2: Satu source_ip mengakses terlalu banyak domain berbeza
        if unique_domains >= MAX_UNIQUE_DOMAINS_PER_WINDOW:
            results.append({
                "source_ip": ip,
                "domain_name": "MULTIPLE",
                "behavior_type": "UNUSUAL_DOMAIN_DIVERSITY",
                "risk_score": 65,
                "description": (
                    f"{ip} mengakses {unique_domains} domain berbeza dalam "
                    f"{TIME_WINDOW_MINUTES} minit (threshold: {MAX_UNIQUE_DOMAINS_PER_WINDOW})"
                )
            })

    return results


# =========================================================
# DNS TUNNELING DETECTION (BAHARU)
# =========================================================

def fetch_recent_logs_for_tunneling(conn):
    """
    Ambil rekod dns_logs dalam tetingkap TIME_WINDOW_MINUTES, TERMASUK
    query_type -- diperlukan untuk kesan corak DNS Tunneling (yang
    bergantung pada jenis query TXT/NULL), berbeza daripada
    fetch_recent_logs_for_pattern() yang tak perlukan column ni.
    """

    try:
        cursor = conn.cursor(dictionary=True)

        window_start = datetime.now() - timedelta(
            minutes=TIME_WINDOW_MINUTES
        )

        query = """
            SELECT source_ip, domain_name, query_type, timestamp
            FROM dns_logs
            WHERE timestamp >= %s
        """

        cursor.execute(query, (window_start,))
        rows = cursor.fetchall()
        cursor.close()

        return rows

    except Error as e:
        logger.error(f"Gagal fetch recent logs untuk tunneling analysis: {e}")
        return []


def detect_dns_tunneling(conn):
    """
    [BAHARU] Kesan corak DNS Tunneling -- teknik data exfiltration
    yang sorok data dalam DNS query, sebab DNS biasanya tak disekat
    firewall (semua orang perlukan DNS untuk internet berfungsi).

    Tanda-tanda yang disemak:
      1. Jenis query TXT/NULL (bukan A/AAAA biasa) -- jenis ni lazim
         digunakan untuk bawa "payload" data dalam teknik tunneling
      2. Kekerapan TINGGI ke domain YANG SAMA dalam tetingkap masa
         (data besar dihantar dalam banyak "cebisan" kecil berulang)
      3. Subdomain SANGAT PANJANG (data yang di-encode jadi teks
         dalam nama subdomain, cth: a8f3k2j9x8f3k2.evil-tunnel.com)

    Domain ditandakan DNS_TUNNELING kalau (1) DAN (2 ATAU 3) berlaku
    serentak -- guna kombinasi (bukan satu syarat sahaja) untuk
    kurangkan false positive. Sebab: banyak perkhidmatan SAH (contoh
    rekod TXT untuk pengesahan SPF/DKIM emel) guna query TXT, tapi
    JARANG berulang tinggi ke domain sama DENGAN subdomain panjang
    serentak -- kombinasi inilah yang jarang berlaku secara sah.
    """

    rows = fetch_recent_logs_for_tunneling(conn)
    results = []

    if not rows:
        return results

    # Kumpul ikut (source_ip, parent_domain) -- guna 2 label terakhir
    # domain (cth "evil-tunnel.com" daripada "a8f3k2.evil-tunnel.com")
    # supaya subdomain BERBEZA ke domain SAMA dikira sebagai SATU
    # kumpulan aktiviti (macam sepatutnya untuk tunneling).
    groups = defaultdict(list)

    for row in rows:

        query_type = str(row.get("query_type") or "").upper()

        if query_type not in TUNNELING_SUSPICIOUS_QUERY_TYPES:
            continue

        domain = str(row.get("domain_name") or "").strip().lower()

        if not domain:
            continue

        parts = domain.split(".")
        parent_domain = ".".join(parts[-2:]) if len(parts) >= 2 else domain

        key = (row["source_ip"], parent_domain)
        groups[key].append(domain)

    for (source_ip, parent_domain), domain_list in groups.items():

        request_count = len(domain_list)
        max_subdomain_length = max(len(d) for d in domain_list)

        high_frequency = request_count >= TUNNELING_MIN_REQUESTS_SAME_DOMAIN
        long_subdomain = max_subdomain_length >= TUNNELING_LONG_SUBDOMAIN_THRESHOLD

        if high_frequency or long_subdomain:

            reasons = []

            if high_frequency:
                reasons.append(
                    f"{request_count} query TXT/NULL ke {parent_domain} "
                    f"dalam {TIME_WINDOW_MINUTES} minit "
                    f"(threshold: {TUNNELING_MIN_REQUESTS_SAME_DOMAIN})"
                )

            if long_subdomain:
                reasons.append(
                    f"subdomain sepanjang {max_subdomain_length} aksara "
                    f"dikesan (threshold: {TUNNELING_LONG_SUBDOMAIN_THRESHOLD})"
                )

            results.append({
                "source_ip": source_ip,
                "domain_name": parent_domain,
                "behavior_type": "DNS_TUNNELING",
                "risk_score": 85,
                "description": (
                    "Kemungkinan DNS tunneling: " + "; ".join(reasons)
                )
            })

    return results

def decide_action(risk_score):
    """
    Tentukan tindakan (action) berdasarkan risk_score.

        0  - 49  -> "MONITOR"
        50 - 79  -> "ALERT"
        80 - 100 -> "BLOCKED"

    Fungsi ini HANYA menentukan label action berdasarkan skor.
    Pemanggilan sebenar ke block_domain_pihole() dilakukan secara
    berasingan oleh process_domain_record(), supaya fungsi ini kekal
    "pure" (mudah diuji/unit test) dan tidak mempunyai side-effect.
    """
    if risk_score >= RISK_SCORE_BLOCK_THRESHOLD:
        return "BLOCKED"
    elif risk_score >= RISK_SCORE_ALERT_THRESHOLD:
        return "ALERT"
    else:
        return "MONITOR"


# =========================================================
# 5. PI-HOLE PREVENTION LAYER (BAHARU)
# =========================================================

def _is_safe_domain_string(domain_name):
    """
    Semakan asas supaya nama domain yang dihantar ke subprocess tidak
    mengandungi aksara yang tidak dijangka (defense-in-depth, walaupun
    subprocess.run() di bawah TIDAK menggunakan shell=True sehingga
    command injection klasik tidak berlaku).
    """
    if not domain_name:
        return False
    return bool(re.match(r'^[A-Za-z0-9.-]+$', domain_name.strip()))


def block_domain_pihole(domain_name):
    """
    Tambah domain ke dalam Pi-hole blacklist (Exact Blacklist) supaya
    Pi-hole terus block resolusi DNS untuk domain tersebut pada semua
    client dalam rangkaian.

    Menggunakan Pi-hole CLI: `pihole deny <domain_name>`
    (guna `sudo` jika PIHOLE_USE_SUDO = True).

    [FIX BAHARU] Sebelum ini guna sintaks lama Pi-hole v5 (`pihole -b`).
    Command ni TAK dikenali/tak berfungsi pada Pi-hole v6 yang guna
    terminologi "deny"/"allow" (`pihole deny <domain>` untuk block,
    `pihole allow <domain>` untuk whitelist) -- ini kemungkinan besar
    PUNCA SEBENAR kenapa auto-block "senyap" (command gagal dengan
    "unknown command" tapi tak selalu jelas dalam output). Dibetulkan
    guna `deny` supaya sepadan dengan Pi-hole v6.

    subprocess.run() dipanggil dengan senarai argumen (BUKAN shell=True
    dan BUKAN string tunggal), supaya domain_name tidak boleh digunakan
    untuk suntik command tambahan (command injection) walaupun nilainya
    datang daripada data DNS log.

    Return:
        True  -> command Pi-hole berjaya dijalankan (returncode == 0)
        False -> command gagal / timeout / ralat lain
    """
    domain_name = (domain_name or "").strip()

    if not _is_safe_domain_string(domain_name):
        logger.error(
            f"[Pi-hole] Domain '{domain_name}' mengandungi aksara tidak sah - "
            f"tidak dihantar ke Pi-hole."
        )
        return False

    cmd = [PIHOLE_CMD, "deny", domain_name]
    if PIHOLE_USE_SUDO:
        cmd = ["sudo", "-n"] + cmd  # -n = non-interactive, jangan tunggu password prompt

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=PIHOLE_TIMEOUT_SECONDS,
            shell=False,
        )

        if result.returncode == 0:
            logger.warning(
                f"[Pi-hole] Domain '{domain_name}' BERJAYA diblock. "
                f"Output: {result.stdout.strip()}"
            )
            return True
        else:
            logger.error(
                f"[Pi-hole] GAGAL block domain '{domain_name}'. "
                f"Return code: {result.returncode}, stderr: {result.stderr.strip()}"
            )
            return False

    except FileNotFoundError:
        logger.error(
            f"[Pi-hole] Command '{PIHOLE_CMD}' tidak dijumpai pada sistem ini. "
            f"Pastikan Pi-hole dipasang dan PIHOLE_CMD betul, atau BA module "
            f"dijalankan pada mesin Pi-hole yang sama."
        )
        return False
    except subprocess.TimeoutExpired:
        logger.error(
            f"[Pi-hole] Timeout ({PIHOLE_TIMEOUT_SECONDS}s) semasa cuba block "
            f"domain '{domain_name}'."
        )
        return False
    except Exception as e:
        logger.error(f"[Pi-hole] Ralat tidak dijangka semasa block '{domain_name}': {e}")
        return False


# =========================================================
# PEMPROSESAN UTAMA SETIAP DOMAIN
# =========================================================

def process_domain_record(conn, record):
    """
    Jalankan DGA detection dan Entropy analysis untuk satu rekod dns_logs
    (logik sedia ada TIDAK diubah), kemudian (baharu) semak domain_cache
    untuk keputusan Threat Intelligence (TI) daripada Detection Engine dan
    gabungkan (fusion) kesemua keputusan ini:

    1. Kira risk_score gabungan:
         - TI MALICIOUS    -> +60
         - TI SUSPICIOUS   -> +30
         - TI SAFE / tiada -> +0
         - DGA suspicious  -> +40 (sama seperti sebelum ini)
         - Entropy tinggi  -> +40 (sama seperti sebelum ini)
         - Jumlah di-clamp kepada maksimum 100.
    2. Tentukan behavior_type gabungan (TI_AND_BEHAVIOR / THREAT_INTELLIGENCE /
       RANDOM_DOMAIN_HIGH_ENTROPY / RANDOM_DOMAIN / HIGH_ENTROPY / NORMAL).
    3. Tentukan 'action':
         - classification == MALICIOUS ATAU risk_score >= 80 -> "BLOCKED"
           (dan block_domain_pihole() dipanggil)
         - 50 <= risk_score <= 79                             -> "ALERT"
         - risk_score < 50                                     -> "MONITOR"
       (DGA sahaja atau entropy sahaja, tanpa TI MALICIOUS dan tanpa
       mencapai risk_score >= 80, TIDAK akan diblock.)
    4. Elak duplicate: jika behavior_logs sudah ada rekod (source_ip,
       domain_name, behavior_type) yang sama pada hari ini, skip INSERT.
    5. Simpan keputusan akhir ke behavior_logs (termasuk processed_dns_log_id
       supaya get_last_processed_id() boleh menyambung selepas restart).
    """
    source_ip = record["source_ip"]
    domain_name = record["domain_name"]
    dns_log_id = record["id"]

    # [FIX BAHARU] Skip domain dengan format tak sah (contoh ada
    # http://, path/slash) SEBELUM dihantar ke DGA/Entropy analysis.
    # Sebelum ini, fetch_new_dns_logs() ambil SEMUA row dns_logs tanpa
    # validate -- domain_name yang mengandungi "http://payypal-..."
    # tetap dianalisis DGA/entropy, hasilkan behavior_logs yang
    # mengarut/tidak bermakna.
    if not is_valid_domain_format(domain_name):
        logger.info(f"[SKIP] Format domain tidak sah: {domain_name}")
        return

    # [FIX BAHARU] Semak whitelist SEBELUM apa-apa DGA/Entropy scoring
    # dikira. Punca sebenar "type balik domain -> block semula walaupun
    # dah whitelist": DGA/Entropy dikira semata-mata dari STRUKTUR nama
    # domain, tak peduli status whitelist/TI langsung. Domain demo yang
    # sengaja "random" (contoh bqxznrtklmvp.tk) akan SENTIASA dapat
    # risk_score 80 (DGA 40 + Entropy 40) setiap kali ada query BARU,
    # walaupun dah diwhitelist -- sebab check ni sebelum ni TIADA.
    if is_whitelisted(conn, domain_name):
        logger.info(f"[WHITELIST] {domain_name} — dilangkau (BA), dianggap NORMAL.")
        return

    # --- (Baharu) Semak Threat Intelligence daripada domain_cache ---
    cache_result = check_domain_cache(conn, domain_name)

    dga_suspicious, dga_reasons = is_random_domain(domain_name)
    entropy_suspicious, entropy_value = analyze_domain_entropy(domain_name)

    risk_score = 0
    description_parts = []
    ti_classification = None

    if cache_result:
        ti_classification = (cache_result.get("classification") or "").strip().upper()
        threat_category = cache_result.get("threat_category")
        confidence_score = cache_result.get("confidence_score")
        matched_source = cache_result.get("matched_source")

        if ti_classification == "MALICIOUS":
            risk_score += 60
            description_parts.append(f"Threat Intelligence: {matched_source}")
            if threat_category:
                description_parts.append(f"Threat Category: {threat_category}")
            if confidence_score is not None:
                description_parts.append(f"Confidence: {confidence_score}%")
        elif ti_classification == "SUSPICIOUS":
            risk_score += 30
            description_parts.append(f"Threat Intelligence: {matched_source} (SUSPICIOUS)")
            if threat_category:
                description_parts.append(f"Threat Category: {threat_category}")
            if confidence_score is not None:
                description_parts.append(f"Confidence: {confidence_score}%")
        # classification == "SAFE" (atau nilai lain) -> tiada tambahan risk_score

    # --- DGA Detection + Entropy Analysis (logik sedia ada, TIDAK diubah) ---
    if dga_suspicious:
        risk_score += 40
        description_parts.append("DGA: " + "; ".join(dga_reasons))

    if entropy_suspicious:
        risk_score += 40
        description_parts.append(f"Entropy: {entropy_value:.2f}")

    risk_score = min(risk_score, 100)

    # --- Behavior Type (fusion TI + Behavior Analysis) ---
    ti_malicious = ti_classification == "MALICIOUS"
    ba_suspicious = dga_suspicious or entropy_suspicious

    if ti_malicious and ba_suspicious:
        behavior_type = "TI_AND_BEHAVIOR"
    elif ti_malicious:
        behavior_type = "THREAT_INTELLIGENCE"
    elif dga_suspicious and entropy_suspicious:
        behavior_type = "RANDOM_DOMAIN_HIGH_ENTROPY"
    elif dga_suspicious:
        behavior_type = "RANDOM_DOMAIN"
    elif entropy_suspicious:
        behavior_type = "HIGH_ENTROPY"
    else:
        behavior_type = "NORMAL"

    if description_parts:
        description = " | ".join(description_parts)
    else:
        description = f"Domain normal (entropy: {entropy_value:.2f})"

    if behavior_type != "NORMAL":
        logger.warning(f"SUSPICIOUS domain dikesan: {domain_name} ({source_ip}) - {description}")
    else:
        logger.info(f"Domain NORMAL: {domain_name} ({source_ip})")

    # [FIX BAHARU] Semak duplicate SEBELUM block/Telegram dipanggil (bukan
    # lepas, macam sebelum ini). Domain yang di-query berulang-ulang dalam
    # masa singkat (contoh domain Microsoft yang "chatty", resolve setiap
    # beberapa saat) menghasilkan SATU row dns_logs baru setiap query --
    # fetch_new_dns_logs() proses SETIAP row secara berasingan, jadi tanpa
    # early-exit ni, block_domain_pihole() + telegram_alert.send_alert()
    # akan dipanggil BERULANG-ULANG untuk domain SAMA yang dah pernah
    # diproses hari ini -- punca sebenar Telegram/[BLOCK] spam berulang
    # setiap beberapa saat untuk domain yang sama.
    already_processed_today = is_duplicate_behavior_log(
        conn, source_ip, domain_name, behavior_type
    )

    if already_processed_today:
        logger.info(
            f"Rekod behavior_logs untuk {domain_name} ({behavior_type}) sudah wujud "
            f"hari ini - block/alert/INSERT dilangkau (duplicate)."
        )
        return

    # --- Risk-Based Decision System (gabungan TI + risk_score) ---
    # Block hanya apabila TI mengesahkan MALICIOUS ATAU risk_score >= 80.
    # DGA sahaja atau entropy sahaja (40 mata setiap satu) tidak mencapai
    # 80 dengan sendirian, jadi ia kekal sebagai ALERT/MONITOR sahaja
    # melainkan digabungkan dengan faktor lain sehingga capai threshold.
    if ti_malicious:
        action = "BLOCKED"
    else:
        action = decide_action(risk_score)

    blocked_flag = "TIDAK"
    if action == "BLOCKED":
        blocked_ok = block_domain_pihole(domain_name)
        if blocked_ok:
            blocked_flag = "YA"

            # [FIX BAHARU] Sebelum ini, block yang berlaku MELALUI
            # behavior_analysis.py (fusion TI + DGA + Entropy, BUKAN
            # laluan detector_engine.py) TIDAK PERNAH hantar notifikasi
            # Telegram -- sebab save_alert()/telegram_alert.send_alert()
            # sebelum ini cuma dipanggil dalam detector_engine.py.
            # Ini punca domain kadang "block jadi, tapi Telegram senyap".
            # Dibetulkan dengan panggil telegram_alert terus di sini,
            # dengan reka bentuk defensif yang sama (try/except, tak
            # pernah crash BA walaupun Telegram tak dikonfigurasi/gagal).
            try:
                import telegram_alert
                telegram_alert.send_alert(
                    domain_name,
                    "MALICIOUS",
                    behavior_type,
                    "BLOCKED",
                )
            except ImportError:
                pass  # telegram_alert.py tak dipasang/tiada -- OK, skip senyap
            except Exception as e:
                logger.warning(f"[Telegram] Gagal hantar alert untuk {domain_name}: {e}")

        else:
            # Pi-hole gagal block - domain masih MALICIOUS dari segi risk_score,
            # tapi kita catatkan dalam description bahawa blocking gagal supaya
            # senang dikesan dalam laporan/analisis FYP.
            description += " | AMARAN: Pi-hole block GAGAL, sila semak log."
            blocked_flag = "GAGAL"
            logger.error(
                f"Domain '{domain_name}' sepatutnya diblock (risk_score={risk_score}) "
                f"tetapi Pi-hole block GAGAL."
            )

    # --- (Baharu) Logging ringkas [BA] seperti diminta ---
    logger.info(
        f"[BA] Domain: {domain_name} | "
        f"Threat Intelligence: {ti_classification or 'TIADA'} | "
        f"Behavior: {behavior_type} | "
        f"Risk Score: {risk_score} | "
        f"Action: {action} | "
        f"Blocked: {blocked_flag}"
    )

    # [FIX BAHARU] Semakan duplicate dah dibuat AWAL (sebelum block/Telegram)
    # -- kalau sampai sini, confirm ini rekod BAHARU untuk hari ini, terus
    # INSERT tanpa perlu check lagi (elak query MySQL berulang tanpa guna).
    insert_behavior_log(
        conn, source_ip, domain_name, behavior_type, risk_score, description,
        action, processed_dns_log_id=dns_log_id
    )


# =========================================================
# MAIN LOOP
# =========================================================

def main():
    logger.info("Behavior Analysis Module bermula...")

    conn = get_connection()
    if conn is None:
        logger.error("Tidak dapat sambung ke database. Program tamat.")
        return

    ensure_behavior_logs_table(conn)
    last_id = get_last_processed_id(conn)

    logger.info(f"Bermula pemprosesan dari dns_logs id > {last_id}")

    try:
        while True:
            if not conn.is_connected():
                logger.warning("Sambungan database terputus. Cuba sambung semula...")
                conn = get_connection()
                if conn is None:
                    time.sleep(POLL_INTERVAL_SECONDS)
                    continue

            # --- Proses domain baru (DGA + Entropy + Pi-hole prevention) ---
            new_records = fetch_new_dns_logs(conn, last_id)
            if new_records:
                logger.info(f"{len(new_records)} rekod dns_logs baru dikesan.")
                for record in new_records:
                    process_domain_record(conn, record)
                    last_id = record["id"]
            else:
                logger.info("Tiada rekod dns_logs baru.")

            # --- Analisis Unusual Query Pattern ---
            pattern_results = detect_unusual_patterns(conn)
            for pattern in pattern_results:
                pattern_action = decide_action(pattern["risk_score"])

                # Corak pattern (UNUSUAL_QUERY_VOLUME / UNUSUAL_DOMAIN_DIVERSITY)
                # dikaitkan dengan satu source_ip, bukan satu domain tunggal
                # ("MULTIPLE"), jadi walaupun risk_score >= 80, kita TIDAK
                # panggil block_domain_pihole() di sini kerana tiada domain
                # spesifik untuk diblock. Ini kekal sebagai ALERT/MONITOR sahaja.
                if pattern_action == "BLOCKED":
                    pattern_action = "ALERT"
                    logger.warning(
                        f"Pattern '{pattern['behavior_type']}' daripada {pattern['source_ip']} "
                        f"capai risk_score tinggi ({pattern['risk_score']}) tetapi tiada domain "
                        f"spesifik untuk diblock - ditandakan ALERT sahaja."
                    )

                logger.warning(
                    f"UNUSUAL PATTERN: {pattern['behavior_type']} - {pattern['description']}"
                )
                insert_behavior_log(
                    conn,
                    pattern["source_ip"],
                    pattern["domain_name"],
                    pattern["behavior_type"],
                    pattern["risk_score"],
                    pattern["description"],
                    pattern_action
                )

            # --- Analisis DNS Tunneling (BAHARU) ---
            tunneling_results = detect_dns_tunneling(conn)
            for tunnel in tunneling_results:
                tunnel_action = decide_action(tunnel["risk_score"])

                logger.warning(
                    f"DNS TUNNELING: {tunnel['domain_name']} daripada "
                    f"{tunnel['source_ip']} - {tunnel['description']}"
                )

                # Berbeza daripada pattern UNUSUAL_QUERY_VOLUME/DIVERSITY
                # di atas, DNS_TUNNELING ada domain_name SEBENAR (bukan
                # "MULTIPLE") -- jadi kalau risk_score capai threshold
                # BLOCKED, kita BOLEH block domain tu terus di Pi-hole.
                if tunnel_action == "BLOCKED":
                    block_domain_pihole(tunnel["domain_name"])

                insert_behavior_log(
                    conn,
                    tunnel["source_ip"],
                    tunnel["domain_name"],
                    tunnel["behavior_type"],
                    tunnel["risk_score"],
                    tunnel["description"],
                    tunnel_action
                )

            time.sleep(POLL_INTERVAL_SECONDS)

    except KeyboardInterrupt:
        logger.info("Behavior Analysis Module dihentikan oleh pengguna (Ctrl+C).")
    except Exception as e:
        logger.error(f"Ralat tidak dijangka: {e}")
    finally:
        if conn is not None and conn.is_connected():
            conn.close()
            logger.info("Sambungan database ditutup.")


if __name__ == "__main__":
    main()
