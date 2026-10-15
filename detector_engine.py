"""
detection_engine.py

Dynamic DNS-Based Threat Prevention System

Functions:
1. Read new DNS domains
2. Check whitelist
3. Check Threat Intelligence
4. Perform rule-based suspicious detection
5. Run AI (Isolation Forest) analysis for SUSPICIOUS domains
6. Save classification to domain_cache
7. Create security alerts
8. Automatically block malicious/high-risk domains using Pi-hole

============================================================
PERUBAHAN / PEMBETULAN berbanding versi asal (rujuk komen
bertanda [FIX n] di tempat berkaitan):

[FIX 1] AI Engine (ai_engine.py) kini disambungkan ke pipeline.
        Domain SUSPICIOUS (dari TI ATAU rule-based) akan dihantar
        ke ai_engine.predict() untuk analisis lanjut, dan hasilnya
        disimpan ke table ai_results (table dicipta automatik jika
        belum wujud).

[FIX 2] Auto-block kini meliputi lebih daripada sekadar TI=MALICIOUS:
        - TI = MALICIOUS               -> auto block (sedia ada)
        - AI prediction = "Malicious"
          ATAU risk_score >= threshold -> auto block (BAHARU)
        Domain yang gagal capai threshold tu kekal SUSPICIOUS +
        ALERT sahaja (tak diblock), supaya tak over-block domain
        yang cuma "berisiko sederhana".

[FIX 3] block_domain() guna "sudo -n" (non-interactive) supaya
        kalau sudoers belum disetkan dengan NOPASSWD untuk pihole,
        ia GAGAL CEPAT dengan mesej jelas -- bukan cuba tunggu
        password yang tak akan pernah sampai.

[FIX 4] Path ke command "pihole" kini boleh dikonfigurasi melalui
        env var PIHOLE_CMD (default kekal "pihole"), supaya boleh
        ditukar ke full path (contoh /usr/local/bin/pihole) kalau
        "pihole" tak dijumpai dalam secure_path sudo.

[FIX 5] Tambah unblock_domain() + dipanggil secara automatik bila
        domain yang SEBELUM INI dicache sebagai MALICIOUS kini
        ditambah ke whitelist -- supaya block di Pi-hole tak
        "tersangkut" selama-lamanya selepas status berubah.

[FIX 6] ensure_ai_results_table() dipanggil sekali semasa startup
        supaya table ai_results automatik dicipta jika belum wujud
        (elak error "table doesn't exist").

[FIX 7] extract_behavior_features() KINI WUJUD dalam behavior_analysis.py
        (nota lama di bawah ni dah outdated -- dikekalkan sebagai rekod
        sejarah sahaja). AI Engine (Isolation Forest) sepatutnya berfungsi
        sepenuhnya sekarang, dengan syarat isolation_forest_model.pkl
        wujud (jalankan train_model.py dahulu jika belum).

[FIX 8] Domain "invalid" (domain_name ada http://, /, atau format tak
        sah lain) kini turut disimpan ke domain_cache sebagai "SAFE"
        (dengan matched_source jelas "INVALID_FORMAT: ...") supaya ia
        tak diproses berulang. NOTA: guna "SAFE" (bukan "INVALID")
        sebab column classification dalam domain_cache ialah ENUM
        yang cuma benarkan SAFE/SUSPICIOUS/MALICIOUS -- value lain
        akan reject (MySQL error 1265).
        Sebelum ini domain sebegini TIDAK PERNAH dicache, jadi
        get_new_domains() sentiasa anggap ia "baharu" -- punca
        infinite loop [SKIP] berulang dalam log walaupun trafik
        sebenar dah lama berhenti.

NOTA SEJARAH (dah dibetulkan -- rujuk [FIX 7] di atas): ai_engine.py
memerlukan fungsi extract_behavior_features() daripada
behavior_analysis.py, tapi fungsi itu SEBELUM INI tiada dalam
behavior_analysis.py. Selagi belum ditambah, panggilan AI dalam fail
ini gagal dengan cara SELAMAT (prediction="Unknown", tak block, tak
crash). Fungsi tu dah wujud sekarang -- rujuk [FIX 7].
============================================================
"""

import os
import re
import time
import subprocess

import mysql.connector
from mysql.connector import Error


# ============================================================
# CONFIGURATION
# ============================================================

DB_CONFIG = {
    "host": os.getenv("DB_HOST", "localhost"),
    "user": os.getenv("DB_USER", "fyp_user"),
    "password": os.getenv("DB_PASSWORD", "fyp2026dns"),
    "database": os.getenv("DB_NAME", "dns_monitor_database"),
}

# How many domains are processed at once
BATCH_SIZE = 20

# Check database every 10 seconds
POLL_INTERVAL_SECONDS = 10

# [FIX 4] Pi-hole command -- boleh override melalui env var PIHOLE_CMD
# (contoh: export PIHOLE_CMD=/usr/local/bin/pihole) kalau "pihole" tak
# dijumpai dalam secure_path sudo.
PIHOLE_CMD = os.getenv("PIHOLE_CMD", "pihole")

# Use sudo for Pi-hole commands
PIHOLE_USE_SUDO = True

# Timeout (saat) untuk setiap command Pi-hole
PIHOLE_TIMEOUT = 10


# ============================================================
# SUSPICIOUS DOMAIN RULES
# ============================================================

DOMAIN_LENGTH_THRESHOLD = 25
DIGIT_RATIO_THRESHOLD = 0.30
HYPHEN_COUNT_THRESHOLD = 2
SUSPICIOUS_SCORE_THRESHOLD = 2


# ============================================================
# [FIX 2] AI AUTO-BLOCK THRESHOLD
# ============================================================

# Domain SUSPICIOUS akan di-auto-block kalau AI Engine beri
# risk_score >= nilai ni, ATAU prediction == "Malicious".
# Laraskan ikut keperluan (lebih rendah = lebih agresif block).
AI_RISK_BLOCK_THRESHOLD = 75


# ============================================================
# DATABASE
# ============================================================

def create_connection():

    try:
        conn = mysql.connector.connect(
            **DB_CONFIG,
            connection_timeout=5
        )

        if conn.is_connected():
            print("[OK] Connected to MySQL")
            return conn

    except Error as e:
        print(f"[ERROR] Database connection failed: {e}")

    return None


# ============================================================
# [FIX 6, dikemaskini] ai_results TABLE
#
# NOTA: table 'ai_results' diuruskan oleh db_writer.py (dipanggil oleh
# test_predict.py secara berasingan), yang ada skema LEBIH LENGKAP
# (domain_name, recommendation, entropy, dll) berbanding versi asal
# fail ini (domain, tanpa entropy/recommendation). DUA skema berbeza
# cuba CREATE TABLE IF NOT EXISTS pada table SAMA menyebabkan konflik
# -- sesiapa jalan dulu tentukan struktur sebenar, skrip SATU LAGI
# akan gagal INSERT sebab nama column tak padan ("domain" vs
# "domain_name"). Dibetulkan dengan guna terus fungsi db_writer.py
# sebagai SATU sumber kebenaran -- lihat run_ai_analysis() di bawah.
# ============================================================


# ============================================================
# NORMALIZE DOMAIN
# ============================================================

def normalize_domain(domain):

    if domain is None:
        return ""

    domain = str(domain)

    domain = (
        domain
        .strip()
        .lower()
        .rstrip(".")
    )

    return domain


# ============================================================
# VALIDATE DOMAIN
# ============================================================

def valid_domain(domain):

    if not domain:
        return False

    pattern = (
        r"^(?=.{1,253}$)"
        r"([a-zA-Z0-9]"
        r"(?:[a-zA-Z0-9-]{0,61}"
        r"[a-zA-Z0-9])?\.)+"
        r"[a-zA-Z]{2,63}$"
    )

    return bool(re.match(pattern, domain))


# ============================================================
# CHECK WHITELIST
# ============================================================

def check_whitelist(conn, domain):

    domain = normalize_domain(domain)

    if not domain:
        return False

    cursor = conn.cursor()

    try:
        # Exact domain match
        cursor.execute(
            """
            SELECT id
            FROM whitelist
            WHERE domain = %s
            LIMIT 1
            """,
            (domain,)
        )

        result = cursor.fetchone()

        if result:
            return True

        # ----------------------------------------------------
        # Optional parent-domain whitelist
        #
        # Example:
        #   whitelist: google.com
        #   DNS: www.google.com
        #   Result: SAFE
        # ----------------------------------------------------

        parts = domain.split(".")

        if len(parts) > 2:

            parent_domains = [
                ".".join(parts[i:])
                for i in range(1, len(parts) - 1)
            ]

            for parent in parent_domains:

                cursor.execute(
                    """
                    SELECT id
                    FROM whitelist
                    WHERE domain = %s
                    LIMIT 1
                    """,
                    (parent,)
                )

                result = cursor.fetchone()

                if result:
                    return True

        return False

    except Error as e:
        print(f"[WARNING] Whitelist check failed for {domain}: {e}")
        return False

    finally:
        cursor.close()


# ============================================================
# CHECK DOMAIN CACHE
# ============================================================

def get_cached_result(conn, domain):

    domain = normalize_domain(domain)

    cursor = conn.cursor()

    try:
        cursor.execute(
            """
            SELECT
                classification,
                matched_source
            FROM domain_cache
            WHERE domain = %s
            LIMIT 1
            """,
            (domain,)
        )

        return cursor.fetchone()

    except Error as e:
        print(f"[WARNING] Cache check failed: {e}")
        return None

    finally:
        cursor.close()


# ============================================================
# RULE-BASED SUSPICIOUS DOMAIN DETECTION
# ============================================================

def check_suspicious_domain(domain):

    domain = normalize_domain(domain)

    score = 0
    reasons = []

    # --------------------------------------------------------
    # Rule 1: Domain length
    # --------------------------------------------------------

    if len(domain) >= DOMAIN_LENGTH_THRESHOLD:
        score += 1
        reasons.append("Long domain name")

    # --------------------------------------------------------
    # Rule 2: Digit ratio
    # --------------------------------------------------------

    alphanumeric = [char for char in domain if char.isalnum()]

    if alphanumeric:

        digit_count = sum(char.isdigit() for char in alphanumeric)
        digit_ratio = digit_count / len(alphanumeric)

        if digit_ratio >= DIGIT_RATIO_THRESHOLD:
            score += 1
            reasons.append("High digit ratio")

    # --------------------------------------------------------
    # Rule 3: Too many hyphens
    # --------------------------------------------------------

    hyphen_count = domain.count("-")

    if hyphen_count >= HYPHEN_COUNT_THRESHOLD:
        score += 1
        reasons.append("Multiple hyphens")

    # --------------------------------------------------------
    # Rule 4: Suspicious characters
    # --------------------------------------------------------

    suspicious_chars = re.findall(r"[^a-zA-Z0-9.-]", domain)

    if suspicious_chars:
        score += 1
        reasons.append("Suspicious characters")

    # --------------------------------------------------------
    # Final result
    # --------------------------------------------------------

    if score >= SUSPICIOUS_SCORE_THRESHOLD:
        return ("SUSPICIOUS", "; ".join(reasons), score)

    return ("SAFE", "No suspicious domain patterns", score)


# ============================================================
# THREAT INTELLIGENCE
# ============================================================

def check_threat_intelligence(domain):
    """
    Uses threat_intelligence.py if available.

    Expected function: threat_check(domain)
    Expected return can be: SAFE / SUSPICIOUS / MALICIOUS
                             OR (classification, source)
    """

    try:
        from threat_intelligence import threat_check

    except ImportError:
        print("[WARNING] threat_intelligence.py not available.")
        return ("SAFE", "TI module unavailable")

    try:
        result = threat_check(domain)

        # If function returns tuple
        if isinstance(result, tuple):

            if len(result) >= 2:
                classification = str(result[0]).upper()
                source = str(result[1])
                return (classification, source)

            if len(result) == 1:
                return (str(result[0]).upper(), "Threat Intelligence")

        # If function returns dict (threat_intelligence.py's actual
        # format: {"classification": ..., "matched_source": ...})
        if isinstance(result, dict):
            classification = str(
                result.get("classification", "SAFE")
            ).upper()
            source = str(
                result.get("matched_source") or "Threat Intelligence"
            )
            return (classification, source)

        # If function returns string
        classification = str(result).upper()

        if classification in ("MALICIOUS", "SUSPICIOUS", "SAFE"):
            return (classification, "Threat Intelligence")

        return ("SAFE", "Threat Intelligence")

    except Exception as e:
        print(f"[WARNING] Threat intelligence failed for {domain}: {e}")
        return ("SAFE", "TI error")


# ============================================================
# [FIX 1] AI ENGINE INTEGRATION
# ============================================================

def run_ai_analysis(conn, domain):
    """
    Jalankan ai_engine.predict() untuk domain SUSPICIOUS, simpan
    hasil ke table ai_results, dan pulangkan hasil tersebut supaya
    process_domain() boleh guna untuk keputusan auto-block.

    Reka bentuk defensif: import ai_engine dilakukan di SINI (lazy
    import, ikut gaya check_threat_intelligence() di atas) supaya
    kalau ai_engine.py (atau dependency-nya seperti
    behavior_analysis.extract_behavior_features) belum siap/rosak,
    detection_engine.py TIDAK crash -- ia cuma fallback ke
    "Unknown" dan proses domain diteruskan macam biasa.
    """

    try:
        import ai_engine

    except ImportError as e:
        print(f"[WARNING] ai_engine.py not available: {e}")
        return {
            "prediction": "Unknown",
            "confidence": 0,
            "risk_score": 0,
            "reason": ["AI module unavailable"],
        }

    try:
        result = ai_engine.predict(conn, domain)

    except Exception as e:
        print(f"[WARNING] AI prediction failed for {domain}: {e}")
        return {
            "prediction": "Unknown",
            "confidence": 0,
            "risk_score": 0,
            "reason": [f"AI prediction error: {e}"],
        }

    save_ai_result(conn, domain, result)

    return result


def save_ai_result(conn, domain, result):
    """
    [FIX] Dulu fungsi ini INSERT terus ke table ai_results dengan
    skema sendiri (column 'domain') -- bertembung dengan db_writer.py
    (column 'domain_name', + column tambahan seperti entropy,
    recommendation) yang turut aktif digunakan oleh test_predict.py.
    Dibetulkan dengan delegate terus ke db_writer.save_result(),
    supaya HANYA SATU skema (milik db_writer.py) yang jadi sumber
    kebenaran untuk table ai_results -- elak konflik/INSERT gagal.
    """

    domain = normalize_domain(domain)

    try:
        import db_writer

    except ImportError as e:
        print(f"[WARNING] db_writer.py not available, AI result not saved: {e}")
        return

    try:
        db_writer.save_result(conn, domain, result)

    except Exception as e:
        print(f"[ERROR] Failed saving AI result for {domain}: {e}")


# ============================================================
# SAVE DOMAIN CACHE
# ============================================================

def save_domain_result(conn, domain, classification, matched_source):
    """
    [FIX] Query asal tak sertakan 'last_seen' dalam INSERT -- gagal
    dengan MySQL error 1364 ("Field 'last_seen' doesn't have a
    default value") sebab column tu NOT NULL tanpa DEFAULT dalam
    struktur table domain_cache. Dibetulkan dengan sertakan
    last_seen = NOW() terus dalam INSERT.
    """

    domain = normalize_domain(domain)

    cursor = conn.cursor()

    try:
        cursor.execute(
            """
            INSERT INTO domain_cache
            (domain, classification, matched_source, last_seen)
            VALUES (%s, %s, %s, NOW())
            ON DUPLICATE KEY UPDATE
                classification = VALUES(classification),
                matched_source = VALUES(matched_source),
                last_seen = CURRENT_TIMESTAMP
            """,
            (domain, classification, matched_source)
        )
        conn.commit()

    except Error as e:
        conn.rollback()
        print(f"[ERROR] Failed saving cache for {domain}: {e}")

    finally:
        cursor.close()


# ============================================================
# SAVE ALERT
# ============================================================

def save_alert(conn, domain, classification, source, action):
    """
    [FIX] Tambah integrasi Telegram -- bila alert disimpan untuk
    domain MALICIOUS, notifikasi turut dihantar ke Telegram (kalau
    dikonfigurasi). Guna lazy import + try/except supaya
    detection_engine.py TAK PERNAH crash walaupun telegram_alert.py
    tiada/tak dikonfigurasi/network gagal -- notifikasi Telegram
    adalah "nice to have", bukan keperluan kritikal.
    """

    cursor = conn.cursor()

    try:
        cursor.execute(
            """
            INSERT INTO alerts
            (domain, classification, matched_source, action, alert_time)
            VALUES (%s, %s, %s, %s, NOW())
            """,
            (domain, classification, source, action)
        )
        conn.commit()

        print(f"[ALERT] {domain} | {classification} | {action}")

    except Error as e:
        conn.rollback()
        print(f"[ERROR] Failed saving alert for {domain}: {e}")

    finally:
        cursor.close()

    # --------------------------------------------------------
    # Telegram notification -- SATU-SATUNYA saluran notifikasi untuk
    # projek ni (ikut keperluan: "notification melalui Telegram sahaja")
    # --------------------------------------------------------
    try:
        import telegram_alert
        telegram_alert.send_alert(domain, classification, source, action)

    except ImportError:
        pass  # telegram_alert.py tak dipasang/tiada -- OK, skip senyap

    except Exception as e:
        print(f"[WARNING] Telegram alert failed for {domain}: {e}")


# ============================================================
# BLOCK / UNBLOCK DOMAIN USING PI-HOLE
# ============================================================

def _run_pihole_command(args, domain, action_label):
    """
    Helper dikongsi oleh block_domain() dan unblock_domain() supaya
    logik subprocess (sudo -n, timeout, error handling) tak berulang.
    """

    command = []

    if PIHOLE_USE_SUDO:
        # [FIX 3] "-n" = non-interactive. Kalau sudoers belum
        # disetkan NOPASSWD untuk pihole, command ni GAGAL CEPAT
        # dengan mesej jelas dalam stderr -- bukan cuba tunggu
        # password yang tak akan sampai (elak proses "tersekat").
        command.extend(["sudo", "-n"])

    command.extend([PIHOLE_CMD])
    command.extend(args)

    try:
        print(f"[{action_label}] {domain} ...")

        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=PIHOLE_TIMEOUT,
        )

        if result.returncode == 0:
            print(f"[OK] {domain} -> {action_label} berjaya")
            return True

        print(f"[ERROR] Pi-hole {action_label} gagal untuk {domain}")

        stderr = (result.stderr or "").strip()

        if "password is required" in stderr.lower() or "a terminal is required" in stderr.lower():
            print(
                "[HINT] sudo perlukan password -- setkan NOPASSWD untuk "
                f"'{PIHOLE_CMD}' dalam /etc/sudoers.d/ (lihat komen [FIX 3] "
                "di atas fail ini)."
            )

        if stderr:
            print(stderr)

        return False

    except subprocess.TimeoutExpired:
        print(f"[ERROR] Pi-hole {action_label} timeout untuk {domain}")
        return False

    except FileNotFoundError:
        print(
            f"[ERROR] Command '{PIHOLE_CMD}' tidak dijumpai. "
            "Semak PIHOLE_CMD (env var) atau pasang full path, "
            "contoh: export PIHOLE_CMD=/usr/local/bin/pihole"
        )
        return False

    except Exception as e:
        print(f"[ERROR] Pi-hole {action_label} failed for {domain}: {e}")
        return False


def block_domain(domain):

    domain = normalize_domain(domain)

    if not domain:
        return False

    # [FIX BAHARU] Sintaks "-b" (blacklist) ialah gaya lama Pi-hole v5.
    # Pi-hole v6 guna terminologi "deny"/"allow" ("pihole deny <domain>")
    # -- "-b" TAK DIKENALI/gagal senyap pada Pi-hole v6, kemungkinan
    # besar PUNCA SEBENAR auto-block tak berfungsi. Dibetulkan guna
    # "deny" supaya sepadan dengan Pi-hole v6 yang digunakan projek ni.
    return _run_pihole_command(["deny", domain], domain, "BLOCK")


def unblock_domain(domain):
    """
    [FIX 5] Buang domain daripada blacklist Pi-hole. Dipanggil
    secara automatik bila domain yang sebelum ini dicache sebagai
    MALICIOUS ditambah ke whitelist, supaya block tak "tersangkut"
    selama-lamanya selepas status domain berubah.

    [FIX BAHARU] Sintaks lama "-b -d" (v5) -> "deny -d" (v6), buang
    domain daripada denylist (bukan "allow", yang sebaliknya TAMBAH
    domain ke allowlist -- operasi berbeza).
    """

    domain = normalize_domain(domain)

    if not domain:
        return False

    return _run_pihole_command(["deny", "-d", domain], domain, "UNBLOCK")


# ============================================================
# [FIX 2] KEPUTUSAN AUTO-BLOCK BERDASARKAN HASIL AI
# ============================================================

def should_block_from_ai(ai_result):

    prediction = str(ai_result.get("prediction", "")).lower()
    risk_score = ai_result.get("risk_score", 0) or 0

    try:
        risk_score = float(risk_score)
    except (TypeError, ValueError):
        risk_score = 0

    return prediction == "malicious" or risk_score >= AI_RISK_BLOCK_THRESHOLD


def handle_suspicious_domain(conn, domain, base_classification, base_source):
    """
    [FIX 1 + FIX 2] Fungsi dikongsi untuk domain SUSPICIOUS -- sama
    ada datang daripada Threat Intelligence (STEP 5) atau rule-based
    (STEP 7). Jalankan AI Engine, dan auto-block kalau AI cukup yakin
    domain tu berbahaya; kalau tidak, kekal sebagai SUSPICIOUS/ALERT
    sahaja.
    """

    print(f"[AI] Menganalisis {domain}...")

    ai_result = run_ai_analysis(conn, domain)

    ai_prediction = ai_result.get("prediction", "Unknown")
    ai_risk = ai_result.get("risk_score", 0)

    print(f"[AI RESULT] {domain} -> {ai_prediction} (risk={ai_risk})")

    combined_source = f"{base_source} + AI:{ai_prediction}"

    if should_block_from_ai(ai_result):

        save_domain_result(conn, domain, "MALICIOUS", combined_source)

        blocked = block_domain(domain)

        action = "BLOCKED" if blocked else "DETECTED"

        save_alert(conn, domain, "MALICIOUS", combined_source, action)

        print(f"[RESULT] {domain} -> MALICIOUS (AI-confirmed)")

        return

    # AI tak cukup yakin -- kekal SUSPICIOUS, tak diblock
    save_domain_result(conn, domain, "SUSPICIOUS", combined_source)

    save_alert(conn, domain, "SUSPICIOUS", combined_source, "ALERT")

    print(f"[RESULT] {domain} -> SUSPICIOUS")


# ============================================================
# PROCESS SINGLE DOMAIN
# ============================================================

def process_domain(conn, domain):

    domain = normalize_domain(domain)

    if not domain:
        return

    if not valid_domain(domain):
        print(f"[SKIP] Invalid domain: {domain}")

        # [FIX BAHARU] Sebelum ini domain "invalid" (contoh ada http://
        # atau / dalam domain_name -- data tak bersih) TAK PERNAH
        # disimpan ke domain_cache. Sebab get_new_domains() hanya
        # ambil domain yang TAKDE dalam domain_cache, domain invalid
        # ni akan dianggap "baharu" SETIAP kali poll -- infinite loop
        # [SKIP] berulang selama-lamanya walaupun trafik sebenar dah
        # lama berhenti. [FIX] Cache guna classification "SAFE" (BUKAN
        # "INVALID") -- column 'classification' dalam domain_cache
        # ialah ENUM yang cuma benarkan SAFE/SUSPICIOUS/MALICIOUS.
        # Value "INVALID" akan REJECT/truncate (MySQL error 1265:
        # "Data truncated for column 'classification'") dalam strict
        # SQL mode, punca INSERT gagal senyap & domain tetap tak
        # tercache. "SAFE" + matched_source jelas ("Format domain
        # tidak sah") capai tujuan sama (elak infinite loop) tanpa
        # perlu ALTER TABLE ubah ENUM.
        save_domain_result(conn, domain, "SAFE", "INVALID_FORMAT: domain mengandungi http:// atau / (bukan domain sebenar)")
        return

    print()
    print("--------------------------------")
    print(f"[DOMAIN] {domain}")

    # ========================================================
    # STEP 1 — WHITELIST
    # ========================================================

    if check_whitelist(conn, domain):

        print(f"[WHITELIST] {domain} is trusted")

        # [FIX 5] Kalau domain ni sebelum ini pernah dicache sebagai
        # MALICIOUS (mungkin ditambah ke whitelist selepas false
        # positive), pastikan ia di-unblock semula daripada Pi-hole.
        previous = get_cached_result(conn, domain)

        if previous and str(previous[0]).upper() == "MALICIOUS":
            print(
                f"[WHITELIST] {domain} pernah MALICIOUS -- "
                "cuba unblock daripada Pi-hole..."
            )
            unblock_domain(domain)

        save_domain_result(conn, domain, "SAFE", "WHITELIST")

        print(f"[RESULT] {domain} -> SAFE (WHITELIST)")

        return

    # ========================================================
    # STEP 2 — CACHE
    # ========================================================

    cached = get_cached_result(conn, domain)

    if cached:

        cached_classification = str(cached[0]).upper()
        cached_source = str(cached[1] if cached[1] else "CACHE")

        print(f"[CACHE] {domain} already classified as {cached_classification}")

        # If already malicious, make sure Pi-hole remains blocked
        if cached_classification == "MALICIOUS":
            block_domain(domain)

        return

    # ========================================================
    # STEP 3 — THREAT INTELLIGENCE
    # ========================================================

    print(f"[TI] Checking {domain}...")

    ti_classification, ti_source = check_threat_intelligence(domain)
    ti_classification = str(ti_classification).upper()

    print(f"[TI RESULT] {domain} -> {ti_classification}")

    # ========================================================
    # STEP 4 — MALICIOUS FROM TI
    # ========================================================

    if ti_classification == "MALICIOUS":

        save_domain_result(conn, domain, "MALICIOUS", ti_source)

        blocked = block_domain(domain)

        action = "BLOCKED" if blocked else "DETECTED"

        save_alert(conn, domain, "MALICIOUS", ti_source, action)

        print(f"[RESULT] {domain} -> MALICIOUS")

        return

    # ========================================================
    # STEP 5 — SUSPICIOUS FROM TI
    #
    # [FIX 1 + FIX 2] Sebelum ini domain SUSPICIOUS dari TI cuma
    # dapat ALERT, tak pernah diblock. Kini dihantar ke AI Engine
    # dahulu -- kalau AI sahkan berisiko tinggi, baru diblock.
    # ========================================================

    if ti_classification == "SUSPICIOUS":

        handle_suspicious_domain(conn, domain, "SUSPICIOUS", ti_source)

        return

    # ========================================================
    # STEP 6 — RULE BASED ANALYSIS
    # ========================================================

    rule_classification, reason, score = check_suspicious_domain(domain)

    print(f"[RULE] {domain} -> {rule_classification} (score={score})")

    # ========================================================
    # STEP 7 — RULE SUSPICIOUS
    #
    # [FIX 1 + FIX 2] Sama macam STEP 5 -- dihantar ke AI Engine
    # dahulu sebelum diputuskan block atau tidak.
    # ========================================================

    if rule_classification == "SUSPICIOUS":

        handle_suspicious_domain(conn, domain, "SUSPICIOUS", f"RULE: {reason}")

        return

    # ========================================================
    # STEP 8 — SAFE
    # ========================================================

    save_domain_result(conn, domain, "SAFE", "Threat Intelligence + Rules")

    print(f"[RESULT] {domain} -> SAFE")


# ============================================================
# GET NEW DOMAINS
# ============================================================

def get_new_domains(conn):
    """
    [FIX] Query asal guna "SELECT DISTINCT dl.domain_name ... ORDER BY
    dl.timestamp" -- ini gagal dengan MySQL error 3065 pada MySQL 8+
    (sql_mode strict): "Expression #1 of ORDER BY clause is not in
    SELECT list ... incompatible with DISTINCT". Dibetulkan guna
    GROUP BY + MIN(timestamp) sebagai ganti DISTINCT, yang sah dari
    segi SQL standard dan beri hasil sama (domain unik, disusun ikut
    kemunculan paling awal).
    """

    cursor = conn.cursor()

    try:
        cursor.execute(
            """
            SELECT dl.domain_name
            FROM dns_logs dl
            LEFT JOIN domain_cache dc
                ON dl.domain_name = dc.domain
            WHERE dc.domain IS NULL
              AND dl.domain_name IS NOT NULL
              AND dl.domain_name != ''
            GROUP BY dl.domain_name
            ORDER BY MIN(dl.timestamp) ASC
            LIMIT %s
            """,
            (BATCH_SIZE,)
        )

        results = cursor.fetchall()

        return [
            normalize_domain(row[0])
            for row in results
            if row[0]
        ]

    except Error as e:
        print(f"[ERROR] Failed reading DNS logs: {e}")
        return []

    finally:
        cursor.close()


# ============================================================
# MAIN LOOP
# ============================================================

def main():

    print()
    print("======================================")
    print("     DNS DETECTION ENGINE")
    print("======================================")
    print("[INFO] Whitelist protection enabled")
    print("[INFO] Threat Intelligence enabled")
    print("[INFO] Rule-based detection enabled")
    print("[INFO] AI Engine analysis enabled (SUSPICIOUS domains)")
    print("[INFO] Pi-hole automatic blocking enabled")
    print(f"[INFO] AI auto-block threshold: risk_score >= {AI_RISK_BLOCK_THRESHOLD}")
    print()

    # [FIX 6, dikemaskini] Pastikan table ai_results wujud sebelum loop
    # bermula -- guna db_writer.py (satu sumber kebenaran untuk skema
    # ai_results, elak konflik dengan test_predict.py)
    setup_conn = create_connection()

    if setup_conn is not None:
        try:
            import db_writer
            db_writer.create_ai_results_table(setup_conn)
        except ImportError as e:
            print(f"[WARNING] db_writer.py not available: {e}")
        setup_conn.close()

    while True:

        conn = None

        try:
            # ------------------------------------------------
            # Connect database
            # ------------------------------------------------

            conn = create_connection()

            if conn is None:
                print("[WARNING] Database unavailable.")
                time.sleep(POLL_INTERVAL_SECONDS)
                continue

            # ------------------------------------------------
            # Get new domains
            # ------------------------------------------------

            domains = get_new_domains(conn)

            if not domains:
                print("[INFO] No new domains.")

            else:
                print(f"[INFO] Found {len(domains)} new domain(s)")

                # --------------------------------------------
                # Process domains
                # --------------------------------------------

                for domain in domains:

                    try:
                        process_domain(conn, domain)

                    except Exception as e:
                        print(f"[ERROR] Processing {domain}: {e}")

                    # [DEMO] Jeda kecil antara setiap domain supaya output
                    # tak "luncur" sekali gus semasa presentation/demo --
                    # senang penonton nampak & faham setiap step. Boleh
                    # buang/comment line ni untuk production (proses
                    # sepantas mungkin).
                    time.sleep(1)

        except KeyboardInterrupt:
            print("\n[STOP] Detection Engine stopped.")
            break

        except Exception as e:
            print(f"[ERROR] Detection Engine: {e}")

        finally:
            if conn and conn.is_connected():
                conn.close()

        # ----------------------------------------------------
        # Wait before checking again
        # ----------------------------------------------------

        time.sleep(POLL_INTERVAL_SECONDS)


# ============================================================
# ENTRY POINT
# ============================================================

if __name__ == "__main__":
    main()
