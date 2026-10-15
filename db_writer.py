"""
db_writer.py
Fasa 2 - Dynamic DNS-Based Threat Prevention System

Modul ini bertanggungjawab MENYIMPAN hasil AI (dari ai_engine.predict())
ke dalam table MySQL 'ai_results'. Ini adalah satu-satunya modul yang
sepatutnya menulis ke table ai_results — supaya schema/format data
berpusat di satu tempat.

Streamlit dashboard.py hanya membaca (SELECT) dari table ini, tidak
pernah menulis terus.
"""

import logging
from mysql.connector import Error

logger = logging.getLogger(__name__)


# ============================================================
# AUTO-CREATE TABLE ai_results
# ============================================================
def create_ai_results_table(conn):
    """
    Buat table 'ai_results' jika belum wujud. Dipanggil sekali masa
    detection_engine.py bermula (sama pattern dengan
    create_alert_table() untuk table 'alerts'), supaya sistem tidak
    bergantung kepada setup manual dalam MySQL.
    """
    query = """
        CREATE TABLE IF NOT EXISTS ai_results (
            id INT AUTO_INCREMENT PRIMARY KEY,
            domain_name VARCHAR(255) NOT NULL,
            prediction VARCHAR(20) NOT NULL,
            confidence FLOAT NOT NULL,
            risk_score FLOAT NOT NULL,
            reason TEXT,
            recommendation VARCHAR(50),
            entropy FLOAT,
            domain_length INT,
            digit_ratio FLOAT,
            request_count INT,
            unique_clients INT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    """
    try:
        cursor = conn.cursor()
        cursor.execute(query)
        conn.commit()
        cursor.close()
        logger.info("Table 'ai_results' sedia digunakan.")
    except Error as e:
        logger.error(f"Gagal membuat table 'ai_results': {e}")


# ============================================================
# MAPPING PREDICTION -> RECOMMENDATION
# ============================================================
def get_recommendation(prediction: str) -> str:
    mapping = {
        "Malicious": "Block Domain",
        "Suspicious": "Monitor",
        "Normal": "Allow",
        "Unknown": "Monitor",
    }
    return mapping.get(prediction, "Monitor")


# ============================================================
# SAVE RESULT KE MySQL
# ============================================================
def save_result(conn, domain: str, result: dict):
    """
    domain : nama domain yang dianalisis
    result : dict yang dipulangkan oleh ai_engine.predict(), contoh:
        {
            "prediction": "Malicious",
            "confidence": 97.2,
            "risk_score": 95,
            "reason": ["High entropy (3.91)", "Long domain name (23 chars)"],
            "features": {
                "entropy": 3.91,
                "length": 23,
                "digit_ratio": 0.26,
                "request_count": 140,
                "unique_clients": 25
            }
        }

    Return: True jika berjaya simpan, False jika gagal.
    """
    query = """
        INSERT INTO ai_results (
            domain_name, prediction, confidence, risk_score,
            reason, recommendation, entropy, domain_length,
            digit_ratio, request_count, unique_clients
        ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
    """

    feats = result.get("features", {})
    reason_text = ", ".join(result.get("reason", []))
    recommendation = get_recommendation(result.get("prediction", "Unknown"))

    values = (
        domain,
        result.get("prediction", "Unknown"),
        result.get("confidence", 0),
        result.get("risk_score", 0),
        reason_text,
        recommendation,
        feats.get("entropy"),
        feats.get("length"),
        feats.get("digit_ratio"),
        feats.get("request_count"),
        feats.get("unique_clients"),
    )

    try:
        cursor = conn.cursor()
        cursor.execute(query, values)
        conn.commit()
        cursor.close()
        logger.info(f"[DB] Hasil AI untuk '{domain}' berjaya disimpan "
                    f"(prediction={result.get('prediction')}).")
        return True

    except Error as e:
        logger.error(f"[DB] Gagal simpan hasil AI untuk '{domain}': {e}")
        conn.rollback()
        return False


# ============================================================
# FUNGSI BANTUAN UNTUK STREAMLIT (baca data)
# ============================================================
def get_all_results(conn, limit: int = 100):
    """
    Digunakan oleh dashboard.py untuk papar hasil terkini.
    Return: list of dict (row-row dari ai_results, terbaru dahulu)
    """
    query = """
        SELECT domain_name, prediction, confidence, risk_score,
               reason, recommendation, created_at
        FROM ai_results
        ORDER BY created_at DESC
        LIMIT %s
    """
    cursor = conn.cursor(dictionary=True)
    cursor.execute(query, (limit,))
    rows = cursor.fetchall()
    cursor.close()
    return rows


def get_statistics(conn):
    """
    Digunakan oleh dashboard.py untuk bahagian 'AI Statistics'
    (Total Analysed, Normal, Malicious, Blocked).

    NOTA: ai_engine.predict() cuma pulangkan prediction "Malicious"
    atau "Normal" (Isolation Forest ialah binary classifier: -1/1).
    Tiada kategori "Suspicious" dihasilkan oleh AI - column tu
    dikekalkan di sini untuk future-proofing sahaja (contoh jika
    threshold pertengahan ditambah kelak), dan akan sentiasa
    bernilai 0 buat masa ini.
    """
    query = """
        SELECT
            COUNT(*) AS total_analysed,
            SUM(CASE WHEN prediction = 'Normal' THEN 1 ELSE 0 END) AS normal_count,
            SUM(CASE WHEN prediction = 'Suspicious' THEN 1 ELSE 0 END) AS suspicious_count,
            SUM(CASE WHEN prediction = 'Malicious' THEN 1 ELSE 0 END) AS malicious_count,
            SUM(CASE WHEN recommendation = 'Block Domain' THEN 1 ELSE 0 END) AS blocked_count
        FROM ai_results
    """
    cursor = conn.cursor(dictionary=True)
    cursor.execute(query)
    row = cursor.fetchone()
    cursor.close()
    return row
