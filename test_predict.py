"""
test_predict.py
Fasa 2 - Dynamic DNS-Based Threat Prevention System

Fail ini BUKAN sebahagian daripada pipeline utama sistem. Ia digunakan
khas untuk TESTING/VERIFY sama ada semua fungsi dalam ai_engine.py
(yang bergantung kepada behavior_analysis.py dan model isolation_forest_model.pkl
hasil train_model.py) berfungsi dengan betul sebelum diintegrasikan ke
dalam detection_engine.py dan db_writer.py.

Fungsi yang diuji:
- calc_entropy()
- digit_ratio()
- extract_features()
- generate_reason()
- predict()

Domain diuji terdiri daripada:
1. Domain RANDOM yang diambil terus dari dns_logs (data sebenar,
   request_count/unique_clients bukan 0)
2. Domain "buatan" bercorak DGA/phishing untuk uji reaksi AI terhadap
   nama domain mencurigakan (request_count akan 0 sebab tiada dalam log)
"""

import mysql.connector
from ai_engine import (
    calc_entropy,
    digit_ratio,
    extract_features,
    generate_reason,
    predict,
)
import os
from dotenv import load_dotenv

load_dotenv()

# ============================================================
# SAMBUNGAN DATABASE
# ============================================================
conn = mysql.connector.connect(
    host=os.getenv("DB_HOST"),
    user=os.getenv("DB_USER"),
    password=os.getenv("DB_PASSWORD"),       # <-- tukar dengan password sebenar
    database=os.getenv("DB_NAME")
)


# ============================================================
# AMBIL DOMAIN RANDOM TERUS DARI dns_logs
# ============================================================
def get_random_domains(conn, limit=5):
    cursor = conn.cursor()
    cursor.execute(
        "SELECT DISTINCT domain_name FROM dns_logs ORDER BY RAND() LIMIT %s",
        (limit,)
    )
    rows = cursor.fetchall()
    cursor.close()
    return [row[0] for row in rows]


# ============================================================
# SENARAI DOMAIN UNTUK DIUJI
# ============================================================
test_domains = get_random_domains(conn, limit=5)

# Domain "buatan" - untuk uji corak DGA-style / phishing-style
test_domains += [
    "xj92kdle.top",
    "a1b2c3d4e5f6g7h8.info",
    "secure-login-verify123.com",
    "normalwebsite.com",
]


# ============================================================
# JALANKAN TEST UNTUK SETIAP DOMAIN
# ============================================================
for domain in test_domains:
    print("=" * 60)
    print(f"Domain: {domain}")

    # Test calc_entropy()
    e = calc_entropy(domain)
    print(f"  Entropy: {e:.3f}")

    # Test digit_ratio()
    dr = digit_ratio(domain)
    print(f"  Digit Ratio: {dr:.3f}")

    # Test extract_features()
    feats = extract_features(conn, domain)
    print(f"  Features: {feats}")

    # Test generate_reason()
    reasons = generate_reason(feats)
    print(f"  Reason: {reasons}")

    # Test predict()
    result = predict(conn, domain)
    print(f"  Prediction: {result['prediction']}")
    print(f"  Confidence: {result['confidence']}%")
    print(f"  Risk Score: {result['risk_score']}/100")

print("=" * 60)
conn.close()
