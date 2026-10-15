"""
train_model.py

Dynamic DNS-Based Threat Prevention System

AI Training Module
------------------
Model:
    Isolation Forest

Features:
    1. entropy
    2. length
    3. digit_ratio
    4. request_count
    5. unique_clients
    6. request_rate
    7. is_high_request
    8. is_many_clients

Output:
    isolation_forest_model.pkl

============================================================
PEMBETULAN berbanding versi asal:

[FIX 1] SEBELUM INI, build_dataset() panggil
        behavior_analysis.extract_behavior_features(conn, domain) untuk
        SETIAP domain unik dalam dns_logs. Fungsi itu direka untuk
        real-time inference -- ia kira request_count/unique_clients
        dalam tetingkap TIME_WINDOW_MINUTES-minit ANCHOR PADA "SEKARANG"
        (datetime.now()), bukan berdasarkan bila domain tu sebenarnya
        di-query dalam sejarah. Akibatnya, domain yang diquery sejam/
        sehari/seminggu sebelum training dijalankan akan dapat
        request_count=0, unique_clients=0, dst -- walaupun domain tu
        sebenarnya PERNAH ada trafik tinggi. Ini buat 5 daripada 8
        feature kekal sifar untuk hampir semua sampel training,
        menjadikannya tak berguna untuk Isolation Forest belajar.

        PEMBETULAN: fungsi baharu build_behavior_features() di bawah
        kira feature ni terus daripada SEJARAH PENUH dns_logs --
        domain "dibahagi" kepada bucket masa TIME_WINDOW_MINUTES-minit
        (saiz tetingkap sama macam production), dan bucket PALING SIBUK
        (max) bagi setiap domain diambil sebagai wakil tingkah laku
        "terburuk" domain tu. Ini kekalkan skala nilai setanding dengan
        apa yang extract_behavior_features() hasilkan secara langsung
        semasa production (satu snapshot tetingkap TIME_WINDOW_MINUTES-
        minit), bukan jumlah keseluruhan sejarah yang boleh jadi
        beratus/beribu kali lebih besar.

[FIX 2] SEBELUM INI, satu query SQL berasingan dijalankan untuk SETIAP
        domain unik (N+1 query problem) -- perlahan untuk dataset
        besar. PEMBETULAN: kini hanya SATU query SQL dijalankan untuk
        ambil semua rekod dns_logs sekali gus; semua pengiraan per-
        domain dilakukan secara lokal dalam pandas.

[FIX 3] Threshold (TIME_WINDOW_MINUTES, AI_FEATURE_REQUEST_THRESHOLD,
        AI_FEATURE_CLIENT_THRESHOLD) kini di-import terus daripada
        behavior_analysis.py (satu sumber kebenaran / single source of
        truth) supaya training dan production SENTIASA guna nilai
        threshold yang sama -- elak kedua-dua fail "drift" berasingan
        kalau salah satu diubah pada masa depan.
============================================================
"""

import os
import math
import logging

import joblib
import pandas as pd
import mysql.connector

from dotenv import load_dotenv
from sklearn.ensemble import IsolationForest

# [FIX 1 + FIX 3] Tak lagi import extract_behavior_features() (direka
# untuk real-time inference, tak sesuai untuk bulk historical training)
# -- sebaliknya import threshold/constant yang releven sahaja, supaya
# training & production konsisten guna nilai sama.
from behavior_analysis import (
    TIME_WINDOW_MINUTES,
    AI_FEATURE_REQUEST_THRESHOLD,
    AI_FEATURE_CLIENT_THRESHOLD,
)


# ============================================================
# LOAD ENVIRONMENT
# ============================================================

load_dotenv()


# ============================================================
# LOGGING
# ============================================================

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(message)s"
)

logger = logging.getLogger(__name__)


# ============================================================
# MODEL CONFIGURATION
# ============================================================

MODEL_PATH = "isolation_forest_model.pkl"


# ============================================================
# FEATURE ORDER
#
# PENTING: susunan ni MESTI sepadan dengan FEATURE_ORDER dalam
# ai_engine.py (sudah disahkan sepadan). Jangan ubah susunan di sini
# tanpa ubah ai_engine.py juga -- kalau tidak, model akan beri
# prediksi salah secara senyap.
# ============================================================

FEATURE_ORDER = [
    "entropy",
    "length",
    "digit_ratio",
    "request_count",
    "unique_clients",
    "request_rate",
    "is_high_request",
    "is_many_clients",
]


# ============================================================
# DATABASE CONFIGURATION
# ============================================================

DB_CONFIG = {
    "host": os.getenv("DB_HOST", "localhost"),
    "user": os.getenv("DB_USER", "fyp_user"),
    "password": os.getenv("DB_PASSWORD", "fyp2026dns"),
    "database": os.getenv("DB_NAME", "dns_monitor_database"),
}


# ============================================================
# DOMAIN ENTROPY
#
# NOTA: logik ni SENGAJA dikekalkan SAMA PERSIS dengan calc_entropy()
# dalam ai_engine.py (guna label pertama sahaja sebelum '.'). Jangan
# ubah salah satu tanpa ubah yang satu lagi -- kalau tidak, berlaku
# "train-serve skew" (model dilatih guna definisi berbeza berbanding
# definisi masa prediksi sebenar).
# ============================================================

def calc_entropy(domain):
    """
    Calculate Shannon entropy untuk domain.
    """

    domain = str(domain or "").strip().lower()

    if not domain:
        return 0.0

    # Ambil bahagian pertama sebelum '.'
    name = domain.split(".")[0]

    if not name:
        return 0.0

    probabilities = [
        name.count(character) / len(name)
        for character in set(name)
    ]

    entropy = -sum(
        probability * math.log2(probability)
        for probability in probabilities
    )

    return round(entropy, 4)


# ============================================================
# DIGIT RATIO
#
# NOTA: sama macam calc_entropy() di atas -- dikekalkan SAMA PERSIS
# dengan digit_ratio() dalam ai_engine.py (guna domain PENUH, bukan
# cuma label pertama).
# ============================================================

def digit_ratio(domain):
    """
    Kira percentage digit dalam domain.
    """

    domain = str(domain or "").strip()

    if not domain:
        return 0.0

    ratio = (
        sum(character.isdigit() for character in domain)
        / len(domain)
    )

    return round(ratio, 4)


# ============================================================
# [FIX 1 + FIX 2] BEHAVIOR FEATURES UNTUK TRAINING
# (guna sejarah PENUH dns_logs, bukan tetingkap "sekarang")
# ============================================================

def build_behavior_features(raw_logs):
    """
    Kira 5 feature behavior (request_count, unique_clients,
    request_rate, is_high_request, is_many_clients) untuk SETIAP
    domain, terus daripada sejarah PENUH dns_logs yang sudah diambil
    (raw_logs) -- BUKAN dengan panggil
    behavior_analysis.extract_behavior_features() yang anchor pada
    waktu semasa (sesuai untuk real-time, tapi tidak untuk bulk
    historical training).

    Kaedah:
        1. Setiap rekod dns_logs "dibahagi" kepada bucket masa
           TIME_WINDOW_MINUTES-minit (contoh: 5 minit), guna
           timestamp sebenar rekod tu (bukan waktu training
           dijalankan).
        2. Untuk setiap (domain, bucket), kira bilangan request dan
           bilangan source_ip unik dalam bucket tu.
        3. Untuk setiap domain, ambil bucket yang PALING SIBUK (max)
           sebagai wakil tingkah laku "paling ekstrem" domain tu
           sepanjang sejarah -- ini penting supaya model nampak
           corak burst/anomali yang pernah berlaku, bukan purata
           yang "melecehkan" corak tersebut.

    Nilai yang terhasil (request_count, unique_clients) setanding
    dari segi skala dengan apa yang extract_behavior_features()
    hasilkan secara langsung semasa production (satu snapshot
    tetingkap TIME_WINDOW_MINUTES-minit) -- bukan jumlah keseluruhan
    sejarah yang boleh jadi jauh lebih besar.

    Parameter:
        raw_logs : pandas.DataFrame dengan column
                   ["domain_name", "source_ip", "timestamp"]

    Return:
        pandas.DataFrame, indexed by domain_name, dengan column:
            request_count, unique_clients, request_rate,
            is_high_request, is_many_clients
    """

    df = raw_logs.copy()

    df["bucket"] = df["timestamp"].dt.floor(f"{TIME_WINDOW_MINUTES}min")

    # --------------------------------------------------------
    # Request count & unique client PER BUCKET, PER DOMAIN
    # --------------------------------------------------------

    per_bucket = (
        df.groupby(["domain_name", "bucket"])
        .agg(
            request_count=("source_ip", "size"),
            unique_clients=("source_ip", "nunique"),
        )
        .reset_index()
    )

    # --------------------------------------------------------
    # Ambil bucket PALING SIBUK (max) bagi setiap domain
    # --------------------------------------------------------

    per_domain = (
        per_bucket.groupby("domain_name")
        .agg(
            request_count=("request_count", "max"),
            unique_clients=("unique_clients", "max"),
        )
    )

    per_domain["request_rate"] = (
        per_domain["request_count"] / TIME_WINDOW_MINUTES
    ).round(4)

    per_domain["is_high_request"] = (
        per_domain["request_count"] >= AI_FEATURE_REQUEST_THRESHOLD
    ).astype(int)

    per_domain["is_many_clients"] = (
        per_domain["unique_clients"] >= AI_FEATURE_CLIENT_THRESHOLD
    ).astype(int)

    return per_domain


# ============================================================
# BUILD TRAINING DATASET
# ============================================================

def build_dataset(conn):
    """
    [FIX 2] Ambil SEMUA rekod dns_logs (domain_name, source_ip,
    timestamp) dalam SATU query sahaja, kemudian bina 8 feature untuk
    setiap domain unik secara lokal dalam pandas (elak N+1 query).
    """

    logger.info("[AI TRAIN] Building dataset...")

    query = """
        SELECT
            domain_name,
            source_ip,
            timestamp
        FROM dns_logs
        WHERE domain_name IS NOT NULL
          AND domain_name != ''
    """

    raw = pd.read_sql(query, conn)

    if raw.empty:
        logger.warning("[AI TRAIN] Tiada domain dalam dns_logs.")
        return pd.DataFrame(), pd.DataFrame()

    raw["domain_name"] = (
        raw["domain_name"].astype(str).str.strip().str.lower()
    )

    raw["timestamp"] = pd.to_datetime(raw["timestamp"], errors="coerce")
    raw = raw.dropna(subset=["timestamp"])

    if raw.empty:
        logger.warning(
            "[AI TRAIN] Tiada timestamp sah dalam dns_logs."
        )
        return pd.DataFrame(), pd.DataFrame()

    # [FIX 1] Kira behavior features daripada sejarah PENUH
    behavior_by_domain = build_behavior_features(raw)

    unique_domains = behavior_by_domain.index.tolist()

    logger.info(f"[AI TRAIN] {len(unique_domains)} unique domains dijumpai.")

    rows = []

    # ========================================================
    # EXTRACT FEATURE (domain-based + behavior-based)
    # ========================================================

    for domain in unique_domains:

        try:
            behavior = behavior_by_domain.loc[domain]

            row = {
                "domain_name": domain,
                "entropy": calc_entropy(domain),
                "length": len(domain),
                "digit_ratio": digit_ratio(domain),
                "request_count": behavior["request_count"],
                "unique_clients": behavior["unique_clients"],
                "request_rate": behavior["request_rate"],
                "is_high_request": behavior["is_high_request"],
                "is_many_clients": behavior["is_many_clients"],
            }

            rows.append(row)

        except Exception as e:
            logger.warning(f"[AI TRAIN] Gagal process domain {domain}: {e}")

    # ========================================================
    # CREATE DATAFRAME
    # ========================================================

    full_df = pd.DataFrame(rows)

    if full_df.empty:
        logger.warning("[AI TRAIN] Dataset kosong.")
        return pd.DataFrame(), pd.DataFrame()

    # ========================================================
    # ENSURE FEATURE ORDER
    # ========================================================

    features = full_df[FEATURE_ORDER].copy()

    # ========================================================
    # HANDLE NaN / INFINITE
    # ========================================================

    features = features.replace([float("inf"), float("-inf")], 0)
    features = features.fillna(0)

    logger.info("[AI TRAIN] Feature dataset:")
    logger.info(f"\n{features}")

    return full_df, features


# ============================================================
# TRAIN ISOLATION FOREST
# ============================================================

def train_and_save(features, output_path=MODEL_PATH):
    """
    Train Isolation Forest dan simpan model sebagai .pkl.
    """

    if features.empty:
        raise ValueError("Training dataset kosong.")

    # Minimum data check
    if len(features) < 5:
        raise ValueError(
            "Data terlalu sedikit untuk training Isolation Forest. "
            "Pastikan dns_logs mempunyai sekurang-kurangnya beberapa "
            "domain unik."
        )

    logger.info("====================================")
    logger.info(" TRAINING ISOLATION FOREST")
    logger.info("====================================")
    logger.info(f"Training samples : {len(features)}")
    logger.info(f"Features         : {len(FEATURE_ORDER)}")
    logger.info(f"Feature order    : {FEATURE_ORDER}")

    # ========================================================
    # MODEL
    # ========================================================

    model = IsolationForest(
        n_estimators=200,
        contamination=0.15,
        random_state=42,
        n_jobs=-1,
    )

    # ========================================================
    # TRAIN
    # ========================================================

    model.fit(features)

    # ========================================================
    # SAVE MODEL
    # ========================================================

    joblib.dump(model, output_path)

    logger.info(f"[AI TRAIN] Model disimpan: {output_path}")

    return model


# ============================================================
# SHOW TRAINING SUMMARY
# ============================================================

def show_dataset_summary(full_df, features):
    """
    Paparkan ringkasan dataset selepas training.
    """

    print()
    print("========================================")
    print("       AI TRAINING DATASET")
    print("========================================")
    print(f"Unique domains : {len(full_df)}")
    print(f"Features       : {len(features.columns)}")
    print()
    print("Feature Order:")

    for index, feature in enumerate(FEATURE_ORDER, start=1):
        print(f"  {index}. {feature}")

    print()
    print("Sample:")
    print(features.head(10))
    print("========================================")
    print()


# ============================================================
# DATABASE CONNECTION
# ============================================================

def create_database_connection():

    logger.info("[AI TRAIN] Connecting to MySQL...")

    try:
        conn = mysql.connector.connect(**DB_CONFIG)

        if conn.is_connected():
            logger.info("[AI TRAIN] MySQL connection successful.")
            return conn

        raise ConnectionError("MySQL connection failed.")

    except mysql.connector.Error as e:
        raise ConnectionError(f"MySQL error: {e}")


# ============================================================
# MAIN
# ============================================================

if __name__ == "__main__":

    print()
    print("========================================")
    print("       DNS THREAT PREVENTION")
    print("       AI MODEL TRAINING")
    print("========================================")
    print()

    conn = None

    try:
        # ----------------------------------------------------
        # CONNECT DATABASE
        # ----------------------------------------------------

        conn = create_database_connection()

        # ----------------------------------------------------
        # BUILD DATASET
        # ----------------------------------------------------

        full_df, features = build_dataset(conn)

        # ----------------------------------------------------
        # CHECK DATA
        # ----------------------------------------------------

        if features.empty:
            print("[ERROR] Tiada data untuk training.")
            print("Pastikan dns_logs mempunyai DNS records terlebih dahulu.")
            raise SystemExit(1)

        # ----------------------------------------------------
        # SHOW SUMMARY
        # ----------------------------------------------------

        show_dataset_summary(full_df, features)

        # ----------------------------------------------------
        # TRAIN MODEL
        # ----------------------------------------------------

        train_and_save(features, MODEL_PATH)

        # ----------------------------------------------------
        # SUCCESS
        # ----------------------------------------------------

        print("========================================")
        print("       TRAINING BERJAYA")
        print("========================================")
        print(f"Model : {MODEL_PATH}")
        print(f"Data  : {len(features)} domains")
        print(f"Feature: {len(FEATURE_ORDER)}")
        print()

    except Exception as e:
        logger.error(f"[AI TRAIN] Training failed: {e}")
        print()
        print("[ERROR] Training gagal.")
        print(f"Reason: {e}")
        print()

    finally:
        if conn is not None:
            try:
                conn.close()
                logger.info("[AI TRAIN] MySQL connection closed.")
            except Exception:
                pass
