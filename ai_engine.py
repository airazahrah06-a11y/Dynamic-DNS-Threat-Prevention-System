"""
ai_engine.py
Dynamic DNS-Based Threat Prevention System

AI Prediction Module
Isolation Forest + Explainability

Fixed version — perubahan berbanding versi asal:
  1. logging.basicConfig() ditambah supaya logger.info() sebenar-benarnya
     dipaparkan (sebelum ini hanya logger.error() yang keluar secara default)
  2. Formula "confidence" dibetulkan — sebelum ini ia SAMA PERSIS dengan
     "risk_score" (1 - (decision_score + 0.5) == 0.5 - decision_score),
     jadi domain yang jelas NORMAL akan dapat confidence rendah, yang
     mengelirukan. Kini confidence diukur berasingan berdasarkan jarak
     dari sempadan keputusan (decision boundary), tanpa kira arah.
  3. generate_reason() kini terima prediction_value supaya "reason" tak
     bercanggah dengan "prediction" (contoh: elak kes "Malicious" tapi
     reason kata "No abnormal pattern detected")
  4. Nota ditambah tentang pergantungan FEATURE_ORDER kepada train_model.py
     — perlu kekal SAMA susunan, jika tidak model beri prediksi salah
     secara senyap
"""

import math
import logging
import joblib
import numpy as np

from behavior_analysis import (
    extract_behavior_features,
)


# ============================================================
# LOGGING
# ============================================================

logger = logging.getLogger(__name__)

# (1) Tanpa basicConfig, secara default Python cuma papar WARNING ke atas —
# logger.info() (contoh: mesej "Model berjaya dimuatkan") tak akan kelihatan.
# Kalau ai_engine.py dijalankan sebagai sebahagian sistem yang lebih besar
# dan main.py/modul lain sudah configure root logger, baris ini selamat
# (basicConfig tak buat apa-apa kalau root logger dah ada handler).
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)


# ============================================================
# MODEL CONFIGURATION
# ============================================================

MODEL_PATH = "isolation_forest_model.pkl"


# ============================================================
# LOAD AI MODEL
# ============================================================

try:

    model = joblib.load(
        MODEL_PATH
    )

    logger.info(
        f"[AI] Model berjaya dimuatkan: {MODEL_PATH}"
    )

except FileNotFoundError:

    model = None

    logger.error(
        f"[AI] Model tidak dijumpai: {MODEL_PATH}"
    )

    logger.error(
        "[AI] Jalankan train_model.py dahulu."
    )

except Exception as e:

    model = None

    logger.error(
        f"[AI] Gagal load model: {e}"
    )


# ============================================================
# FEATURE ORDER
#
# PENTING: susunan ni MESTI sama persis dengan susunan feature yang
# digunakan semasa train_model.py melatih model. Kalau tak sama, model
# akan tetap "berjaya" beri prediksi (tiada error dilontar) tapi hasilnya
# SALAH secara senyap kerana setiap nilai feature akan dipadan ke lajur
# yang tersalah. Sentiasa semak silang dengan train_model.py bila fail
# ni diubah.
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
# AI THRESHOLDS
# ============================================================

ENTROPY_THRESHOLD = 3.5

LENGTH_THRESHOLD = 20

DIGIT_RATIO_THRESHOLD = 0.3


# ============================================================
# DOMAIN ENTROPY
# ============================================================

def calc_entropy(domain):
    """
    Calculate Shannon entropy bagi domain.

    Entropy tinggi boleh menunjukkan
    domain yang lebih random / DGA-like.
    """

    domain = str(
        domain or ""
    ).strip().lower()


    name = domain.split(".")[0]


    if len(name) == 0:

        return 0.0


    probabilities = [
        name.count(char) / len(name)
        for char in set(name)
    ]


    entropy = -sum(
        probability * math.log2(probability)
        for probability in probabilities
    )


    return round(
        entropy,
        4
    )


# ============================================================
# DIGIT RATIO
# ============================================================

def digit_ratio(domain):
    """
    Calculate percentage character
    yang merupakan digit.
    """

    domain = str(
        domain or ""
    )


    if len(domain) == 0:

        return 0.0


    digits = sum(
        char.isdigit()
        for char in domain
    )


    return round(
        digits / len(domain),
        4
    )


# ============================================================
# FEATURE EXTRACTION
# ============================================================

def extract_features(
    conn,
    domain
):
    """
    Extract 8 feature yang digunakan
    oleh Isolation Forest.

    3 domain-based features:
        entropy
        length
        digit_ratio

    5 behavior-based features:
        request_count
        unique_clients
        request_rate
        is_high_request
        is_many_clients
    """

    domain = str(
        domain or ""
    ).strip().lower()


    # --------------------------------------------------------
    # BEHAVIOR FEATURES
    # --------------------------------------------------------

    behavior_features = (
        extract_behavior_features(
            conn,
            domain
        )
    )


    # --------------------------------------------------------
    # COMBINE DOMAIN + BEHAVIOR FEATURES
    # --------------------------------------------------------

    features = {

        "entropy":
            calc_entropy(domain),

        "length":
            len(domain),

        "digit_ratio":
            digit_ratio(domain),

        "request_count":
            behavior_features[
                "request_count"
            ],

        "unique_clients":
            behavior_features[
                "unique_clients"
            ],

        "request_rate":
            behavior_features[
                "request_rate"
            ],

        "is_high_request":
            behavior_features[
                "is_high_request"
            ],

        "is_many_clients":
            behavior_features[
                "is_many_clients"
            ],
    }


    logger.info(
        f"[AI FEATURES] "
        f"{domain} -> {features}"
    )


    return features


# ============================================================
# EXPLAINABILITY
# ============================================================

def generate_reason(
    features,
    prediction_value=None,
):
    """
    Generate explanation kenapa domain
    dianggap berisiko.

    prediction_value (pilihan): hasil ramalan Isolation Forest
    (-1 = Malicious, 1 = Normal). Digunakan untuk elak "reason" yang
    bercanggah dengan "prediction" (contoh: model kata Malicious tapi
    tiada satu pun threshold heuristik tercapai).
    """

    reasons = []


    # --------------------------------------------------------
    # ENTROPY
    # --------------------------------------------------------

    if (
        features["entropy"]
        > ENTROPY_THRESHOLD
    ):

        reasons.append(
            f"High entropy "
            f"({features['entropy']:.2f})"
        )


    # --------------------------------------------------------
    # DOMAIN LENGTH
    # --------------------------------------------------------

    if (
        features["length"]
        > LENGTH_THRESHOLD
    ):

        reasons.append(
            f"Long domain name "
            f"({features['length']} chars)"
        )


    # --------------------------------------------------------
    # DIGIT RATIO
    # --------------------------------------------------------

    if (
        features["digit_ratio"]
        > DIGIT_RATIO_THRESHOLD
    ):

        percentage = (
            features["digit_ratio"]
            * 100
        )


        reasons.append(
            f"High digit ratio "
            f"({percentage:.0f}%)"
        )


    # --------------------------------------------------------
    # REQUEST FREQUENCY
    # --------------------------------------------------------

    if (
        features["is_high_request"]
        == 1
    ):

        reasons.append(
            f"High DNS request "
            f"frequency "
            f"({features['request_count']} req)"
        )


    # --------------------------------------------------------
    # UNIQUE CLIENTS
    # --------------------------------------------------------

    if (
        features["is_many_clients"]
        == 1
    ):

        reasons.append(
            f"Unusually high "
            f"unique client count "
            f"({features['unique_clients']})"
        )


    # --------------------------------------------------------
    # NORMAL / FALLBACK
    #
    # (3) Elak "reason" bercanggah dengan "prediction". Threshold
    # heuristik di atas berasingan daripada logik Isolation Forest, jadi
    # model boleh sahaja kata "Malicious" walaupun tiada satu threshold
    # pun tercapai (model nampak corak lain dalam data behavior).
    # --------------------------------------------------------

    if not reasons:

        if prediction_value == -1:

            reasons.append(
                "Flagged by AI model based on combined behaviour pattern "
                "(no single threshold rule triggered)"
            )

        else:

            reasons.append(
                "No abnormal pattern detected"
            )


    return reasons


# ============================================================
# AI PREDICTION
# ============================================================

def predict(
    conn,
    domain
):
    """
    Jalankan Isolation Forest prediction.

    Return:

    {
        prediction,
        confidence,
        risk_score,
        reason,
        features
    }
    """

    domain = str(
        domain or ""
    ).strip().lower()


    # --------------------------------------------------------
    # CHECK MODEL
    # --------------------------------------------------------

    if model is None:

        logger.error(
            "[AI] Model belum tersedia."
        )


        return {

            "prediction":
                "Unknown",

            "confidence":
                0,

            "risk_score":
                0,

            "reason": [
                "Model not loaded"
            ],

            "features":
                {},
        }


    # --------------------------------------------------------
    # EXTRACT FEATURES
    # --------------------------------------------------------

    try:

        features = extract_features(
            conn,
            domain
        )

    except Exception as e:

        logger.error(
            f"[AI] Feature extraction "
            f"failed untuk {domain}: {e}"
        )


        return {

            "prediction":
                "Unknown",

            "confidence":
                0,

            "risk_score":
                0,

            "reason": [
                "Feature extraction failed"
            ],

            "features":
                {},
        }


    # --------------------------------------------------------
    # CREATE FEATURE VECTOR
    # --------------------------------------------------------

    try:

        X = np.array(
            [
                [
                    features[feature]
                    for feature
                    in FEATURE_ORDER
                ]
            ],
            dtype=float
        )

    except Exception as e:

        logger.error(
            f"[AI] Feature vector error "
            f"untuk {domain}: {e}"
        )


        return {

            "prediction":
                "Unknown",

            "confidence":
                0,

            "risk_score":
                0,

            "reason": [
                "Feature vector error"
            ],

            "features":
                features,
        }


    # --------------------------------------------------------
    # ISOLATION FOREST
    # --------------------------------------------------------

    try:

        decision_score = float(
            model.decision_function(X)[0]
        )


        prediction_value = int(
            model.predict(X)[0]
        )


    except Exception as e:

        logger.error(
            f"[AI] Model prediction "
            f"failed untuk {domain}: {e}"
        )


        return {

            "prediction":
                "Unknown",

            "confidence":
                0,

            "risk_score":
                0,

            "reason": [
                "AI prediction failed"
            ],

            "features":
                features,
        }


    # --------------------------------------------------------
    # RISK SCORE
    #
    # decision_score IsolationForest: positif = lebih "normal" (inlier),
    # negatif = lebih "anomali" (outlier/berpotensi malicious).
    # risk_score: 0 (langsung tak berisiko) -> 100 (sangat berisiko).
    # --------------------------------------------------------

    risk_score = round(
        min(
            max(
                (
                    0.5
                    - decision_score
                )
                * 100,
                0
            ),
            100
        )
    )


    # --------------------------------------------------------
    # CONFIDENCE
    #
    # (2) DIBETULKAN: sebelum ini formula confidence SAMA PERSIS dengan
    # risk_score (1 - (decision_score + 0.5) == 0.5 - decision_score),
    # jadi domain yang jelas NORMAL akan dilaporkan confidence RENDAH —
    # mengelirukan. Confidence sepatutnya ukur sejauh mana model YAKIN
    # dengan label yang diberi (Normal ATAU Malicious), tanpa kira arah.
    #
    # Di sini confidence dikira daripada jarak decision_score dari
    # sempadan keputusan (0.0): semakin jauh dari sempadan (positif
    # ATAU negatif), semakin yakin model dengan labelnya.
    # --------------------------------------------------------

    confidence = round(
        min(
            abs(decision_score) * 200,
            100
        ),
        1
    )


    # --------------------------------------------------------
    # PREDICTION LABEL
    # --------------------------------------------------------

    if prediction_value == -1:

        prediction_label = (
            "Malicious"
        )

    else:

        prediction_label = (
            "Normal"
        )


    # --------------------------------------------------------
    # REASONS
    # --------------------------------------------------------

    reasons = generate_reason(
        features,
        prediction_value,
    )


    # --------------------------------------------------------
    # LOG
    # --------------------------------------------------------

    logger.info(
        f"[AI] {domain} -> "
        f"{prediction_label} | "
        f"confidence={confidence}% | "
        f"risk={risk_score}"
    )


    # --------------------------------------------------------
    # RETURN RESULT
    # --------------------------------------------------------

    return {

        "prediction":
            prediction_label,

        "confidence":
            confidence,

        "risk_score":
            risk_score,

        "reason":
            reasons,

        "features":
            features,
    }
