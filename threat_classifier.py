"""
threat_classifier.py

Threat Category Classification Module

Purpose:
- Determine the most likely threat category
- Use evidence from:
    1. Threat Intelligence
    2. Rule-Based Detection
    3. Behavior Analysis
    4. Isolation Forest AI

This module does NOT block domains.
It only determines the threat category.

Detection Engine remains responsible for:
- Classification
- Alert
- Pi-hole blocking
- Saving block events
"""


# ============================================================
# THREAT CATEGORIES
# ============================================================

THREAT_CATEGORIES = [

    "None",

    "Phishing",

    "Malware/Botnet",

    "Botnet/C2",

    "DGA",

    "DNS Tunneling",

    "Fast Flux",

    "DNS Flood",

    "DDoS Attack",

    "Anomalous DNS Activity",

    "Malicious Activity",

    "Suspicious Activity",

    "Unknown"
]


# ============================================================
# NORMALIZE TEXT
# ============================================================

def _text(value):

    if value is None:
        return ""

    return str(value).strip().lower()


# ============================================================
# GET AI REASONS
# ============================================================

def _get_ai_reason_text(ai_result):

    if not ai_result:
        return ""

    reason = ai_result.get(
        "reason",
        []
    )

    if isinstance(reason, list):

        return " ".join(
            str(item)
            for item in reason
        ).lower()

    return str(reason).lower()


# ============================================================
# CLASSIFY THREAT
# ============================================================

def classify_threat(
    domain,
    classification="UNKNOWN",
    matched_source=None,
    behavior_result=None,
    ai_result=None,
    dns_tunneling=False,
    fast_flux=False
):

    """
    Determine threat category.

    Parameters:
        domain
            Domain being analysed.

        classification
            SAFE / SUSPICIOUS / MALICIOUS

        matched_source
            Threat Intelligence / Rule-Based / AI source.

        behavior_result
            Result returned by Behavior Analysis.

        ai_result
            Result returned by AI Engine.

        dns_tunneling
            Boolean result from DNS tunneling detection.

        fast_flux
            Boolean result from Fast Flux detection.

    Returns:
        Threat category string.
    """


    # ========================================================
    # SAFE
    # ========================================================

    if classification == "SAFE":

        return "None"


    source = _text(
        matched_source
    )

    domain_text = _text(
        domain
    )

    behavior_text = _text(
        behavior_result
    )

    ai_reason = _get_ai_reason_text(
        ai_result
    )


    # ========================================================
    # THREAT INTELLIGENCE
    # ========================================================

    if "openphish" in source:

        return "Phishing"


    if "threatfox" in source:

        return "Malware/Botnet"


    if (
        "alienvault" in source
        or "otx" in source
    ):

        return "Malicious Activity"


    # ========================================================
    # DNS TUNNELING
    # ========================================================

    if dns_tunneling:

        return "DNS Tunneling"


    if (
        "tunneling" in behavior_text
        or "dns tunnel" in behavior_text
    ):

        return "DNS Tunneling"


    # ========================================================
    # FAST FLUX
    # ========================================================

    if fast_flux:

        return "Fast Flux"


    if "fast flux" in behavior_text:

        return "Fast Flux"


    # ========================================================
    # AI ANALYSIS
    # ========================================================

    if ai_result:

        prediction = _text(
            ai_result.get(
                "prediction",
                ""
            )
        )

        features = ai_result.get(
            "features",
            {}
        )

        request_count = features.get(
            "request_count",
            0
        )

        unique_clients = features.get(
            "unique_clients",
            0
        )


        # ----------------------------------------------------
        # DDoS
        # ----------------------------------------------------

        try:

            if int(unique_clients) >= 20:

                return "DDoS Attack"

        except (ValueError, TypeError):

            pass


        # ----------------------------------------------------
        # DNS FLOOD
        # ----------------------------------------------------

        try:

            if (
                int(request_count) > 100
                and int(unique_clients) < 20
            ):

                return "DNS Flood"

        except (ValueError, TypeError):

            pass


        # ----------------------------------------------------
        # DGA
        # ----------------------------------------------------

        dga_keywords = [

            "entropy",

            "long domain",

            "long subdomain",

            "digit ratio",

            "random",

            "dga",

            "high entropy"

        ]


        if any(
            keyword in ai_reason
            for keyword in dga_keywords
        ):

            return "DGA"


        # ----------------------------------------------------
        # BOTNET / C2
        # ----------------------------------------------------

        c2_keywords = [

            "c2",

            "command and control",

            "botnet",

            "beacon",

            "malware communication"

        ]


        if any(
            keyword in ai_reason
            for keyword in c2_keywords
        ):

            return "Botnet/C2"


        # ----------------------------------------------------
        # AI ANOMALY
        # ----------------------------------------------------

        if (
            prediction == "malicious"
            and not ai_reason
        ):

            return "Anomalous DNS Activity"


    # ========================================================
    # BEHAVIOR ANALYSIS
    # ========================================================

    if behavior_result:

        behavior_keywords = [

            "dns flood",
            "flood",
            "ddos",
            "tunneling",
            "fast flux",
            "botnet",
            "c2",
            "dga"

        ]


        for keyword in behavior_keywords:

            if keyword in behavior_text:

                if keyword == "dns flood":
                    return "DNS Flood"

                if keyword == "flood":
                    return "DNS Flood"

                if keyword == "ddos":
                    return "DDoS Attack"

                if keyword == "tunneling":
                    return "DNS Tunneling"

                if keyword == "fast flux":
                    return "Fast Flux"

                if keyword == "botnet":
                    return "Botnet/C2"

                if keyword == "c2":
                    return "Botnet/C2"

                if keyword == "dga":
                    return "DGA"


    # ========================================================
    # RULE-BASED DETECTION
    # ========================================================

    if (
        "rule-based" in source
        or "rule based" in source
    ):

        return "Suspicious Activity"


    # ========================================================
    # AI ISOLATION FOREST
    # ========================================================

    if (
        "ai" in source
        and "isolation" in source
    ):

        return "Anomalous DNS Activity"


    # ========================================================
    # SUSPICIOUS DOMAIN KEYWORDS
    # ========================================================

    suspicious_keywords = [

        "login",
        "verify",
        "secure",
        "account",
        "password",
        "bank"

    ]


    suspicious_count = sum(
        keyword in domain_text
        for keyword in suspicious_keywords
    )


    if suspicious_count >= 2:

        return "Suspicious Activity"


    # ========================================================
    # DEFAULT
    # ========================================================

    if classification in (
        "MALICIOUS",
        "SUSPICIOUS"
    ):

        return "Suspicious Activity"


    return "Unknown"
