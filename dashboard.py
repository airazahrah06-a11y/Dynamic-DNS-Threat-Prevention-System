"""
dashboard.py
Dynamic DNS-Based Threat Prevention System
Professional Streamlit Dashboard
"""

import os
import re
import subprocess
from datetime import datetime, timedelta

import pandas as pd
import mysql.connector
from mysql.connector import Error
import streamlit as st
import plotly.express as px
import plotly.graph_objects as go

# [FIX BAHARU] Naikkan had Pandas Styler ("styler.render.max_elements").
# Default Pandas cuma benarkan 262,144 cell distyle sekali gus
# (row x column). Bila jumlah rekod dns_logs/domain_cache/alerts
# membesar (contoh 77,000+ baris x 9 column = 693,675 cell) akibat
# testing berterusan, .style.apply(highlight_classification, ...)
# dalam pages DNS Logs/Domain Cache/Alerts akan CRASH dengan
# StreamlitAPIException. Naikkan had ke angka jauh lebih besar
# supaya dashboard tetap boleh papar & highlight walaupun data
# sistem dah membesar (contoh selepas demo/testing berulang kali).
pd.set_option("styler.render.max_elements", 5_000_000)

# ============================================================
# PAGE CONFIG
# ============================================================

st.set_page_config(
    page_title="DNS Threat Prevention",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ============================================================
# THEME / CSS
# ============================================================

st.markdown(
    """
<style>
/* ---------- Global ---------- */
.stApp {
    background:
        radial-gradient(circle at 85% 5%, rgba(37,99,235,.10), transparent 25%),
        radial-gradient(circle at 15% 20%, rgba(16,185,129,.06), transparent 25%),
        #070B12;
    color: #E5E7EB;
}

.block-container {
    padding-top: 1.2rem;
    padding-bottom: 2rem;
    max-width: 1500px;
}

h1, h2, h3, h4 {
    color: #F8FAFC !important;
}

p, label, .stCaption {
    color: #94A3B8;
}

/* ---------- Sidebar ---------- */
section[data-testid="stSidebar"] {
    background: linear-gradient(180deg, #0B1220 0%, #080D16 100%);
    border-right: 1px solid #1E293B;
}

section[data-testid="stSidebar"] .block-container {
    padding-top: 1.4rem;
}

.sidebar-brand {
    padding: 10px 4px 18px 4px;
}

.sidebar-brand-title {
    font-size: 19px;
    font-weight: 800;
    color: #F8FAFC;
    letter-spacing: .2px;
}

.sidebar-brand-sub {
    font-size: 11px;
    color: #64748B;
    margin-top: 4px;
}

.status-card {
    background: rgba(16,185,129,.08);
    border: 1px solid rgba(16,185,129,.25);
    border-radius: 12px;
    padding: 12px;
    margin: 12px 0 14px 0;
}

.status-dot {
    display: inline-block;
    width: 8px;
    height: 8px;
    border-radius: 50%;
    background: #22C55E;
    box-shadow: 0 0 10px rgba(34,197,94,.8);
    margin-right: 7px;
}

.status-text {
    color: #86EFAC;
    font-weight: 700;
    font-size: 12px;
}

.side-stat {
    display: flex;
    justify-content: space-between;
    padding: 6px 0;
    border-bottom: 1px solid rgba(51,65,85,.35);
    font-size: 12px;
}

.side-stat:last-child {
    border-bottom: none;
}

.side-stat-label {
    color: #64748B;
}

.side-stat-value {
    color: #E2E8F0;
    font-weight: 700;
}

/* ---------- Top header ---------- */
.top-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    background: linear-gradient(135deg, rgba(15,23,42,.96), rgba(15,23,42,.72));
    border: 1px solid #1E293B;
    border-radius: 16px;
    padding: 18px 22px;
    margin-bottom: 18px;
    box-shadow: 0 12px 35px rgba(0,0,0,.20);
}

.top-title {
    color: #F8FAFC;
    font-size: 22px;
    font-weight: 800;
}

.top-subtitle {
    color: #64748B;
    font-size: 12px;
    margin-top: 4px;
}

.top-right {
    text-align: right;
}

.operational {
    color: #86EFAC;
    font-size: 12px;
    font-weight: 800;
}

.updated {
    color: #64748B;
    font-size: 10px;
    margin-top: 4px;
}

/* ---------- KPI cards ---------- */
.kpi-card {
    position: relative;
    background: linear-gradient(145deg, #0F172A, #0B1220);
    border: 1px solid #1E293B;
    border-radius: 15px;
    padding: 17px 18px;
    min-height: 105px;
    overflow: hidden;
    box-shadow: 0 8px 25px rgba(0,0,0,.15);
}

.kpi-card:after {
    content: "";
    position: absolute;
    width: 80px;
    height: 80px;
    right: -28px;
    top: -28px;
    border-radius: 50%;
    background: rgba(59,130,246,.08);
}

.kpi-blue { border-left: 3px solid #3B82F6; }
.kpi-green { border-left: 3px solid #22C55E; }
.kpi-yellow { border-left: 3px solid #F59E0B; }
.kpi-red { border-left: 3px solid #EF4444; }
.kpi-purple { border-left: 3px solid #A855F7; }

.kpi-label {
    color: #64748B;
    font-size: 11px;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: .5px;
}

.kpi-value {
    color: #F8FAFC;
    font-size: 28px;
    font-weight: 800;
    margin-top: 8px;
}

.kpi-desc {
    color: #475569;
    font-size: 10px;
    margin-top: 3px;
}

/* ---------- Section ---------- */
.section-title {
    color: #E2E8F0;
    font-size: 15px;
    font-weight: 800;
    margin: 8px 0 12px 0;
}

/* ---------- Cards ---------- */
.info-card {
    background: #0B1220;
    border: 1px solid #1E293B;
    border-radius: 14px;
    padding: 16px;
}

/* ---------- Streamlit widgets ---------- */
div[data-testid="metric-container"] {
    background: #0F172A;
    border: 1px solid #1E293B;
    border-radius: 14px;
    padding: 15px;
}

.stButton > button {
    border-radius: 9px;
    border: 1px solid #334155;
    background: #111827;
    color: #E2E8F0;
}

.stButton > button:hover {
    border-color: #3B82F6;
    color: white;
}

div[data-baseweb="select"] > div,
div[data-baseweb="input"] > div,
textarea {
    background-color: #0F172A !important;
    border-color: #334155 !important;
}

[data-testid="stDataFrame"] {
    border: 1px solid #1E293B;
    border-radius: 10px;
}

/* ---------- Hide Streamlit decoration ---------- */
#MainMenu {visibility: hidden;}
footer {visibility: hidden;}
</style>
""",
    unsafe_allow_html=True,
)

# ============================================================
# CONFIG
# ============================================================

# NOTA: behavior_analysis.py guna default DB_CONFIG berbeza (user="root",
# password=""), manakala di sini default ialah user="fyp_user",
# password="fyp2026dns". Kalau env var DB_USER/DB_PASSWORD/dll tak
# disetkan secara konsisten (contoh dalam fail .env yang dikongsi semua
# modul), sesetengah modul mungkin gagal connect ke MySQL sedangkan yang
# lain berjaya. Pastikan semua modul (dns_monitor.py, behavior_analysis.py,
# ai_engine.py, dashboard.py, detection_engine.py) baca kredential yang
# SAMA - eloknya semua guna os.getenv() + satu fail .env yang dikongsi.
DB_CONFIG = {
    "host": os.getenv("DB_HOST", "localhost"),
    "user": os.getenv("DB_USER", "fyp_user"),
    "password": os.getenv("DB_PASSWORD", "fyp2026dns"),
    "database": os.getenv("DB_NAME", "dns_monitor_database"),
}

# ============================================================
# DATABASE
# ============================================================

@st.cache_resource
def connect():
    try:
        return mysql.connector.connect(
            **DB_CONFIG,
            connection_timeout=5,
        )
    except Error as e:
        st.error(f"❌ Database connection failed: {e}")
        st.stop()


def get_conn():
    conn = connect()

    try:
        if not conn.is_connected():
            conn.reconnect(attempts=3, delay=2)
        else:
            conn.ping(reconnect=True, attempts=3, delay=2)
    except Error as e:
        st.error(f"❌ Database reconnect failed: {e}")
        st.stop()

    return conn


# ============================================================
# DATA LOADERS
# ============================================================

@st.cache_data(ttl=5)
def load_dns():
    # NOTA (dibetulkan): query asal ada typo "dl.matched_sourced" (patut
    # "matched_source") yang menyebabkan SQL error "Unknown column" dan
    # load_dns() gagal senyap (return DataFrame kosong), merosakkan
    # majoriti dashboard yang bergantung pada dns_logs.
    #
    # Selain typo tu, dl.classification / dl.threat_category /
    # dl.matched_source turut dibuang kerana table dns_logs (ikut
    # fetch_new_dns_logs() dalam behavior_analysis.py) hanya ada column:
    # id, source_ip, destination_ip, query_type, domain_name, timestamp.
    # Data Threat Intelligence (classification, threat_category,
    # matched_source) disimpan dalam table domain_cache, bukan dns_logs -
    # jadi diambil melalui LEFT JOIN sahaja (dc.classification AS
    # classification, dan threat_category/matched_source turut ditambah
    # daripada dc untuk kegunaan akan datang jika perlu).
    #
    # Jika detection_engine.py sebenarnya ALTER table dns_logs untuk
    # tambah column classification/threat_category/matched_source
    # sendiri, sila kembalikan semula rujukan dl.<column> tersebut - tapi
    # pastikan namanya "matched_source" (bukan "matched_sourced").
    query = """
        SELECT
            dl.id,
            dl.source_ip,
            dl.destination_ip,
            dl.query_type,
            dl.domain_name,
            dl.timestamp,
            dc.classification AS classification,
            dc.threat_category AS threat_category,
            dc.matched_source AS matched_source
        FROM dns_logs dl
        LEFT JOIN domain_cache dc
            ON dl.domain_name = dc.domain
        ORDER BY dl.timestamp DESC
    """

    try:
        df = pd.read_sql(query, get_conn())

        if "classification" in df.columns:
            df["classification"] = (
                df["classification"]
                .fillna("UNKNOWN")
                .astype(str)
                .str.upper()
            )

        if "timestamp" in df.columns:
            df["timestamp"] = pd.to_datetime(
                df["timestamp"], errors="coerce"
            )

        return df

    except Exception as e:
        st.error(f"❌ Failed loading DNS logs: {e}")
        return pd.DataFrame()


@st.cache_data(ttl=5)
def load_behavior():
    try:
        return pd.read_sql(
            """
            SELECT *
            FROM behavior_logs
            ORDER BY detected_time DESC
            """,
            get_conn(),
        )
    except Exception as e:
        st.warning(f"Behavior data unavailable: {e}")
        return pd.DataFrame()


@st.cache_data(ttl=5)
def load_alert():
    try:
        df = pd.read_sql(
            """
            SELECT *
            FROM alerts
            ORDER BY alert_time DESC
            """,
            get_conn(),
        )

        if "alert_time" in df.columns:
            df["alert_time"] = pd.to_datetime(
                df["alert_time"], errors="coerce"
            )

        return df

    except Exception as e:
        st.warning(f"Alert data unavailable: {e}")
        return pd.DataFrame()


@st.cache_data(ttl=5)
def load_cache():
    try:
        return pd.read_sql(
            """
            SELECT *
            FROM domain_cache
            ORDER BY last_seen DESC
            """,
            get_conn(),
        )
    except Exception as e:
        st.warning(f"Domain cache unavailable: {e}")
        return pd.DataFrame()


@st.cache_data(ttl=5)
def load_ai_results():
    try:
        return pd.read_sql(
            """
            SELECT *
            FROM ai_results
            ORDER BY id DESC
            """,
            get_conn(),
        )
    except Exception:
        return pd.DataFrame()


@st.cache_data(ttl=5)
def load_whitelist():
    try:
        return pd.read_sql(
            """
            SELECT
                id,
                domain,
                added_by,
                added_at
            FROM whitelist
            ORDER BY added_at DESC
            """,
            get_conn(),
        )
    except Exception:
        return pd.DataFrame(
            columns=["id", "domain", "added_by", "added_at"]
        )


# ============================================================
# WHITELIST ACTIONS
# ============================================================

def normalize_domain(domain):
    return (
        str(domain or "")
        .strip()
        .lower()
        .rstrip(".")
    )


def valid_domain(domain):
    if not domain:
        return False

    return bool(
        re.match(
            r"^(?=.{1,253}$)([a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}$",
            domain,
        )
    )


def unblock_domain_pihole(domain):
    """
    [FIX BAHARU] Buang domain daripada denylist Pi-hole SERTA-MERTA
    bila domain ditambah ke whitelist -- tak perlu tunggu
    detector_engine.py proses semula domain tu (yang sebelum ini
    hanya berlaku kalau domain dianggap "baharu" dalam dns_logs,
    dan domain yang DAH cache sebagai MALICIOUS takkan pernah
    dianggap baharu lagi, jadi unblock automatik takkan sempat
    trigger). Guna sintaks Pi-hole v6 ("deny -d").

    Reka bentuk defensif -- kegagalan Pi-hole (contoh sudoers
    belum setup NOPASSWD untuk user yang jalankan dashboard) TIDAK
    menghalang whitelist entry disimpan; admin cuma dapat amaran
    dalam mesej status, whitelist tetap berkuatkuasa untuk semakan
    detection SELEPAS ini.
    """

    domain = str(domain or "").strip().lower()

    if not domain:
        return False, "Domain kosong."

    pihole_cmd = os.getenv("PIHOLE_CMD", "pihole")
    cmd = ["sudo", "-n", pihole_cmd, "deny", "-d", domain]

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=15,
        )

        if result.returncode == 0:
            return True, "Pi-hole denylist dikemas kini."

        return False, (
            f"Pi-hole unblock gagal (exit {result.returncode}): "
            f"{result.stderr.strip() or result.stdout.strip()}"
        )

    except FileNotFoundError:
        return False, "Command 'pihole' tidak dijumpai pada mesin dashboard ini."

    except subprocess.TimeoutExpired:
        return False, "Pi-hole unblock timeout (mungkin sudo minta password)."

    except Exception as e:
        return False, f"Ralat tidak dijangka: {e}"


# ============================================================
# [FIX BAHARU] WHITELIST BUNDLES
# ============================================================
# Senarai "bundle" domain popular yang admin selalu perlu whitelist
# sekali gus (contoh: semua sub-domain Microsoft/Google yang
# digunakan aplikasi biasa). Sebelum ini nampaknya admin whitelist
# domain-domain ni SATU-SATU secara manual dan taip label
# "BUNDLE:<Nama> (admin)" dalam field "Added By" sendiri (rujuk
# entry sedia ada dalam whitelist korang). Ciri baharu ni automasikan
# proses tu -- admin pilih bundle, klik SATU butang, semua domain
# dalam bundle terus ditambah ke whitelist + terus diunblock dari
# Pi-hole (guna add_whitelist() yang sama, row demi row).
WHITELIST_BUNDLES = {
    "Microsoft": [
        "microsoft.com",
        "live.com",
        "msn.com",
        "office.com",
        "windows.com",
        "microsoftonline.com",
        "skype.com",
        "trouter.io",
    ],
    "Google": [
        "google.com",
        "gstatic.com",
        "googleapis.com",
        "googleusercontent.com",
        "youtube.com",
        "ytimg.com",
    ],
    "Grammarly": [
        "grammarly.com",
        "grammarly.io",
    ],
    "Apple": [
        "apple.com",
        "icloud.com",
        "itunes.com",
        "mzstatic.com",
    ],
    "Zoom": [
        "zoom.us",
        "zoomgov.com",
    ],
    "Adobe": [
        "adobe.com",
        "adobelogin.com",
    ],
}


def add_whitelist(domain, added_by):
    domain = normalize_domain(domain)
    added_by = str(added_by or "admin").strip() or "admin"

    if not domain:
        return False, "Domain cannot be empty."

    if not valid_domain(domain):
        return False, "Invalid domain format."

    conn = get_conn()
    cursor = conn.cursor()

    try:
        cursor.execute(
            """
            INSERT INTO whitelist (domain, added_by)
            VALUES (%s, %s)
            ON DUPLICATE KEY UPDATE
                added_by = VALUES(added_by)
            """,
            (domain, added_by),
        )

        # [FIX BAHARU] Kemas kini domain_cache terus ke SAFE di sini
        # (bukan tunggu detector_engine.py reprocess), supaya page
        # "Domain Cache" dan "Alerts" terus reflect status terkini
        # serta-merta lepas whitelist ditambah. Guna try/except
        # berasingan -- kalau table domain_cache tiada row untuk
        # domain ni lagi (belum pernah diproses), UPDATE ni cuma
        # affect 0 rows, tiada error, whitelist tetap berjaya simpan.
        try:
            cursor.execute(
                """
                UPDATE domain_cache
                SET classification = 'SAFE',
                    matched_source = 'WHITELIST (manual override)'
                WHERE domain = %s
                """,
                (domain,),
            )
        except Error:
            pass

        conn.commit()

        # [FIX BAHARU] Unblock Pi-hole SERTA-MERTA (lihat
        # unblock_domain_pihole() di atas) -- ini yang buat admin
        # tak perlu tunggu/paksa query DNS baru untuk unblock
        # berkuatkuasa, sesuai untuk demo live.
        pihole_ok, pihole_msg = unblock_domain_pihole(domain)

        if pihole_ok:
            return True, f"{domain} added to whitelist and unblocked from Pi-hole immediately."

        return True, (
            f"{domain} added to whitelist (cache updated), "
            f"but Pi-hole unblock failed: {pihole_msg}. "
            f"Manual fallback: sudo pihole deny -d {domain}"
        )

    except Error as e:
        conn.rollback()
        return False, str(e)

    finally:
        cursor.close()


def remove_whitelist(domain):
    domain = normalize_domain(domain)

    conn = get_conn()
    cursor = conn.cursor()

    try:
        cursor.execute(
            "DELETE FROM whitelist WHERE domain = %s",
            (domain,),
        )
        deleted = cursor.rowcount

        # [FIX BAHARU] Punca sebenar "remove whitelist tapi domain tak
        # block semula" -- sebelum ini, cuma DELETE dari table whitelist
        # sahaja. Domain tu MASIH ada dalam domain_cache (classification
        # SAFE, dari semasa diwhitelist tadi). Sebab detector_engine.py
        # punya get_new_domains() cuma ambil domain yang TAKDE dalam
        # domain_cache (LEFT JOIN ... WHERE dc.domain IS NULL), domain
        # ni TAK AKAN PERNAH diproses semula -- kekal "SAFE" selama-
        # lamanya walaupun whitelist entry dah dibuang, block page
        # custom tak akan papar sebab TI/Rule/AI tak pernah sempat
        # re-evaluate dia.
        #
        # Dibetulkan dengan PADAM row domain_cache untuk domain ni sekali
        # -- ini "reset" status dia jadi macam domain BAHARU sepenuhnya.
        # Kali seterusnya ada query DNS untuk domain ni, detector_engine.py
        # (TI + Rule + AI) DAN behavior_analysis.py (DGA + Entropy, sebab
        # is_whitelisted() pun akan return False lepas ini) akan
        # re-evaluate dia dari kosong -- kalau memang MALICIOUS (contoh
        # masih match openphish_cache.txt), ia akan diblock semula secara
        # automatik & betul, block page custom pun akan papar normal.
        try:
            cursor.execute(
                "DELETE FROM domain_cache WHERE domain = %s",
                (domain,),
            )
        except Error:
            pass

        conn.commit()

        if deleted:
            return True, (
                f"{domain} removed from whitelist and reset for re-evaluation "
                f"(will be re-checked by TI/Rule/AI/Behaviour Analysis on next query)."
            )

        return False, f"{domain} was not found."

    except Error as e:
        conn.rollback()
        return False, str(e)

    finally:
        cursor.close()


# ============================================================
# HELPERS
# ============================================================

def safe_len(df):
    return 0 if df is None else len(df)


def classification_count(df, value):
    if df.empty or "classification" not in df.columns:
        return 0

    return int(
        (df["classification"].astype(str).str.upper() == value).sum()
    )


def risk_count(df, minimum, maximum=None):
    if df.empty or "risk_score" not in df.columns:
        return 0

    scores = pd.to_numeric(
        df["risk_score"], errors="coerce"
    ).fillna(0)

    if maximum is None:
        return int((scores >= minimum).sum())

    return int(
        ((scores >= minimum) & (scores < maximum)).sum()
    )


def style_dark(fig):
    fig.update_layout(
        plot_bgcolor="#0B1220",
        paper_bgcolor="#0B1220",
        font=dict(color="#CBD5E1"),
        margin=dict(l=20, r=20, t=50, b=20),
        legend=dict(
            bgcolor="rgba(0,0,0,0)",
            font=dict(color="#CBD5E1"),
        ),
    )

    fig.update_xaxes(
        gridcolor="#1E293B",
        zerolinecolor="#1E293B",
    )

    fig.update_yaxes(
        gridcolor="#1E293B",
        zerolinecolor="#1E293B",
    )

    return fig


def highlight_classification(row):
    value = str(
        row.get(
            "classification",
            row.get("action", "")
        )
    ).upper()

    if value in ("MALICIOUS", "BLOCKED"):
        return [
            "background-color: rgba(239,68,68,.15)"
        ] * len(row)

    if value in ("SUSPICIOUS", "ALERT"):
        return [
            "background-color: rgba(245,158,11,.15)"
        ] * len(row)

    return [""] * len(row)


# ============================================================
# LOAD DATA
# ============================================================

dns_logs = load_dns()
behavior_logs = load_behavior()
alerts = load_alert()
domain_cache = load_cache()
ai_results = load_ai_results()
whitelist = load_whitelist()

# ============================================================
# SIDEBAR
# ============================================================

st.sidebar.markdown(
    """
<div class="sidebar-brand">
    <div class="sidebar-brand-title">🛡️ DNS THREAT</div>
    <div class="sidebar-brand-title">PREVENTION</div>
    <div class="sidebar-brand-sub">Security Monitoring Platform</div>
</div>
""",
    unsafe_allow_html=True,
)

st.sidebar.markdown(
    """
<div class="status-card">
    <span class="status-dot"></span>
    <span class="status-text">SYSTEM ONLINE</span>
</div>
""",
    unsafe_allow_html=True,
)

st.sidebar.markdown("### Navigation")

page = st.sidebar.radio(
    "Menu",
    [
        "🏠 Dashboard",
        "📄 DNS Logs",
        "📈 Behavior Analysis",
        "🚨 Alerts",
        "🌐 Domain Cache",
        "🤖 AI Detection",
        "🛡️ Whitelist",
    ],
    label_visibility="collapsed",
)

st.sidebar.markdown("---")

st.sidebar.markdown(
    f"""
<div>
    <div class="side-stat">
        <span class="side-stat-label">DNS Logs</span>
        <span class="side-stat-value">{len(dns_logs):,}</span>
    </div>
    <div class="side-stat">
        <span class="side-stat-label">Alerts</span>
        <span class="side-stat-value">{len(alerts):,}</span>
    </div>
    <div class="side-stat">
        <span class="side-stat-label">Behavior</span>
        <span class="side-stat-value">{len(behavior_logs):,}</span>
    </div>
    <div class="side-stat">
        <span class="side-stat-label">Cache</span>
        <span class="side-stat-value">{len(domain_cache):,}</span>
    </div>
    <div class="side-stat">
        <span class="side-stat-label">Whitelist</span>
        <span class="side-stat-value">{len(whitelist):,}</span>
    </div>
</div>
""",
    unsafe_allow_html=True,
)

st.sidebar.markdown("---")

if st.sidebar.button("🔄 Refresh Data", use_container_width=True):
    st.cache_data.clear()
    st.rerun()

auto_refresh = st.sidebar.checkbox(
    "⏱ Auto-refresh (30s)",
    value=False,
)

if auto_refresh:
    try:
        from streamlit_autorefresh import st_autorefresh
        st_autorefresh(
            interval=30000,
            key="dns_dashboard_refresh",
        )
    except ImportError:
        st.sidebar.caption(
            "Install: pip install streamlit-autorefresh"
        )

# ============================================================
# TOP HEADER
# ============================================================

st.markdown(
    f"""
<div class="top-header">
    <div>
        <div class="top-title">Dynamic DNS Threat Prevention</div>
        <div class="top-subtitle">
            Real-Time DNS Monitoring • Threat Intelligence • Behavioral Analysis • AI
        </div>
    </div>
    <div class="top-right">
        <div>
            <span class="status-dot"></span>
            <span class="operational">SYSTEM OPERATIONAL</span>
        </div>
        <div class="updated">
            Last updated: {datetime.now().strftime("%d %b %Y • %H:%M:%S")}
        </div>
    </div>
</div>
""",
    unsafe_allow_html=True,
)

# ============================================================
# DASHBOARD
# ============================================================

if page == "🏠 Dashboard":

    st.markdown(
        '<div class="section-title">Security Overview</div>',
        unsafe_allow_html=True,
    )

    total_dns = len(dns_logs)
    safe = classification_count(domain_cache, "SAFE")
    suspicious = classification_count(alerts, "SUSPICIOUS")
    malicious = classification_count(alerts, "MALICIOUS")
    total_alert = len(alerts)

    cols = st.columns(5)

    cards = [
        ("kpi-blue", "🌐", "DNS REQUESTS", total_dns, "Captured DNS traffic"),
        ("kpi-green", "✓", "SAFE", safe, "Trusted / allowed"),
        ("kpi-yellow", "⚠", "SUSPICIOUS", suspicious, "Requires attention"),
        ("kpi-red", "✕", "MALICIOUS", malicious, "Threats detected"),
        ("kpi-purple", "🚨", "ALERTS", total_alert, "Security events"),
    ]

    for col, (css, icon, label, value, desc) in zip(cols, cards):
        with col:
            st.markdown(
                f"""
<div class="kpi-card {css}">
    <div class="kpi-label">{icon} {label}</div>
    <div class="kpi-value">{value:,}</div>
    <div class="kpi-desc">{desc}</div>
</div>
""",
                unsafe_allow_html=True,
            )

    st.markdown("---")

    left, right = st.columns(2)

    with left:
        st.markdown(
            '<div class="section-title">Threat Classification</div>',
            unsafe_allow_html=True,
        )

        chart = pd.DataFrame(
            {
                "Classification": [
                    "SAFE",
                    "SUSPICIOUS",
                    "MALICIOUS",
                ],
                "Total": [
                    safe,
                    suspicious,
                    malicious,
                ],
            }
        )

        fig = px.pie(
            chart,
            names="Classification",
            values="Total",
            hole=0.55,
        )

        fig.update_traces(
            textposition="inside",
            textinfo="percent+label",
        )

        st.plotly_chart(
            style_dark(fig),
            use_container_width=True,
        )

    with right:
        st.markdown(
            '<div class="section-title">Threat Summary</div>',
            unsafe_allow_html=True,
        )

        fig2 = px.bar(
            chart,
            x="Classification",
            y="Total",
            color="Classification",
            text="Total",
        )

        st.plotly_chart(
            style_dark(fig2),
            use_container_width=True,
        )

    st.markdown("---")

    left, right = st.columns(2)

    with left:
        st.markdown(
            '<div class="section-title">Latest Security Alerts</div>',
            unsafe_allow_html=True,
        )

        if alerts.empty:
            st.success("No security alerts.")
        else:
            st.dataframe(
                alerts.head(8).style.apply(
                    highlight_classification,
                    axis=1,
                ),
                use_container_width=True,
                hide_index=True,
            )

    with right:
        st.markdown(
            '<div class="section-title">Latest Behavior Analysis</div>',
            unsafe_allow_html=True,
        )

        if behavior_logs.empty:
            st.info("No behavior analysis data.")
        else:
            st.dataframe(
                behavior_logs.head(8),
                use_container_width=True,
                hide_index=True,
            )

    st.markdown("---")

    st.markdown(
        '<div class="section-title">DNS Traffic Trend</div>',
        unsafe_allow_html=True,
    )

    if not dns_logs.empty and "timestamp" in dns_logs.columns:
        trend = dns_logs.copy()
        trend["timestamp"] = pd.to_datetime(
            trend["timestamp"],
            errors="coerce",
        )
        trend = trend.dropna(subset=["timestamp"])

        if not trend.empty:
            trend["Minute"] = trend["timestamp"].dt.floor("min")
            trend = (
                trend.groupby("Minute")
                .size()
                .reset_index(name="Requests")
            )

            fig3 = px.line(
                trend,
                x="Minute",
                y="Requests",
                markers=True,
            )

            st.plotly_chart(
                style_dark(fig3),
                use_container_width=True,
            )
        else:
            st.info("No valid timestamp data.")

    else:
        st.info("No DNS traffic data.")

    st.markdown("---")

    left, right = st.columns(2)

    with left:
        st.markdown(
            '<div class="section-title">Top Queried Domains</div>',
            unsafe_allow_html=True,
        )

        if not dns_logs.empty and "domain_name" in dns_logs.columns:
            domain = (
                dns_logs.groupby("domain_name")
                .size()
                .reset_index(name="Total")
                .sort_values("Total", ascending=False)
                .head(10)
            )

            fig4 = px.bar(
                domain,
                x="Total",
                y="domain_name",
                orientation="h",
                text="Total",
            )

            st.plotly_chart(
                style_dark(fig4),
                use_container_width=True,
            )

    with right:
        st.markdown(
            '<div class="section-title">Top Source IP</div>',
            unsafe_allow_html=True,
        )

        if not dns_logs.empty and "source_ip" in dns_logs.columns:
            ip = (
                dns_logs.groupby("source_ip")
                .size()
                .reset_index(name="Total")
                .sort_values("Total", ascending=False)
                .head(10)
            )

            fig5 = px.bar(
                ip,
                x="source_ip",
                y="Total",
                text="Total",
            )

            st.plotly_chart(
                style_dark(fig5),
                use_container_width=True,
            )

# ============================================================
# DNS LOGS
# ============================================================

elif page == "📄 DNS Logs":

    st.title("📄 DNS Logs")
    st.caption("Live DNS query monitoring and classification.")
    st.markdown("---")

    c1, c2, c3, c4 = st.columns(4)

    with c1:
        keyword = st.text_input(
            "🔍 Search Domain",
            placeholder="example.com",
        )

    with c2:
        query_types = (
            sorted(
                dns_logs["query_type"]
                .dropna()
                .astype(str)
                .unique()
                .tolist()
            )
            if "query_type" in dns_logs.columns
            else []
        )

        query_filter = st.selectbox(
            "Query Type",
            ["ALL"] + query_types,
        )

    with c3:
        class_filter = st.selectbox(
            "Classification",
            [
                "ALL",
                "SAFE",
                "SUSPICIOUS",
                "MALICIOUS",
                "UNKNOWN",
            ],
        )

    with c4:
        time_filter = st.selectbox(
            "Time Range",
            [
                "All Time",
                "Last 1 Hour",
                "Last 24 Hours",
                "Last 7 Days",
            ],
        )

    filtered = dns_logs.copy()

    if keyword and "domain_name" in filtered.columns:
        filtered = filtered[
            filtered["domain_name"]
            .astype(str)
            .str.contains(
                keyword,
                case=False,
                na=False,
            )
        ]

    if query_filter != "ALL" and "query_type" in filtered.columns:
        filtered = filtered[
            filtered["query_type"] == query_filter
        ]

    if class_filter != "ALL" and "classification" in filtered.columns:
        filtered = filtered[
            filtered["classification"] == class_filter
        ]

    if (
        time_filter != "All Time"
        and "timestamp" in filtered.columns
    ):
        now = datetime.now()
        windows = {
            "Last 1 Hour": timedelta(hours=1),
            "Last 24 Hours": timedelta(hours=24),
            "Last 7 Days": timedelta(days=7),
        }

        filtered = filtered[
            filtered["timestamp"]
            >= now - windows[time_filter]
        ]

    st.success(
        f"Showing {len(filtered):,} records"
    )

    if filtered.empty:
        st.info("No DNS records match the selected filters.")
    else:
        st.dataframe(
            filtered.style.apply(
                highlight_classification,
                axis=1,
            ),
            use_container_width=True,
            hide_index=True,
        )

    st.markdown("---")

    if not filtered.empty and "classification" in filtered.columns:
        summary = (
            filtered.groupby("classification")
            .size()
            .reset_index(name="Total")
        )

        fig = px.bar(
            summary,
            x="classification",
            y="Total",
            color="classification",
            text="Total",
        )

        st.plotly_chart(
            style_dark(fig),
            use_container_width=True,
        )

    csv = filtered.to_csv(index=False).encode("utf-8")

    st.download_button(
        "⬇ Download Filtered Logs",
        csv,
        "dns_logs.csv",
        "text/csv",
    )

# ============================================================
# BEHAVIOR ANALYSIS
# ============================================================

elif page == "📈 Behavior Analysis":

    st.title("📈 Behavioral Analysis")
    st.caption("DNS behavioral anomaly and risk analysis.")
    st.markdown("---")

    total_behavior = len(behavior_logs)
    high_risk = risk_count(behavior_logs, 80)
    medium_risk = risk_count(behavior_logs, 50, 80)
    low_risk = risk_count(behavior_logs, 0, 50)

    c1, c2, c3, c4 = st.columns(4)

    c1.metric("Total Analysis", total_behavior)
    c2.metric("🔴 High Risk", high_risk)
    c3.metric("🟡 Medium Risk", medium_risk)
    c4.metric("🟢 Low Risk", low_risk)

    st.markdown("---")

    if behavior_logs.empty:
        st.info("No behavior analysis data.")
    else:
        left, right = st.columns(2)

        with left:
            if "risk_score" in behavior_logs.columns:
                fig = px.histogram(
                    behavior_logs,
                    x="risk_score",
                    nbins=20,
                    color=(
                        "behavior_type"
                        if "behavior_type" in behavior_logs.columns
                        else None
                    ),
                )

                st.plotly_chart(
                    style_dark(fig),
                    use_container_width=True,
                )

        with right:
            if "behavior_type" in behavior_logs.columns:
                summary = (
                    behavior_logs.groupby("behavior_type")
                    .size()
                    .reset_index(name="Total")
                )

                fig2 = px.pie(
                    summary,
                    names="behavior_type",
                    values="Total",
                    hole=.5,
                )

                st.plotly_chart(
                    style_dark(fig2),
                    use_container_width=True,
                )

        st.markdown("---")
        st.subheader("🔥 High Risk Domains")

        if "risk_score" in behavior_logs.columns:
            scores = pd.to_numeric(
                behavior_logs["risk_score"],
                errors="coerce",
            ).fillna(0)

            high = behavior_logs[scores >= 80]

            if high.empty:
                st.success("No high-risk domains.")
            else:
                st.dataframe(
                    high,
                    use_container_width=True,
                    hide_index=True,
                )

        st.markdown("---")
        st.dataframe(
            behavior_logs,
            use_container_width=True,
            hide_index=True,
        )

        csv = behavior_logs.to_csv(index=False).encode("utf-8")

        st.download_button(
            "⬇ Download Behavior Report",
            csv,
            "behavior_report.csv",
            "text/csv",
        )

# ============================================================
# ALERTS
# ============================================================

elif page == "🚨 Alerts":

    st.title("🚨 Security Alert Center")
    st.caption("Centralized threat alerts and response status.")
    st.markdown("---")

    total_alert = len(alerts)
    malicious = classification_count(alerts, "MALICIOUS")
    suspicious = classification_count(alerts, "SUSPICIOUS")

    blocked = 0

    if not alerts.empty and "action" in alerts.columns:
        blocked = int(
            (
                alerts["action"]
                .astype(str)
                .str.upper()
                == "BLOCKED"
            ).sum()
        )

    c1, c2, c3, c4 = st.columns(4)

    c1.metric("Total Alerts", total_alert)
    c2.metric("🔴 Malicious", malicious)
    c3.metric("🟡 Suspicious", suspicious)
    c4.metric("🛡 Blocked", blocked)

    st.markdown("---")

    col1, col2 = st.columns(2)

    with col1:
        search = st.text_input(
            "🔍 Search Domain",
            placeholder="example.com",
        )

    with col2:
        time_filter = st.selectbox(
            "Time Range",
            [
                "All Time",
                "Last 1 Hour",
                "Last 24 Hours",
                "Last 7 Days",
            ],
            key="alert_time_filter",
        )

    alert_df = alerts.copy()

    if (
        search
        and "domain" in alert_df.columns
    ):
        alert_df = alert_df[
            alert_df["domain"]
            .astype(str)
            .str.contains(
                search,
                case=False,
                na=False,
            )
        ]

    if (
        time_filter != "All Time"
        and "alert_time" in alert_df.columns
    ):
        now = datetime.now()

        windows = {
            "Last 1 Hour": timedelta(hours=1),
            "Last 24 Hours": timedelta(hours=24),
            "Last 7 Days": timedelta(days=7),
        }

        alert_df = alert_df[
            alert_df["alert_time"]
            >= now - windows[time_filter]
        ]

    if alert_df.empty:
        st.success("No alerts found.")
    else:
        st.dataframe(
            alert_df.style.apply(
                highlight_classification,
                axis=1,
            ),
            use_container_width=True,
            hide_index=True,
        )

    st.markdown("---")

    if (
        not alert_df.empty
        and "classification" in alert_df.columns
    ):
        summary = (
            alert_df.groupby("classification")
            .size()
            .reset_index(name="Total")
        )

        fig = px.pie(
            summary,
            names="classification",
            values="Total",
            hole=.5,
        )

        st.plotly_chart(
            style_dark(fig),
            use_container_width=True,
        )

    csv = alert_df.to_csv(index=False).encode("utf-8")

    st.download_button(
        "⬇ Download Alerts",
        csv,
        "alerts.csv",
        "text/csv",
    )

# ============================================================
# DOMAIN CACHE
# ============================================================

elif page == "🌐 Domain Cache":

    st.title("🌐 Domain Cache")
    st.caption("Cached reputation results from the detection engine.")
    st.markdown("---")

    safe = classification_count(domain_cache, "SAFE")
    suspicious = classification_count(domain_cache, "SUSPICIOUS")
    malicious = classification_count(domain_cache, "MALICIOUS")

    c1, c2, c3 = st.columns(3)

    c1.metric("🟢 Safe", safe)
    c2.metric("🟡 Suspicious", suspicious)
    c3.metric("🔴 Malicious", malicious)

    st.markdown("---")

    keyword = st.text_input(
        "🔍 Search Cached Domain",
        placeholder="example.com",
    )

    cache = domain_cache.copy()

    if keyword and "domain" in cache.columns:
        cache = cache[
            cache["domain"]
            .astype(str)
            .str.contains(
                keyword,
                case=False,
                na=False,
            )
        ]

    if cache.empty:
        st.info("No cached domains found.")
    else:
        st.dataframe(
            cache.style.apply(
                highlight_classification,
                axis=1,
            ),
            use_container_width=True,
            hide_index=True,
        )

    st.markdown("---")

    if not cache.empty and "classification" in cache.columns:
        chart = (
            cache.groupby("classification")
            .size()
            .reset_index(name="Total")
        )

        fig = px.bar(
            chart,
            x="classification",
            y="Total",
            color="classification",
            text="Total",
        )

        st.plotly_chart(
            style_dark(fig),
            use_container_width=True,
        )

    csv = cache.to_csv(index=False).encode("utf-8")

    st.download_button(
        "⬇ Download Cache Report",
        csv,
        "domain_cache.csv",
        "text/csv",
    )

# ============================================================
# AI DETECTION
# ============================================================

elif page == "🤖 AI Detection":

    st.title("🤖 AI Detection")
    st.caption("Isolation Forest anomaly detection for DNS activity.")
    st.markdown("---")

    total_analyzed = len(ai_results)

    ai_flagged = 0
    avg_risk = 0

    if not ai_results.empty:
        if "prediction" in ai_results.columns:
            ai_flagged = int(
                (
                    ai_results["prediction"]
                    .astype(str)
                    .str.lower()
                    == "malicious"
                ).sum()
            )

        if "risk_score" in ai_results.columns:
            scores = pd.to_numeric(
                ai_results["risk_score"],
                errors="coerce",
            )

            if scores.notna().any():
                avg_risk = round(
                    float(scores.mean()),
                    1,
                )

    c1, c2, c3 = st.columns(3)

    c1.metric(
        "AI Domains Analyzed",
        total_analyzed,
    )

    c2.metric(
        "🤖 AI Flagged Malicious",
        ai_flagged,
    )

    c3.metric(
        "📊 Average Risk",
        f"{avg_risk}/100",
    )

    st.markdown("---")

    if ai_results.empty:
        st.info(
            "No AI results yet. Run detection_engine.py "
            "and process a SUSPICIOUS domain."
        )
    else:
        left, right = st.columns(2)

        with left:
            if "risk_score" in ai_results.columns:
                fig = px.histogram(
                    ai_results,
                    x="risk_score",
                    nbins=20,
                    color=(
                        "prediction"
                        if "prediction" in ai_results.columns
                        else None
                    ),
                )

                st.plotly_chart(
                    style_dark(fig),
                    use_container_width=True,
                )

        with right:
            if "prediction" in ai_results.columns:
                summary = (
                    ai_results.groupby("prediction")
                    .size()
                    .reset_index(name="Total")
                )

                fig2 = px.pie(
                    summary,
                    names="prediction",
                    values="Total",
                    hole=.5,
                )

                st.plotly_chart(
                    style_dark(fig2),
                    use_container_width=True,
                )

        st.markdown("---")
        st.subheader("📋 High-Risk AI Results")

        if "risk_score" in ai_results.columns:
            scores = pd.to_numeric(
                ai_results["risk_score"],
                errors="coerce",
            ).fillna(0)

            anomalies = ai_results[scores >= 75]

            if anomalies.empty:
                st.success("No high-risk AI anomalies.")
            else:
                st.dataframe(
                    anomalies,
                    use_container_width=True,
                    hide_index=True,
                )

        st.markdown("---")
        st.subheader("📄 All AI Results")

        st.dataframe(
            ai_results,
            use_container_width=True,
            hide_index=True,
        )

        csv = ai_results.to_csv(index=False).encode("utf-8")

        st.download_button(
            "⬇ Download AI Results",
            csv,
            "ai_results.csv",
            "text/csv",
        )

# ============================================================
# WHITELIST
# ============================================================

elif page == "🛡️ Whitelist":

    st.title("🛡️ Whitelist Management")
    st.caption(
        "Manage trusted domains that should always be allowed."
    )
    st.markdown("---")

    total_whitelist = len(whitelist)

    c1, c2 = st.columns(2)

    with c1:
        st.markdown(
            f"""
<div class="kpi-card kpi-blue">
    <div class="kpi-label">🛡️ TOTAL WHITELISTED DOMAINS</div>
    <div class="kpi-value">{total_whitelist:,}</div>
    <div class="kpi-desc">Trusted domains</div>
</div>
""",
            unsafe_allow_html=True,
        )

    with c2:
        st.markdown(
            """
<div class="kpi-card kpi-green">
    <div class="kpi-label">● STATUS</div>
    <div class="kpi-value" style="font-size:24px;">ACTIVE</div>
    <div class="kpi-desc">Whitelist enforcement enabled</div>
</div>
""",
            unsafe_allow_html=True,
        )

    st.markdown("---")

    st.subheader("➕ Add Domain to Whitelist")

    with st.form("add_whitelist_form", clear_on_submit=True):

        col1, col2 = st.columns([2, 1])

        with col1:
            domain_input = st.text_input(
                "Domain",
                placeholder="example.com",
            )

        with col2:
            added_by = st.text_input(
                "Added By",
                value="admin",
            )

        submitted = st.form_submit_button(
            "➕ Add to Whitelist",
            use_container_width=True,
        )

        if submitted:
            ok, message = add_whitelist(
                domain_input,
                added_by,
            )

            if ok:
                st.success(f"✓ {message}")
                st.cache_data.clear()
                st.rerun()
            else:
                st.error(f"✕ {message}")

    st.markdown("---")

    # [FIX BAHARU] Bundle Whitelist -- whitelist beberapa domain
    # berkaitan sekali gus (contoh: semua domain Microsoft/Google),
    # menggantikan cara lama (add satu-satu, taip label
    # "BUNDLE:<Nama>" secara manual dalam "Added By").
    st.subheader("📦 Add Whitelist Bundle")
    st.caption(
        "Add a group of related trusted domains at once "
        "(e.g. all Microsoft or Grammarly domains) instead of adding them one by one."
    )

    bundle_col1, bundle_col2 = st.columns([2, 1])

    with bundle_col1:
        bundle_choice = st.selectbox(
            "Select Bundle",
            list(WHITELIST_BUNDLES.keys()),
        )

    with bundle_col2:
        bundle_added_by = st.text_input(
            "Added By",
            value="admin",
            key="bundle_added_by",
        )

    st.caption(
        "Domains included: "
        + ", ".join(WHITELIST_BUNDLES[bundle_choice])
    )

    add_bundle_clicked = st.button(
        f"📦 Add '{bundle_choice}' Bundle to Whitelist",
        use_container_width=True,
    )

    if add_bundle_clicked:
        bundle_domains = WHITELIST_BUNDLES[bundle_choice]
        bundle_by = str(bundle_added_by or "admin").strip() or "admin"
        bundle_label = f"BUNDLE:{bundle_choice} ({bundle_by})"

        results = []

        for bd in bundle_domains:
            ok, message = add_whitelist(bd, bundle_label)
            results.append((bd, ok, message))

        success_count = sum(1 for _, ok, _ in results if ok)

        st.success(
            f"✓ {success_count}/{len(results)} domains in bundle "
            f"'{bundle_choice}' added to whitelist."
        )

        with st.expander("View details per domain"):
            for bd, ok, message in results:
                if ok:
                    st.write(f"✅ {bd} — {message}")
                else:
                    st.write(f"❌ {bd} — {message}")

        st.cache_data.clear()
        st.rerun()

    st.markdown("---")

    st.subheader("📋 Current Whitelist")

    if whitelist.empty:
        st.info("No whitelisted domains.")
    else:
        display_whitelist = whitelist.copy()

        st.dataframe(
            display_whitelist,
            use_container_width=True,
            hide_index=True,
        )

    st.markdown("---")

    st.subheader("🗑 Remove Domain from Whitelist")

    if whitelist.empty:
        st.info("There are no domains available to remove.")
    else:
        remove_domain = st.selectbox(
            "Select Domain",
            whitelist["domain"].astype(str).tolist(),
        )

        confirm_remove = st.checkbox(
            "I confirm that I want to remove this domain.",
        )

        if st.button(
            "🗑 Remove Selected Domain",
            use_container_width=True,
        ):

            if not confirm_remove:
                st.warning(
                    "Please confirm the removal first."
                )
            else:
                ok, message = remove_whitelist(
                    remove_domain
                )

                if ok:
                    st.success(f"✓ {message}")
                    st.cache_data.clear()
                    st.rerun()
                else:
                    st.error(f"✕ {message}")

# ============================================================
# FOOTER
# ============================================================

st.markdown(
    """
<div style="
    text-align:center;
    color:#475569;
    font-size:10px;
    padding:25px 0 5px 0;
">
    Dynamic DNS-Based Threat Prevention System
    • Pi-hole • Threat Intelligence • Behavioral Analysis • AI
</div>
""",
    unsafe_allow_html=True,
)
