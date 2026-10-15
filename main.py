"""
main.py
Dynamic DNS-Based Threat Prevention System

Purpose:
- Start all project modules
- Keep all modules running together
- Stop all modules safely with Ctrl+C

Fixed version — perubahan berbanding versi asal:
  1. Semakan root/sudo sebelum start (DNS Monitor perlukan raw socket access)
  2. Elak spam [WARNING] tanpa henti bila modul mati (guna flag "reported")
  3. Buang blok except KeyboardInterrupt yang tak akan tercapai (signal handler
     sudah uruskan SIGINT)
  4. Tambah process.wait() selepas kill() untuk elak zombie process
  5. Guna sys.executable dan bukan "python3" supaya cross-platform
  6. Semak fail modul wujud sebelum cuba start
  7. Setiap modul log ke fail berasingan dalam folder logs/ supaya output
     tak bercampur
  8. [BAHARU] Buang "AI Engine" daripada MODULES -- ai_engine.py tiada
     main()/loop sendiri (reka bentuk terkini: detection_engine.py panggil
     ai_engine.predict() TERUS bila perlu, bukan sebagai proses
     berasingan). Menjalankannya sebagai proses standalone akan sentiasa
     "exit code 0" serta-merta selepas load model -- bukan error, tapi
     memang tak perlu lagi dijalankan macam tu.
  9. [BAHARU] Dashboard kini dilancar guna
     [PYTHON, "-m", "streamlit", "run", ...] dan bukan ["streamlit", ...].
     Command "streamlit" bergantung pada PATH, dan bawah sudo, PATH tak
     merangkumi venv/bin (punca "[Errno 2] No such file or directory:
     'streamlit'"). "python -m streamlit" guna PYTHON (sys.executable)
     terus -- python venv yang sama, streamlit sebagai module Python,
     tak bergantung langsung pada PATH.
"""

import os
import subprocess
import sys
import threading
import time
import signal


# ============================================================
# CONFIGURATION
# ============================================================

PYTHON = sys.executable  # (5) guna interpreter semasa, bukan hardcode "python3"

LOG_DIR = "logs"

MODULES = [
    ("DNS Monitor", [PYTHON, "dns_monitor.py"]),
    ("Detection Engine", [PYTHON, "detector_engine.py"]),
    ("Behavior Analysis", [PYTHON, "behavior_analysis.py"]),
    # (8) "AI Engine" DIBUANG daripada sini -- ai_engine.py tiada main()
    # sendiri, dipanggil terus oleh detection_engine.py bila perlu.
    (
        "Dashboard",
        [
            PYTHON,
            "-m",
            "streamlit",
            "run",
            "dashboard.py",
            "--server.address=0.0.0.0",
            "--server.port=8501",
        ],
    ),
]


# ============================================================
# GLOBAL PROCESS LIST
# ============================================================

processes = []


def get_local_ip():
    """
    [BAHARU] Dapatkan IP LAN sebenar mesin ni secara automatik, supaya
    mesej "Dashboard: http://..." papar IP sebenar -- bukan placeholder
    text "<UBUNTU-IP>" yang sebelum ini tak pernah digantikan.

    Guna teknik "connect" UDP ke alamat luar (tak benar-benar hantar
    apa-apa data) sekadar untuk tanya OS "kalau nak hubungi alamat ni,
    IP local mana yang OS akan guna" -- cara standard untuk dapatkan
    IP LAN tanpa perlu parse output 'ip addr'/'hostname -I' yang
    berbeza-beza format antara OS.
    """

    import socket

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
        finally:
            s.close()
    except Exception:
        return "<IP-SERVER>"


# ============================================================
# (1) ROOT / PRIVILEGE CHECK
# ============================================================

def require_root():
    """
    DNS Monitor guna pyshark.LiveCapture yang perlukan hak root untuk
    raw socket. Kalau main.py tak dijalankan dengan sudo, modul itu akan
    start lalu mati senyap dalam beberapa saat.

    [FIX] Sebelum ini, fungsi ni cuma print mesej error dan sys.exit(1)
    -- user perlu taip semula "sudo $(which python3) main.py" secara
    manual setiap kali. Kini, kalau bukan root, main.py AUTOMATIK
    jalankan semula dirinya sendiri dengan sudo (guna PYTHON =
    sys.executable, iaitu Python venv yang SAMA yang sedang menjalankan
    skrip ni sekarang -- bukan Python sistem) melalui os.execvp().
    Ini bermakna user cuma perlu taip:

        python3 main.py

    dan skrip akan automatik "naik taraf" kepada:

        sudo <venv>/bin/python3 main.py

    di sebalik tabir -- sama seperti kalau ditaip manual, cuma tak
    perlu diingati/ditaip setiap kali. Terminal akan tetap minta
    password sudo (ini keperluan keselamatan OS, tak boleh dielak),
    tapi command yang perlu DITAIP oleh user kekal ringkas.
    """

    if os.name == "nt":
        # Windows: semakan admin lebih rumit — beri amaran sahaja
        try:
            import ctypes
            is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
        except Exception:
            is_admin = False

        if not is_admin:
            print(
                "[WARNING] Skrip ini mungkin perlukan hak Administrator "
                "untuk DNS capture (pyshark)."
            )
        return

    # Linux / macOS
    if hasattr(os, "geteuid") and os.geteuid() != 0:
        print(
            "[INFO] main.py perlukan akses root untuk DNS capture -- "
            "naik taraf automatik dengan sudo..."
        )
        try:
            os.execvp("sudo", ["sudo", PYTHON, os.path.abspath(__file__)] + sys.argv[1:])
        except Exception as e:
            # Fallback kalau os.execvp gagal (contoh 'sudo' tak dijumpai)
            print(f"[ERROR] Gagal naik taraf automatik dengan sudo: {e}")
            print("[ERROR] Sila jalankan main.py dengan sudo secara manual:")
            print(f"        sudo {PYTHON} {os.path.abspath(__file__)}")
            sys.exit(1)


# ============================================================
# (6) SEMAK FAIL MODUL WUJUD SEBELUM START
# ============================================================

def module_file_exists(command):
    """
    Semak sama ada fail .py yang dirujuk dalam command wujud.
    Modul seperti Dashboard (streamlit) juga disemak melalui fail
    dashboard.py yang dirujuk dalam argumennya.
    """

    for part in command:
        if part.endswith(".py"):
            return os.path.isfile(part)

    # Command tanpa fail .py (contoh binari luar) — anggap OK, biar
    # subprocess.Popen sendiri yang lapor jika tak wujud
    return True


# ============================================================
# START MODULE
# ============================================================

def stream_output(name, process, log_file):
    """
    [BAHARU] Thread latar yang baca output proses baris demi baris, dan
    tulis ke DUA tempat serentak:
      1. Fail log (logs/xxx.log) -- macam sebelum ini, untuk rujukan/
         debug kemudian
      2. Terminal utama, dengan label nama modul di depan (contoh
         "[DNS Monitor] ...") -- supaya output SEMUA modul boleh
         nampak dalam SATU terminal sahaja, tanpa perlu buka terminal
         kedua untuk `tail -f`.

    Setiap modul dapat thread sendiri, jadi 4 modul boleh "cakap"
    serentak tanpa saling menyekat (blocking) antara satu sama lain.
    """

    try:
        for line in process.stdout:
            log_file.write(line)
            log_file.flush()
            # Label nama modul di depan setiap baris supaya senang
            # dibezakan bila banyak modul "bercakap" serentak dalam
            # satu terminal.
            print(f"[{name}] {line}", end="")

    except Exception:
        pass

    finally:
        try:
            log_file.close()
        except Exception:
            pass


def start_module(name, command):

    print(f"[+] Starting {name}...")

    if not module_file_exists(command):
        print(f"[ERROR] Failed to start {name}: fail modul tidak dijumpai.")
        return None

    try:
        os.makedirs(LOG_DIR, exist_ok=True)
        log_path = os.path.join(
            LOG_DIR, f"{name.replace(' ', '_').lower()}.log"
        )
        # buffering=1 = line-buffered -- setiap baris ditulis ke fail
        # SERTA-MERTA, bukan tunggu buffer penuh.
        log_file = open(log_path, "w", buffering=1)

        # PYTHONUNBUFFERED=1 -- paksa Python child process itu sendiri
        # (contoh detection_engine.py) tulis stdout tanpa buffer
        # sepenuhnya, supaya thread stream_output() di atas terima
        # baris baharu SERTA-MERTA (bukan tertahan dalam buffer child
        # process).
        child_env = os.environ.copy()
        child_env["PYTHONUNBUFFERED"] = "1"

        # (BAHARU) stdout=subprocess.PIPE (bukan terus ke log_file)
        # supaya main.py boleh BACA output tu sendiri dan "tee"-kan
        # ke fail log SERTA terminal serentak, melalui thread
        # stream_output() di atas.
        process = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            env=child_env,
            text=True,
            bufsize=1,
        )

        reader_thread = threading.Thread(
            target=stream_output,
            args=(name, process, log_file),
            daemon=True,
        )
        reader_thread.start()

        processes.append(
            {
                "name": name,
                "process": process,
                "log_file": log_file,
                "reader_thread": reader_thread,
                "reported": False,  # (2) elak spam warning berulang
            }
        )

        print(
            f"[OK] {name} started "
            f"(PID: {process.pid}, log: {log_path})"
        )

        return process

    except Exception as e:

        print(
            f"[ERROR] Failed to start "
            f"{name}: {e}"
        )

        return None


# ============================================================
# STOP ALL MODULES
# ============================================================

def stop_all():

    print("\n")
    print("==============================")
    print(" STOPPING DNS THREAT SYSTEM ")
    print("==============================")


    # Stop in reverse order
    for item in reversed(processes):

        name = item["name"]
        process = item["process"]

        if process.poll() is None:

            print(
                f"[-] Stopping {name}..."
            )

            try:

                process.terminate()

                process.wait(
                    timeout=5
                )

                print(
                    f"[OK] {name} stopped"
                )

            except subprocess.TimeoutExpired:

                print(
                    f"[!] {name} did not stop. "
                    f"Force killing..."
                )

                process.kill()

                try:
                    process.wait(timeout=3)  # (4) elak zombie process
                except subprocess.TimeoutExpired:
                    print(f"[ERROR] {name}: gagal ditutup walaupun selepas kill().")

            except Exception as e:

                print(
                    f"[ERROR] "
                    f"{name}: {e}"
                )

        # Tutup fail log
        log_file = item.get("log_file")
        if log_file and not log_file.closed:
            log_file.close()


    print("\n[SYSTEM STOPPED]")
    print("==============================")


# ============================================================
# SIGNAL HANDLER
# ============================================================

def signal_handler(
    signum,
    frame
):

    stop_all()

    sys.exit(0)


signal.signal(
    signal.SIGINT,
    signal_handler
)

signal.signal(
    signal.SIGTERM,
    signal_handler
)


# ============================================================
# MAIN
# ============================================================

def main():

    require_root()  # (1)

    print()
    print("==============================")
    print(" DNS THREAT DETECTION SYSTEM ")
    print("==============================")
    print()


    # --------------------------------------------------------
    # Start modules one by one
    # --------------------------------------------------------

    for name, command in MODULES:

        process = start_module(
            name,
            command
        )

        if process is None:

            print(
                f"\n[WARNING] "
                f"{name} could not start."
            )

            continue

        # Give module some time to initialize
        time.sleep(3)


    # --------------------------------------------------------
    # System status
    # --------------------------------------------------------

    print()
    print("==============================")
    print("       SYSTEM RUNNING        ")
    print("==============================")

    for item in processes:

        name = item["name"]
        process = item["process"]

        print(
            f"[RUNNING] "
            f"{name} "
            f"(PID: {process.pid})"
        )


    print()
    print(
        "[INFO] Dashboard:"
    )

    print(f"http://{get_local_ip()}:8501")

    print()
    print(f"[INFO] Log setiap modul disimpan dalam folder '{LOG_DIR}/'")
    print(
        "[INFO] Press CTRL+C to stop "
        "all modules."
    )

    print()


    # --------------------------------------------------------
    # Keep system alive
    # --------------------------------------------------------

    # Note: KeyboardInterrupt tak akan sampai ke sini kerana signal_handler
    # (didaftarkan di atas untuk SIGINT) akan panggil stop_all() dan
    # sys.exit(0) terus. Loop ni cuma perlu tangani "modul mati sendiri".
    while True:

        time.sleep(2)

        # Check whether any process died — (2) lapor SEKALI sahaja
        for item in processes:

            name = item["name"]
            process = item["process"]

            if process.poll() is not None and not item["reported"]:

                print(
                    f"[WARNING] "
                    f"{name} stopped "
                    f"(exit code: "
                    f"{process.returncode}) — semak logs/{name.replace(' ', '_').lower()}.log"
                )

                item["reported"] = True


# ============================================================
# ENTRY POINT
# ============================================================

if __name__ == "__main__":

    main()
