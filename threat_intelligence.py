import requests
import os
import time
from urllib.parse import urlparse
from dotenv import load_dotenv     

load_dotenv()   

# ==============================
# CONFIGURATION
# ==============================

OPENPHISH_URL = "https://openphish.com/feed.txt"
CACHE_FILE = "openphish_cache.txt"

# Refresh OpenPhish setiap 24 jam
CACHE_TIME = 86400

THREATFOX_AUTH_KEY = os.getenv("THREATFOX_AUTH_KEY")


# ==============================
# UPDATE OPENPHISH CACHE
# ==============================

def update_openphish_cache():

    try:
        response = requests.get(
            OPENPHISH_URL,
            timeout=10
        )

        response.raise_for_status()

        with open(CACHE_FILE, "w") as file:
            file.write(response.text)

        print("[+] OpenPhish cache updated")

        return True


    except Exception as e:

        print("[!] OpenPhish update error:", e)

        return False



# ==============================
# EXTRACT HOSTNAME
# ==============================

def _extract_hostname(url_str):

    try:

        url_str = url_str.strip().lower()


        # Tambah protocol jika URL tiada http/https
        if not url_str.startswith(("http://", "https://")):
            url_str = "http://" + url_str


        host = urlparse(url_str).hostname


        if host:

            # Buang www supaya matching lebih tepat
            if host.startswith("www."):
                host = host[4:]


            return host.lower()


        return None


    except Exception:

        return None



# ==============================
# CHECK OPENPHISH
# ==============================

def check_openphish(domain):

    domain = domain.strip().lower()


    # Buang www pada domain input
    if domain.startswith("www."):
        domain = domain[4:]


    try:

        cache_is_fresh = False


        if os.path.exists(CACHE_FILE):

            age = time.time() - os.path.getmtime(CACHE_FILE)

            if age < CACHE_TIME:
                cache_is_fresh = True



        if not cache_is_fresh:

            update_openphish_cache()



        if not os.path.exists(CACHE_FILE):

            return {
                "classification": "SAFE",
                "matched_source": None
            }



        with open(CACHE_FILE, "r") as file:

            feed = file.readlines()



        for item in feed:


            host = _extract_hostname(item)



            if host:


                if host == domain or domain.endswith("." + host):

                    return {

                        "classification": "MALICIOUS",
                        "matched_source": "OpenPhish"

                    }



        return {

            "classification": "SAFE",
            "matched_source": None

        }



    except Exception as e:


        print("[!] OpenPhish Error:", e)


        return {

            "classification": "UNKNOWN",
            "matched_source": None

        }




# ==============================
# CHECK THREATFOX
# ==============================

def check_threatfox(domain):

    domain = domain.strip().lower()


    try:


        url = "https://threatfox-api.abuse.ch/api/v1/"


        payload = {

            "query": "search_ioc",
            "search_term": domain,
            "exact_match": True

        }


        headers = {

            "Auth-Key": THREATFOX_AUTH_KEY,
            "Content-Type": "application/json"

        }



        response = requests.post(

            url,
            json=payload,
            headers=headers,
            timeout=10

        )


        response.raise_for_status()


        data = response.json()



        if (

            data.get("query_status") == "ok"

            and data.get("data")

        ):


            return {

                "classification": "MALICIOUS",
                "matched_source": "ThreatFox"

            }



        return {

            "classification": "SAFE",
            "matched_source": None

        }



    except Exception as e:


        print("[!] ThreatFox Error:", e)


        return {

            "classification": "SAFE",
            "matched_source": None

        }




# ==============================
# MAIN THREAT CHECK FUNCTION
# ==============================

def threat_check(domain):


    if not domain:

        return {

            "classification": "SAFE",
            "matched_source": None

        }



    # 1. Check OpenPhish

    openphish_result = check_openphish(domain)



    if openphish_result["classification"] == "MALICIOUS":

        return openphish_result



    openphish_status = openphish_result["classification"]



    # 2. Check ThreatFox

    threatfox_result = check_threatfox(domain)



    if threatfox_result["classification"] == "MALICIOUS":

        return threatfox_result



    threatfox_status = threatfox_result["classification"]



    # Jika mana-mana TI gagal

    if (

        openphish_status == "UNKNOWN"

        or threatfox_status == "UNKNOWN"

    ):

        return {

            "classification": "SAFE",
            "matched_source": None

        }



    return {

        "classification": "SAFE",
        "matched_source": None

    }




# ==============================
# TEST
# ==============================

if __name__ == "__main__":


    test_domain = "google.com"


    result = threat_check(test_domain)


    print(result)
