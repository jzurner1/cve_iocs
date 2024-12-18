import requests


def get_kev_json():  # done
    kev_raw = requests.get("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json")
    try:
        return kev_raw.json()
    except json.decoder.JSONDecodeError:
        print("[-] failed to decode KEV JSON data")
        return 0

