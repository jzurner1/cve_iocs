import requests
import json


def get_kev_json():
    """ get raw KEV from CISA

    :return: raw json
    """
    try:
        kev_raw = requests.get("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json")
    except requests.exceptions.ConnectTimeout:
        print('[-] connection failure in get_kev_json()\n')
        return 1
    except requests.exceptions.ConnectionError:
        print('[-] connection failure in get_kev_json()\n')
        return 1

    try:
        return kev_raw.json()
    except json.decoder.JSONDecodeError:
        print("[-] failed to decode KEV JSON data")
        return 1

