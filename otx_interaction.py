import requests
import time


def otx_get_cve_info(cve_id):  # done
    """ get raw json about a CVE from OTX

    :param cve_id: cve identifier
    :return: raw json
    """
    otx_api_key = ""  # insert your own
    headers = {"X-OTX-API-KEY": otx_api_key}
    endpoint = f"https://otx.alienvault.com/api/v1/indicators/cve/{cve_id}"

    resp = requests.get(endpoint, headers=headers)

    if resp.status_code == 404:
        print(f"[-] invalid CVE ID '{cve_id}'")
        return 0

    if resp.status_code != 200:
        print(f"[-] failed to retrieve OTX CVE indicator!\nResponse code: {str(resp.status_code)}\nDomain requested: {endpoint}")
        return 0
    if "detail" in resp.json().keys():
        print(f"[-] error from OTX: {resp.json()['detail']}")
        return 0

    return resp.json()


def otx_get_pulse_ids(cve_json, pulse_limit=10):  # done
    """ get a list of pulse ids from OTX

    :param cve_json: json from otx_get_cve_info()
    :param pulse_limit: max number of pulses to retrieve
    :return: list of pulse ids
    """
    pulse_ids = []

    if cve_json['pulse_info']['count'] == 0:  # no pulses
        return []

    cve_id = cve_json['base_indicator']['indicator']

    for pulse in cve_json['pulse_info']['pulses']:
        pulse_ids.append(pulse['id'])

    pulse_ids = pulse_ids[:pulse_limit]
    return pulse_ids


def otx_get_iocs_from_pulse_ids(pulse_ids, cve_id):  # done
    """ get list of iocs from a list of pulse ids

    :param pulse_ids: list of pulse ids from otx_get_pulse_ids()
    :param cve_id: cve that pulses are linked to
    :return: list of iocs
    """
    otx_api_key = ""  # insert your own
    pulses_raw = []
    indicators = []

    for pulse_id in pulse_ids:
        headers = {"X-OTX-API-KEY": otx_api_key}
        endpoint = f"https://otx.alienvault.com/api/v1/pulses/{pulse_id}"

        resp = requests.get(endpoint, headers=headers)
        try:
            pulses_raw.append(resp.json())
        except:
            continue

    for pulse in pulses_raw:
        for indicator in pulse['indicators']:
            if indicator['type'] != 'CVE':
                # cve_id, ioc_type, ioc_value, indicator_id
                ic = {
                    "cve_id": cve_id,
                    "ioc_type": indicator["type"],
                    "ioc_value": indicator["indicator"],
                    "indicator_id": indicator["id"]
                }
                indicators.append(ic)

    return indicators

