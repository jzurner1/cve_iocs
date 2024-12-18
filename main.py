import kev_interaction
import otx_interaction
import db_interaction
import csv


def add_all_kev_to_cve_db():  # done
    """ add all CVEs from the official KEV document to the CVE database

    :return: list of CVE IDs, just for fun
    """
    kev_json = kev_interaction.get_kev_json()
    cve_ids = []
    for kev in kev_json['vulnerabilities']:
        cve_ids.append(kev['cveID'])
        db_interaction.add_cve_to_db(kev)
    return list(set(cve_ids))


def add_all_pulse_ioc_to_db(cve_id_list):  # done
    """ add all IOCs from a list of CVEs based on OTX Pulses

    :param cve_id_list: list of CVE IDs
    :return: 0 if error, otherwise 1
    """
    iocs = []


    for cve_id in cve_id_list:
        cve_json = otx_interaction.otx_get_cve_info(cve_id)
        if isinstance(cve_json, int):  # error within otx_get_cve_info(), typically invalid response from server
            return 0
        pulse_ids = otx_interaction.otx_get_pulse_ids(cve_json)
        pulse_iocs = otx_interaction.otx_get_iocs_from_pulse_ids(pulse_ids, cve_id)

        count = 0

        for ioc in pulse_iocs:
            db_interaction.add_ioc_to_db(ioc)
            count += 1


        print(f"[+] finished {cve_id}, total of {str(count)} IOCs found")
    return 1


def update_all_cves_and_iocs():
    """ update KEV database and IOC database from all KEVs

    :return: nothing
    """
    cve_ids = []

    kevj = kev_interaction.get_kev_json()['vulnerabilities']
    for k in kevj:
        cve_ids.append(k['cveID'])

    # cve_ids = add_all_kev_to_cve_db()
    add_all_pulse_ioc_to_db(cve_ids)


def get_user_choice(query, choices):
    """ get user input on a query

    :param query: query to ask
    :param choices: list of valid choices
    :return: user's response as a string; one of choices
    """

    # print query and choices
    print(query)
    for i, choice in enumerate(choices, start=1):
        print(f"{i}. {choice}")

    user_input = input("> ").strip()

    # if number was entered, make sure its valid, then return it
    if user_input.isdigit():
        choice_index = int(user_input) - 1
        if 0 <= choice_index < len(choices):
            return choices[choice_index]

    # otherwise check if string was entered, make sure its valid, then return it
    lower_choices = [choice.lower() for choice in choices]
    if user_input.lower() in lower_choices:
        return choices[lower_choices.index(user_input.lower())]

    # invalid input
    print(f"[-] invalid choice - please choose one of the listed options.")
    return get_user_choice(query, choices)


def get_main_action_choice():
    """ main menu

    :return: nothing
    """
    c1 = get_user_choice("Choose an action:", [
        "Update KEV database - add new KEVs",
        "Update IOC database - single CVE",
        "Create file - all KEVs (json)",
        "Create file - all IOCs for CVE (csv)",
        "Update KEV and IOC database - all KEVs and IOCs"
    ])

    if c1 == "Update KEV database - add new KEVs":
        add_all_kev_to_cve_db()
        print("[+] done, added KEV to database")
        print('')  # newline
        get_main_action_choice()

    elif c1 == "Update IOC database - single CVE":
        cve_id = input("Enter a CVE ID in standard format such as CVE-2021-41277: ")
        add_all_pulse_ioc_to_db([cve_id])
        print('')  # newline
        get_main_action_choice()

    elif c1 == "Create file - all KEVs (json)":
        js = kev_interaction.get_kev_json()
        f = open("KEV.json", "w", encoding='utf8')
        f.write(str(js))
        f.close()

        print("[+] created file KEV.json\n")
        get_main_action_choice()

    elif c1 == "Create file - all IOCs for CVE (csv)":
        cve_id = input("Enter a CVE ID in standard format such as CVE-2021-41277: ")
        data = db_interaction.retrieve_cve_iocs_from_db(cve_id)
        if data:
            keys = data[0].keys()

            filename = cve_id + ".csv"

            with open(filename, mode='w', newline='', encoding='utf8') as file:
                writer = csv.DictWriter(file, fieldnames=keys)
                writer.writeheader()
                writer.writerows(data)

            print(f'[+] CSV file {filename} created\n')
        else:
            print(f'[-] no data found, file creation failed\n')
        get_main_action_choice()

    elif c1 == "Update KEV and IOC database - all KEVs and IOCs":
        if get_user_choice("Warning: This is slow! Are you sure?", ["Y", "N"]) != "Y":
            print("Aborting...\n")
            get_main_action_choice()

        update_all_cves_and_iocs()





if __name__ == "__main__":
    get_main_action_choice()

