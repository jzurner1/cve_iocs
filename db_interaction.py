import mysql.connector

mydb = mysql.connector.connect(  # insert your own
    host="",
    user="",
    password="",
    database=""
)


def set_up_db():
    """ set up the database

    :return: nothing
    """
    mycursor = mydb.cursor()
    mycursor.execute("USE ttps;")
    mycursor.execute("CREATE TABLE known_exploited(id INT AUTO_INCREMENT, cve_id VARCHAR(100), vendor VARCHAR(100), product VARCHAR(100), vuln_name VARCHAR(255), campaign_use boolean, notes text, PRIMARY KEY(id));")
    mycursor.execute("CREATE TABLE cve_iocs(id INT AUTO_INCREMENT, cve_id VARCHAR(100), ioc_type VARCHAR(100), ioc_value VARCHAR(255), indicator_id VARCHAR(20), PRIMARY KEY(id));")


def check_if_cve_in_db(cve_id):
    """ check if a specific CVE ID is already in known_exploited database

    :param cve_id: cve identifier like 'CVE-2024-55956'
    :return: boolean
    """
    mycursor = mydb.cursor()
    q = "SELECT * FROM known_exploited WHERE cve_id = %s"
    mycursor.execute(q, (clean_value(cve_id),))
    res = mycursor.fetchall()

    if not res:
        return False
    else:
        return True


def check_if_ioc_in_db(indicator_id, cve_id):
    """ check if IOC is already in cve_iocs database

    :param indicator_id: indicator ID used by Pulse, such as '4003607808'
    :param cve_id: cve identifier like 'CVE-2024-55956'
    :return: boolean
    """
    mycursor = mydb.cursor()
    q = f"SELECT * FROM cve_iocs WHERE indicator_id = \"{clean_value(indicator_id)}\" AND cve_id = \"{clean_value(cve_id)}\";"
    mycursor.execute(q)
    res = mycursor.fetchall()

    if not res:
        return False
    else:
        return True


def clean_value(val):
    """ crummy sanitization function to "prevent" sql injection

    :param val: value to sanitize
    :return: sanitized value
    """
    if isinstance(val, str):
        val = val.replace("'", "").replace('"', '').replace(';', '').replace('\\', '')
    return val


def retrieve_cve_data_from_db(cve_id):
    """ get info about a CVE from known_exploited database

    :param cve_id: cve identifier like 'CVE-2024-55956'
    :return: dict of cve information
    """
    mycursor = mydb.cursor()
    q = "SELECT * FROM known_exploited WHERE cve_id = %s"
    mycursor.execute(q, (clean_value(cve_id),))
    res = mycursor.fetchone()
    if not res:
        print(f"[-] {cve_id} not found in DB")
        return 0
    res = list(res)
    dc = {
        "id": res[0],
        "cve_id": res[1],
        "vendor": res[2],
        "product": res[3],
        "vuln_name": res[4],
        "campaign_use": res[5],
        "notes": res[6]
    }

    return dc


def retrieve_ioc_data_from_db(indicator_id):
    """ get ioc data from the cve_iocs database
    
    :param indicator_id: indicator ID used by Pulse, such as '4003607808'
    :return: dict of ioc information
    """
    mycursor = mydb.cursor()
    q = "SELECT * FROM cve_iocs WHERE indicator_id = %s"
    mycursor.execute(q, (clean_value(indicator_id),))
    res = mycursor.fetchone()
    if not res:
        print(f"[-] {indicator_id} not found in DB")
        return 0
    res = list(res)
    dc = {
        "id": res[0],
        "cve_id": res[1],
        "ioc_type": res[2],
        "ioc_value": res[3],
        "indicator_id": res[4]
    }

    return dc


def retrieve_cve_iocs_from_db(cve_id):
    """ get iocs from the cve_iocs database given a cve_id

    :param cve_id: cve identifier like 'CVE-2024-55956'
    :return: dict of ioc information
    """
    mycursor = mydb.cursor()
    q = "SELECT * FROM cve_iocs WHERE cve_id = %s"
    mycursor.execute(q, (clean_value(cve_id),))
    res = mycursor.fetchall()
    if not res:
        print(f"[-] {cve_id} not found in DB")
        return 0

    iocs = []

    for i in list(res):
        dc = {
            "id": i[0],
            "cve_id": i[1],
            "ioc_type": i[2],
            "ioc_value": i[3],
            "indicator_id": i[4]
        }
        iocs.append(dc)

    return iocs


def get_all_kevs_from_db():
    """ get all known exploited vulns from known_exploited db

    :return: dict of cve information
    """
    mycursor = mydb.cursor()
    q = "SELECT * FROM known_exploited"
    mycursor.execute(q)
    res = mycursor.fetchall()
    kevs = []

    for i in res:
        i = list(i)
        dc = {
            "id": i[0],
            "cve_id": i[1],
            "vendor": i[2],
            "product": i[3],
            "vuln_name": i[4],
            "campaign_use": i[5],
            "notes": i[6]
        }
        kevs.append(dc)

    return kevs


def add_cve_to_db(cve_info):
    """ add a single cve to the known_exploited db

    :param cve_info: dict about a singular cve
    :return: 1 if successful, 0 if not
    """
    # known_exploited: id, cve_id, vendor, product, vuln_name, campaign_use, notes
    mycursor = mydb.cursor()
    if check_if_cve_in_db(cve_info['cveID']):
        return 1

    known_use = 0
    if cve_info['knownRansomwareCampaignUse'] == "Known":
        known_use = 1

    cve_id = clean_value(cve_info['cveID'])
    vendor = clean_value(cve_info['vendorProject'][:100])
    product = clean_value(cve_info['product'][:100])
    vuln_name = clean_value(cve_info['vulnerabilityName'][:100])
    notes = clean_value(cve_info['notes'][:255])

    fields = "cve_id, vendor, product, vuln_name, campaign_use, notes"
    values = f"\"{cve_id}\", \"{vendor}\", \"{product}\"," \
             f"\"{vuln_name}\", {str(known_use)}, \"{notes}\""

    q = f"INSERT INTO known_exploited ({fields}) VALUES ({values});"

    try:
        mycursor.execute(q)
        mydb.commit()
        return 1
    except mysql.connector.errors.ProgrammingError as e:
        print(f"[-] Error in query syntax - are the data types correct? {q}\n{e}")
        return 0


def add_ioc_to_db(ioc):
    """ add an ioc to cve_iocs db

    :param ioc: dict of singular ioc information
    :return: 1 if successful, 0 if not
    """
    # cve_iocs: id, cve_id, ioc_type, ioc_value, indicator_id
    if check_if_ioc_in_db(ioc['indicator_id'], ioc['cve_id']):
        return 1
    mycursor = mydb.cursor()

    cve_id = clean_value(ioc['cve_id'])
    ioc_type = clean_value(ioc['ioc_type'][:100])
    ioc_value = clean_value(ioc['ioc_value'][:255])
    indicator_id = clean_value(ioc['indicator_id'])

    fields = "cve_id, ioc_type, ioc_value, indicator_id"
    values = f"\"{cve_id}\", \"{ioc_type}\", \"{ioc_value}\", \"{indicator_id}\""

    q = f"INSERT INTO cve_iocs ({fields}) VALUES ({values});"

    try:
        mycursor.execute(q)
        mydb.commit()
        return 1
    except mysql.connector.errors.ProgrammingError as e:
        print(f"[-] Error in query syntax - are the data types correct? {q}\n{e}")
        return 0

