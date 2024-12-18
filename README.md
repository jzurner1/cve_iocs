This is a quick project that attempts to streamline threat hunting efforts by utilizing threat intelligence from known-exploited vulnerabilities (KEVs) provided by CISA. It automates the collection and analysis of those vulnerabilities to provide IOCs that can be utilized to identify and mitigate threats.

Currently, the script mainly uses CISA's KEV catalogue and OTX's threat hunting pulses to extract known IOCs. In the future I may include other threat feeds such as those provided by VirusTotal for more rounded information, but for now it acts as a proof-of-concept.

## Starting up
1. Set up a local MySQL instance
2. Create a database called `ttps`
3. In `db_interaction()`, set the `mydb` variable information. Set `database="ttps"`
4. Get an OTX API key for free from https://otx.alienvault.com/
5. Replace all instances of `otx_api_key = ""` with your API key
6. In `main.py` under `if __name__ == "__main__":`, insert and run `db_interaction.set_up_db()` to create the database and tables
7. In `main.py` under `if __name__ == "__main__":`, insert and run `get_main_action_choice()` to begin the script


## Notes
- DO NOT RUN THIS IN ANY PRODUCTION ENVIRONMENT! The SQL injection protection is shoddy at best
- To see a sample of the IOC output, view the file `50k IOCs sample.csv`
- Some IOCs are related to multiple CVEs so there will be some overlap there, but there should be no duplicates for both CVE ID and IOC value
- As is the nature of IOCs, there are plenty of false positives in here, so do not treat it as gospel
