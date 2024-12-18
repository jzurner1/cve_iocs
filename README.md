This is a quick project that attempts to streamline threat hunting efforts by utilizing threat intelligence from known-exploited vulnerabilities (KEVs) provided by CISA. It automates the collection and analysis of those vulnerabilities to provide IOCs that can be utilized to identify and mitigate threats.

Currently, the script mainly uses CISA's KEV catalogue and OTX's threat hunting pulses to extract known IOCs. In the future I may include other threat feeds such as those provided by VirusTotal for more rounded information, but for now it acts as a proof-of-concept.

## Starting up
1. Set up a local MySQL instance
2. In `db_interaction()`, set the `mydb` variable information. Set `database="ttps"`
3. Get an OTX API key for free from https://otx.alienvault.com/
4. Replace all instances of `otx_api_key = ""` with your API key
5. In `main.py` under `if __name__ == "__main__":`, insert and run `db_interaction.set_up_db()` to create the database and tables
6. In `main.py` under `if __name__ == "__main__":`, insert and run `get_main_action_choice()` to begin the script