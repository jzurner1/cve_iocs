This is a quick project intended to ease threat hunting through known IOCs found in use with known exploited vulnerabilities (KEVs).

## Starting up
1. Set up a local MySQL instance
2. In `db_interaction()`, set the `mydb` variable information. Set `database="ttps"`
3. Get an OTX API key for free from https://otx.alienvault.com/
4. Replace all instances of `otx_api_key = ""` with your API key
5. In `main.py` under `if __name__ == "__main__":`, insert and run `db_interaction.set_up_db()` to create the database and tables
6. In `main.py` under `if __name__ == "__main__":`, insert and run `get_main_action_choice()` to begin the script
