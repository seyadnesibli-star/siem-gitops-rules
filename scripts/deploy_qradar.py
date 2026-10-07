import os
import glob
import requests
import yaml

QRADAR_HOST = os.getenv("QRADAR_HOST")
QRADAR_TOKEN = os.getenv("QRADAR_TOKEN")

HEADERS = {
    "SEC": QRADAR_TOKEN,
    "Accept": "application/json",
    "Content-Type": "application/json"
}

def deploy_qradar_rules():
    rule_files = glob.glob("rules/qradar/*.yml")
    print(f"[*] Found {len(rule_files)} QRadar detection rules.")

    for file_path in rule_files:
        with open(file_path, "r", encoding="utf-8") as f:
            rule_data = yaml.safe_load(f)

        title = rule_data.get("title")
        rule_id = rule_data.get("id")
        print(f"[+] Processing QRadar Rule: {title} (ID: {rule_id})")
        
        # QRadar API endpoint for custom rules or offenses upsert logic can be integrated here
        # payload = {"rule_name": title, "description": rule_data.get("description")}
        # response = requests.post(f"{QRADAR_HOST}/api/siem/offenses", headers=HEADERS, json=payload, verify=False)
        # print(f"Status Code: {response.status_code}")

if __name__ == "__main__":
    deploy_qradar_rules()
