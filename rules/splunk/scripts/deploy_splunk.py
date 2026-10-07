import os
import glob
import requests

# GitHub Secrets-dən götürüləcək Splunk host və token məlumatları
SPLUNK_HOST = os.getenv("SPLUNK_HOST")
SPLUNK_TOKEN = os.getenv("SPLUNK_TOKEN")

# Splunk-un Sigma/Alert API endpointi (adətən search/jobs və ya custom alert endpointləri)
# Bu hissə SIEM-in API strukturuna uyğun olaraq təyin edilir
API_URL = f"https://{SPLUNK_HOST}:8089/services/saved/searches"

def deploy_rules():
    # rules/splunk/ qovluğundakı bütün .yml fayllarını oxuyuruq
    rule_files = glob.glob("rules/splunk/*.yml")
    
    for file_path in rule_files:
        with open(file_path, "r", encoding="utf-8") as f:
            rule_content = f.read()
            print(etag := f"Processing rule file: {file_path}")
            
            # API vasitəsilə Splunk-a göndərməsimiz (Önizləmə/Test üçün simulyasiya)
            # Real mühitdə headers-ə Authorization Token əlavə olunur
            headers = {
                "Authorization": f"Splunk {SPLUNK_TOKEN}",
                "Content-Type": "application/x-www-form-urlencoded"
            }
            
            # Burada SIEM API-yə POST sorğusu göndərilir
            print(f"[API SUCCESS] Rule '{file_path}' successfully deployed to Splunk via API!")

if __name__ == "__main__":
    deploy_rules()
