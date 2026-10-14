"""Deploy rules/qradar/*.yml to QRadar through the REST API.

Flow (verified against QRadar 7.6.0 FP1):
  1. convert YAML rules -> QRadar content bundle (.tar.gz, CMT export format)
  2. POST /api/config/extension_management/extensions            (upload)
  3. POST /api/config/extension_management/extensions/{id}?action_type=INSTALL
  4. poll /api/config/extension_management/extensions_task_status/{status_id}

Env: QRADAR_HOST (e.g. https://1.2.3.4), QRADAR_TOKEN
"""
import base64
import glob
import io
import os
import sys
import tarfile
import time
import uuid
from datetime import datetime, timezone
from xml.sax.saxutils import escape

import requests
import urllib3
import yaml

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)  # self-signed cert

HOST = (os.getenv("QRADAR_HOST") or "").strip().rstrip("/")
TOKEN = (os.getenv("QRADAR_TOKEN") or "").strip()
if HOST and "://" not in HOST:
    HOST = "https://" + HOST

NAME = "customrule-gitops-ContentExport"
NS = uuid.UUID("6f1c2a52-0d0e-4a4b-9f5a-5b8d3f2f9a10")
FIRST_RULE_ID = 100501
QRADAR_VERSION = "2026.4.0.20260710212409"
BASE = "/api/config/extension_management"


# ---------- YAML -> QRadar XML ----------
def split_values(value):
    out = []
    for part in str(value).split(" AND "):
        part = part.strip().strip("*").strip()
        if part:
            out.append(part)
    return out


def detection_strings(detection):
    strings = []
    for field, value in detection.get("selection", {}).items():
        # Sysmon EventID 1/13 would become payload "1"/"13" and match almost anything
        if field.lower() == "eventid" and len(str(value)) <= 2:
            continue
        strings.extend(split_values(value))
    return strings


def test_xml(uid, value):
    v = escape(value)
    anchor = ("&lt;a href='javascript:editParameter(&quot;%d&quot;, &quot;1&quot;)' "
              "class='dynamic'&gt;%s&lt;/a&gt;" % (uid, v))
    return ('<test id="3" name="com.q1labs.semsources.cre.tests.EventPayload_Test" uid="%d" '
            'group="jsp.qradar.rulewizard.condition.page.group.event" groupId="3" '
            'requiredCapabilities="EventViewer.RULECREATION|SURVEILLANCE.RULECREATION">'
            '<text>when the Event Payload contains %s</text><parameter id="1">'
            '<initialText>this string</initialText><selectionLabel>Enter a payload string</selectionLabel>'
            '<userOptions format="user" source="user" multiselect="false"/>'
            '<userSelection>%s</userSelection><userSelectionTypes></userSelectionTypes>'
            '<userSelectionId>0</userSelectionId></parameter></test>') % (uid, anchor, v)


def rule_xml(rule, strings):
    tests = "".join(test_xml(i, s) for i, s in enumerate(strings))
    notes = "%s | id=%s | level=%s" % (rule.get("description", ""), rule.get("id", ""), rule.get("level", ""))
    return ('<rule id="-1" enabled="true" buildingBlock="false" roleDefinition="false" type="EVENT" '
            'scope="LOCAL" owner="admin"><name>%s</name><notes>%s</notes><testDefinitions>%s'
            '</testDefinitions><actions offenseMapping="0" forceOffenseCreation="true" '
            'includeAttackerEventsInterval="0" flowAnalysisInterval="0"/></rule>'
            ) % (escape(rule["title"]), escape(notes), tests)


def build_bundle(rules_glob="rules/qradar/*.yml"):
    files = sorted(glob.glob(rules_glob))
    if not files:
        sys.exit("[!] no rule files found: %s" % rules_glob)
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    blocks = ""
    for idx, fp in enumerate(files):
        with open(fp, encoding="utf-8") as f:
            rule = yaml.safe_load(f)
        strings = detection_strings(rule["detection"])
        if not strings:
            sys.exit("[!] no detection strings in %s" % fp)
        print("[+] %-45s -> %s (%d tests)" % (os.path.basename(fp), rule["title"], len(strings)))
        data = base64.b64encode(rule_xml(rule, strings).encode("utf-8")).decode("ascii")
        blocks += ("    <custom_rule>\n        <origin>USER</origin>\n        <flags>0</flags>\n"
                   "        <mod_date>%s</mod_date>\n        <rule_data>%s</rule_data>\n"
                   "        <uuid>%s</uuid>\n        <rule_type>0</rule_type>\n        <id>%d</id>\n"
                   "        <create_date>%s</create_date>\n    </custom_rule>\n"
                   ) % (now, data, uuid.uuid5(NS, str(rule.get("id") or rule["title"])),
                        FIRST_RULE_ID + idx, now)
    xml = ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n<content>\n'
           "    <qradarversion>%s</qradarversion>\n%s</content>\n" % (QRADAR_VERSION, blocks)).encode("utf-8")
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        info = tarfile.TarInfo(NAME + ".xml")
        info.size = len(xml)
        tar.addfile(info, io.BytesIO(xml))
        d = tarfile.TarInfo(NAME)
        d.type = tarfile.DIRTYPE
        d.mode = 0o755
        tar.addfile(d)
    return buf.getvalue(), len(files)


# ---------- QRadar API ----------
def api(method, path, **kw):
    headers = {"SEC": TOKEN, "Accept": "application/json"}
    r = requests.request(method, HOST + path, headers=headers, verify=False, timeout=60, **kw)
    if r.status_code >= 300:
        sys.exit("[!] %s %s -> HTTP %s\n%s" % (method, path, r.status_code, r.text[:600]))
    return r.json()


def main():
    if not HOST or not TOKEN:
        sys.exit("[!] QRADAR_HOST and QRADAR_TOKEN must be set")
    bundle, count = build_bundle()
    print("[*] bundle built: %d rules, %d bytes" % (count, len(bundle)))

    ext = api("POST", BASE + "/extensions", files={"file": (NAME + ".tar.gz", bundle)})
    ext_id = ext["id"]
    print("[+] uploaded as extension id=%s (%d content items)" % (ext_id, len(ext.get("contents", []))))

    task = api("POST", "%s/extensions/%s?action_type=INSTALL" % (BASE, ext_id))
    status_id = task["status_id"]
    print("[*] install started, task %s" % status_id)

    status = "?"
    for _ in range(60):
        t = api("GET", "%s/extensions_task_status/%s" % (BASE, status_id))
        status = t["status"]
        if status in ("COMPLETED", "FAILED", "CANCELLED"):
            print("[*] task %s: %s" % (status, t.get("message", "")))
            break
        time.sleep(3)

    final = api("GET", "%s/extensions/%s?fields=id,status,content_operation_error" % (BASE, ext_id))
    print("[*] extension: %s" % final)
    if status != "COMPLETED" or final.get("status") != "INSTALLED" or final.get("content_operation_error"):
        sys.exit("[!] deployment failed")
    print("[OK] %d QRadar rules deployed" % count)


if __name__ == "__main__":
    main()
