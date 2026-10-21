#!/usr/bin/env python3
"""Detection-as-code: push the YAML rules in siem/rules/ to Kibana Security.

Usage:  siem rules            (create or update every rule; safe to re-run)
        siem rules --list     (show rule ids, severity, enabled)

A rule file is YAML: either one rule or a list of rules. Fields:
  id: unique-slug            # becomes the Kibana rule_id; keep it stable
  name: Short title
  description: What it detects and why it matters
  type: query | threshold    # default query
  query: KQL over filebeat-* (ECS fields)
  threshold: {field: source.ip, value: 5}          # only for type threshold
             optional: cardinality: {field: destination.port, value: 100}
  severity: low | medium | high | critical
  risk: 0-100
  interval: 5m               # how often it runs
  mitre: [T1110]             # technique ids; looked up in TECHNIQUES below
  tags: [..]
  enabled: true
  note: What to do when it fires (shown on the alert)
"""
import base64, glob, json, os, subprocess, sys, urllib.error, urllib.request
import yaml

KIBANA = "http://127.0.0.1:5601"
HERE = os.path.dirname(os.path.abspath(__file__))

TACTICS = {
    "TA0001": "Initial Access", "TA0002": "Execution", "TA0003": "Persistence", "TA0004": "Privilege Escalation",
    "TA0005": "Defense Evasion", "TA0006": "Credential Access", "TA0007": "Discovery", "TA0009": "Collection",
    "TA0010": "Exfiltration", "TA0011": "Command and Control", "TA0040": "Impact",
}
# technique id -> (name, tactic id). Add more as you write rules.
TECHNIQUES = {
    "T1110": ("Brute Force", "TA0006"), "T1548": ("Abuse Elevation Control Mechanism", "TA0004"),
    "T1136": ("Create Account", "TA0003"), "T1098": ("Account Manipulation", "TA0003"),
    "T1543": ("Create or Modify System Process", "TA0003"), "T1053": ("Scheduled Task/Job", "TA0003"),
    "T1547": ("Boot or Logon Autostart Execution", "TA0003"), "T1556": ("Modify Authentication Process", "TA0006"),
    "T1071": ("Application Layer Protocol", "TA0011"), "T1571": ("Non-Standard Port", "TA0011"),
    "T1046": ("Network Service Discovery", "TA0007"), "T1200": ("Hardware Additions", "TA0001"),
    "T1078": ("Valid Accounts", "TA0001"), "T1496": ("Resource Hijacking", "TA0040"),
    "T1048": ("Exfiltration Over Alternative Protocol", "TA0010"), "T1105": ("Ingress Tool Transfer", "TA0011"),
    "T1569": ("System Services", "TA0002"), "T1095": ("Non-Application Layer Protocol", "TA0011"),
}


def password():
    return subprocess.run(["sudo", "-n", "sed", "-n", "s/^ELASTIC_PASSWORD=//p", "/etc/siem/.env"],
                          capture_output=True, text=True, check=True).stdout.strip()


AUTH = None


def call(method, path, body=None):
    req = urllib.request.Request(KIBANA + path, method=method,
                                 data=json.dumps(body).encode() if body is not None else None,
                                 headers={"kbn-xsrf": "true", "Authorization": AUTH, "Content-Type": "application/json",
                                          "elastic-api-version": "2023-10-31"})
    try:
        with urllib.request.urlopen(req) as r:
            return r.status, json.load(r)
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.loads(e.read().decode())
        except Exception:
            return e.code, {}


def threat(ids):
    out = {}
    for t in ids or []:
        name, tac = TECHNIQUES[t]
        e = out.setdefault(tac, {"framework": "MITRE ATT&CK",
                                 "tactic": {"id": tac, "name": TACTICS[tac],
                                            "reference": f"https://attack.mitre.org/tactics/{tac}/"},
                                 "technique": []})
        e["technique"].append({"id": t, "name": name, "reference": f"https://attack.mitre.org/techniques/{t}/"})
    return list(out.values())


def to_kibana(r):
    body = {
        "rule_id": r["id"], "name": r["name"], "description": r.get("description", r["name"]),
        "type": r.get("type", "query"), "language": r.get("language", "kuery"), "query": r["query"], "index": ["filebeat-*"],
        "severity": r.get("severity", "medium"), "risk_score": int(r.get("risk", 50)),
        "interval": r.get("interval", "5m"), "from": "now-6m", "enabled": r.get("enabled", True),
        "tags": r.get("tags", []), "threat": threat(r.get("mitre")), "note": r.get("note", ""),
        "author": ["laptop-setup"], "max_signals": 100,
    }
    if body["type"] == "threshold":
        t = r["threshold"]
        body["threshold"] = {"field": [t["field"]] if isinstance(t["field"], str) else t["field"], "value": int(t["value"])}
        if "cardinality" in t:
            c = t["cardinality"]
            body["threshold"]["cardinality"] = [{"field": c["field"], "value": int(c["value"])}]
    return body


def load():
    rules = []
    for f in sorted(glob.glob(os.path.join(HERE, "rules", "*.y*ml"))):
        data = yaml.safe_load(open(f))
        for r in (data if isinstance(data, list) else [data]):
            r["_file"] = os.path.basename(f)
            rules.append(r)
    ids = [r["id"] for r in rules]
    dup = {i for i in ids if ids.count(i) > 1}
    if dup:
        sys.exit(f"duplicate rule ids: {sorted(dup)}")
    return rules


def main():
    global AUTH
    AUTH = "Basic " + base64.b64encode(f"elastic:{password()}".encode()).decode()
    rules = load()
    if "--list" in sys.argv:
        for r in rules:
            print(f"{r['id']:34} {r.get('severity','medium'):9} {'on' if r.get('enabled', True) else 'off':4} {r['name']}")
        return 0
    call("POST", "/api/detection_engine/index")  # makes sure the alerts index exists
    bad = 0
    for r in rules:
        body = to_kibana(r)
        code, res = call("POST", "/api/detection_engine/rules", body)
        verb = "created"
        if code == 409:
            code, res = call("PUT", "/api/detection_engine/rules", body)
            verb = "updated"
        if code >= 300:
            bad += 1
            print(f"FAILED  {r['id']} ({r['_file']}): HTTP {code} {res.get('message', res)}")
        else:
            print(f"{verb:8}{r['id']}")
    print(f"{len(rules) - bad}/{len(rules)} rules in Kibana -> http://127.0.0.1:5601/app/security/rules")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
