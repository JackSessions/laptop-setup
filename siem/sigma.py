#!/usr/bin/env python3
"""Convert Sigma rules in siem/sigma/rules/ to Lucene queries and push them to Kibana Security.

Usage:  siem sigma            (convert + create/update; safe to re-run)
        siem sigma --list     (show what would be pushed)

Needs sigma-cli with the elasticsearch backend:  pipx install sigma-cli && sigma plugin install elasticsearch
Zeek rules use the built-in `ecs_zeek_beats` pipeline; Linux auditd rules use auditd-ecs.yml (this folder).
Rules are SigmaHQ's, under the Detection Rule License 1.1 (see NOTICE.md).
"""
import base64, glob, os, re, shutil, subprocess, sys
import yaml

HERE = os.path.dirname(os.path.abspath(__file__))        # siem/
SDIR = os.path.join(HERE, "sigma")                          # siem/sigma/ (rules + pipeline)
sys.path.insert(0, HERE)
import rules as R  # reuse the Kibana client and rule builder from rules.py

SIGMA = shutil.which("sigma") or os.path.expanduser("~/.local/bin/sigma")
RISK = {"informational": 5, "low": 21, "medium": 47, "high": 73, "critical": 99}


def convert(path, logsource):
    pipe = os.path.join(SDIR, "auditd-ecs.yml") if logsource.get("product") == "linux" else "ecs_zeek_beats"
    out = subprocess.run([SIGMA, "convert", "-t", "lucene", "-p", pipe, "-f", "default", path],
                         capture_output=True, text=True)
    lines = [l for l in out.stdout.splitlines() if l.strip() and not l.startswith("Parsing Sigma")]
    if out.returncode or not lines:
        raise RuntimeError((out.stderr or out.stdout).strip()[:200])
    return lines[0] if len(lines) == 1 else "(" + ") OR (".join(lines) + ")"


def build(path):
    s = yaml.safe_load(open(path))
    techs = sorted({m.group(1).upper() for t in s.get("tags", []) if (m := re.match(r"attack\.(t\d{4})", t))})
    level = s.get("level", "medium")
    ls = s.get("logsource", {})
    return {
        "id": "sigma-" + s["id"], "name": "Sigma: " + s["title"],
        "description": (s.get("description") or s["title"]).strip(),
        "language": "lucene", "query": convert(path, ls),
        "severity": "low" if level == "informational" else level, "risk": RISK.get(level, 47),
        "mitre": [t for t in techs if t in R.TECHNIQUES], "tags": ["sigma", ls.get("product", "")] + ([ls["service"]] if ls.get("service") else []),
        "note": f"SigmaHQ rule {s['id']} by {s.get('author', 'SigmaHQ')} (DRL 1.1). References: " + ", ".join(s.get("references", [])[:3]),
        "interval": "5m", "_file": os.path.basename(path),
    }


def main():
    R.AUTH = "Basic " + base64.b64encode(f"elastic:{R.password()}".encode()).decode()
    built, bad = [], 0
    for f in sorted(glob.glob(os.path.join(SDIR, "rules", "*.yml"))):
        try:
            built.append(build(f))
        except Exception as e:
            bad += 1
            print(f"SKIP    {os.path.basename(f)}: {e}")
    if "--list" in sys.argv:
        for b in built:
            print(f"{b['severity']:8} {b['name']}\n         {b['query'][:110]}")
        return 0
    R.call("POST", "/api/detection_engine/index")
    for b in built:
        body = R.to_kibana(b)
        code, res = R.call("POST", "/api/detection_engine/rules", body)
        verb = "created"
        if code == 409:
            code, res = R.call("PUT", "/api/detection_engine/rules", body); verb = "updated"
        if code >= 300:
            bad += 1; print(f"FAILED  {b['id']}: HTTP {code} {res.get('message', res)}")
        else:
            print(f"{verb:8}{b['name']}")
    print(f"{len(built) - bad}/{len(built)} Sigma rules in Kibana")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
