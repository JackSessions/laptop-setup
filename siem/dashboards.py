#!/usr/bin/env python3
"""Build the SIEM dashboards (dashboards-as-code) and push them to Kibana.

Usage:  siem dashboards          (re-run any time; it overwrites the same saved objects)

Edit the PANELS below to change what is shown. Each panel is a small Lens chart over the
filebeat-* data view. KQL filters use ECS field names (event.dataset, destination.port, ...).
"""
import json, os, subprocess, sys, urllib.request, base64, uuid

KIBANA = "http://127.0.0.1:5601"
DV = "siem-filebeat"
VERSION = "9.5.5"


def elastic_password():
    out = subprocess.run(["sudo", "-n", "sed", "-n", "s/^ELASTIC_PASSWORD=//p", "/etc/siem/.env"],
                         capture_output=True, text=True, check=True).stdout.strip()
    return out


# ---------- Lens column helpers ----------
def c_count(label="Events"):
    return {"label": label, "dataType": "number", "operationType": "count", "isBucketed": False,
            "scale": "ratio", "sourceField": "___records___", "params": {"emptyAsNull": True}}


def c_sum(field, label):
    return {"label": label, "dataType": "number", "operationType": "sum", "sourceField": field,
            "isBucketed": False, "scale": "ratio", "params": {"emptyAsNull": True}}


def c_date():
    return {"label": "@timestamp", "dataType": "date", "operationType": "date_histogram",
            "sourceField": "@timestamp", "isBucketed": True, "scale": "interval",
            "params": {"interval": "auto", "includeEmptyIntervals": True, "dropPartials": False}}


def c_terms(field, label, order_by="c_y", size=10):
    return {"label": label, "dataType": "string", "operationType": "terms", "scale": "ordinal",
            "sourceField": field, "isBucketed": True,
            "params": {"size": size, "orderBy": {"type": "column", "columnId": order_by},
                       "orderDirection": "desc", "otherBucket": True, "missingBucket": False,
                       "parentFormat": {"id": "terms"}}}


# ---------- Lens chart builders ----------
def lens(title, vtype, columns, visualization, query=""):
    cols = {k: v for k, v in columns}
    return {
        "type": "lens", "coreMigrationVersion": "8.8.0", "typeMigrationVersion": "10.1.0",
        "id": "siem-" + title.lower().replace(" ", "-").replace("/", "-").replace("(", "").replace(")", ""),
        "attributes": {
            "title": title, "description": "", "visualizationType": vtype,
            "state": {
                "datasourceStates": {"formBased": {"layers": {"l1": {
                    "columns": cols, "columnOrder": [k for k, _ in columns], "incompleteColumns": {}}}}},
                "visualization": visualization,
                "query": {"query": query, "language": "kuery"},
                "filters": [],
            },
        },
        "references": [{"type": "index-pattern", "id": DV, "name": "indexpattern-datasource-layer-l1"}],
    }


def metric(title, query, label="Events"):
    col = c_count(label)
    col["params"]["emptyAsNull"] = False   # show 0 instead of N/A when nothing matches
    return lens(title, "lnsMetric", [("c_y", col)],
                {"layerId": "l1", "layerType": "data", "metricAccessor": "c_y"}, query)


def timeline(title, query="", split=None, split_label="", kind="bar_stacked"):
    cols = [("c_x", c_date()), ("c_y", c_count())]
    layer = {"layerId": "l1", "accessors": ["c_y"], "position": "top", "seriesType": kind,
             "showGridlines": False, "layerType": "data", "xAccessor": "c_x"}
    if split:
        cols.insert(1, ("c_s", c_terms(split, split_label, size=8)))
        layer["splitAccessor"] = "c_s"
    vis = {"legend": {"isVisible": True, "position": "bottom"}, "valueLabels": "hide",
           "fittingFunction": "None", "preferredSeriesType": kind, "layers": [layer]}
    return lens(title, "lnsXY", cols, vis, query)


def top_bar(title, field, label, query="", size=10, value=None):
    # Lens wants bucket (group-by) columns before metric columns in columnOrder.
    cols = [("c_x", c_terms(field, label, size=size)), ("c_y", value or c_count())]
    layer = {"layerId": "l1", "accessors": ["c_y"], "position": "top", "seriesType": "bar_horizontal",
             "showGridlines": False, "layerType": "data", "xAccessor": "c_x"}
    vis = {"legend": {"isVisible": False, "position": "right"}, "valueLabels": "show",
           "preferredSeriesType": "bar_horizontal", "layers": [layer]}
    return lens(title, "lnsXY", cols, vis, query)


def donut(title, field, label, query="", size=6):
    cols = [("c_x", c_terms(field, label, size=size)), ("c_y", c_count())]
    vis = {"shape": "donut", "layers": [{
        "layerId": "l1", "primaryGroups": ["c_x"], "metrics": ["c_y"], "numberDisplay": "percent",
        "categoryDisplay": "default", "legendDisplay": "show", "nestedLegend": False, "layerType": "data"}]}
    return lens(title, "lnsPie", cols, vis, query)


def table(title, groups, query="", size=10, extra=None):
    """groups: [(field, label), ...]; extra: optional extra metric column (id, column)."""
    cols = [(f"c_g{i}", c_terms(f, l, order_by="c_y", size=size)) for i, (f, l) in enumerate(groups)]
    cols.append(("c_y", c_count("Events")))
    if extra:
        cols.append(extra)
    vis = {"layerId": "l1", "layerType": "data",
           "columns": [{"columnId": k} for k, _ in cols]}
    return lens(title, "lnsDatatable", cols, vis, query)


# ---------- Dashboards ----------
ZC = 'event.dataset : "zeek.connection"'
ZD = 'event.dataset : "zeek.dns"'
ZS = 'event.dataset : "zeek.ssl"'
AUTH = 'event.dataset : "system.auth"'
AUDIT = 'event.dataset : "auditd.log"'

DASHBOARDS = {
    "soc-overview": {
        "title": "SOC Overview",
        "description": "Everything at a glance: network, DNS, logins and host auditing",
        "panels": [
            # (chart, x, y, w, h)
            (metric("Total events", ""), 0, 0, 10, 7),
            (metric("Network connections", ZC), 10, 0, 10, 7),
            (metric("DNS lookups", ZD), 20, 0, 10, 7),
            (metric("Failed logins", AUTH + ' and event.outcome : "failure"'), 30, 0, 9, 7),
            (metric("Notices and weirds", 'event.dataset : ("zeek.notice" or "zeek.weird")'), 39, 0, 9, 7),
            (timeline("Events over time by source", "", "event.dataset", "Dataset"), 0, 7, 32, 14),
            (donut("Events by source", "event.dataset", "Dataset"), 32, 7, 16, 14),
            (top_bar("Top destination ports", "destination.port", "Port", ZC), 0, 21, 16, 14),
            (top_bar("Top DNS names", "dns.question.name", "Name", ZD), 16, 21, 16, 14),
            (top_bar("Top auditd rule keys", "auditd.log.key", "Key", AUDIT), 32, 21, 16, 14),
            (table("Failed logins by source", [("source.ip", "Source IP"), ("user.name", "User")],
                   AUTH + ' and event.outcome : "failure"'), 0, 35, 24, 13),
            (table("Auth activity by user", [("user.name", "User"), ("event.outcome", "Outcome")], AUTH),
             24, 35, 24, 13),
        ],
    },
    "network-zeek": {
        "title": "Network (Zeek)",
        "description": "Connections, DNS, TLS and notices seen by Zeek on the Wi-Fi interface",
        "panels": [
            (metric("Connections", ZC), 0, 0, 12, 7),
            (metric("Zeek DNS lookups", ZD), 12, 0, 12, 7),
            (metric("TLS handshakes", ZS), 24, 0, 12, 7),
            (metric("HTTP requests", 'event.dataset : "zeek.http"'), 36, 0, 12, 7),
            (timeline("Connections over time by protocol", ZC, "network.transport", "Transport"), 0, 7, 32, 14),
            (donut("Connection states", "zeek.connection.state", "State", ZC), 32, 7, 16, 14),
            (top_bar("Top TLS server names", "tls.client.server_name", "Server name", ZS, size=12), 0, 21, 24, 15),
            (top_bar("Top DNS names (Zeek)", "dns.question.name", "Name", ZD, size=12), 24, 21, 24, 15),
            (table("Top destinations by bytes", [("destination.ip", "Destination IP")], ZC, size=12,
                   extra=("c_b", c_sum("network.bytes", "Bytes"))), 0, 36, 24, 14),
            (donut("DNS record types", "dns.question.type", "Type", ZD), 24, 36, 12, 14),
            (donut("Destination countries", "destination.geo.country_name", "Country", ZC), 36, 36, 12, 14),
            (table("Zeek notices and weirds", [("event.dataset", "Type"), ("zeek.weird.name", "Weird"),
                                                ("zeek.notice.note", "Notice")],
                   'event.dataset : ("zeek.notice" or "zeek.weird")'), 0, 50, 48, 12),
        ],
    },
    "host-security": {
        "title": "Host Security",
        "description": "Logins, sudo and auditd activity on this laptop",
        "panels": [
            (metric("Login events", AUTH), 0, 0, 12, 7),
            (metric("Failed logins (host)", AUTH + ' and event.outcome : "failure"'), 12, 0, 12, 7),
            (metric("Auditd events", AUDIT), 24, 0, 12, 7),
            (metric("Syslog events", 'event.dataset : "system.syslog"'), 36, 0, 12, 7),
            (timeline("Login outcomes over time", AUTH, "event.outcome", "Outcome"), 0, 7, 32, 14),
            (donut("SSH auth methods", "system.auth.ssh.method", "Method", AUTH), 32, 7, 16, 14),
            (top_bar("Top users", "user.name", "User", AUTH), 0, 21, 16, 14),
            (top_bar("Top processes (auditd)", "process.name", "Process", AUDIT), 16, 21, 16, 14),
            (top_bar("Auditd rule keys", "auditd.log.key", "Key", AUDIT), 32, 21, 16, 14),
            (table("Auth events", [("event.action", "Action"), ("user.name", "User"), ("source.ip", "Source")],
                   AUTH, size=15), 0, 35, 48, 14),
        ],
    },
}


def dashboard_object(did, spec):
    panels, refs, charts = [], [], []
    for i, (chart, x, y, w, h) in enumerate(spec["panels"], 1):
        charts.append(chart)
        panels.append({"version": VERSION, "type": "lens", "panelIndex": str(i), "embeddableConfig": {},
                       "gridData": {"x": x, "y": y, "w": w, "h": h, "i": str(i)}, "panelRefName": f"panel_{i}"})
        refs.append({"name": f"panel_{i}", "type": "lens", "id": chart["id"]})
    dash = {
        "type": "dashboard", "id": did, "coreMigrationVersion": "8.8.0", "typeMigrationVersion": "10.3.0",
        "attributes": {
            "title": spec["title"], "description": spec["description"],
            "panelsJSON": json.dumps(panels),
            "optionsJSON": json.dumps({"useMargins": True, "syncColors": True, "syncCursor": True,
                                       "syncTooltips": True, "hidePanelTitles": False}),
            "timeRestore": True, "timeFrom": "now-24h", "timeTo": "now",
            "refreshInterval": {"pause": False, "value": 30000},
            "kibanaSavedObjectMeta": {"searchSourceJSON": json.dumps({"query": {"query": "", "language": "kuery"}, "filter": []})},
        },
        "references": refs,
    }
    return dash, charts


def main():
    objs = [{"type": "index-pattern", "id": DV, "coreMigrationVersion": "8.8.0", "typeMigrationVersion": "8.0.0",
             "attributes": {"title": "filebeat-*", "name": "SIEM: all logs", "timeFieldName": "@timestamp"},
             "references": []}]
    seen = set()
    for did, spec in DASHBOARDS.items():
        dash, charts = dashboard_object(did, spec)
        for c in charts:
            if c["id"] in seen:
                sys.exit(f"duplicate panel title: {c['attributes']['title']}")
            seen.add(c["id"])
            objs.append(c)
        objs.append(dash)
    ndjson = "\n".join(json.dumps(o) for o in objs) + "\n"

    pw = elastic_password()
    auth = "Basic " + base64.b64encode(f"elastic:{pw}".encode()).decode()
    boundary = uuid.uuid4().hex
    body = (f"--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"siem.ndjson\"\r\n"
            f"Content-Type: application/ndjson\r\n\r\n{ndjson}\r\n--{boundary}--\r\n").encode()
    req = urllib.request.Request(f"{KIBANA}/api/saved_objects/_import?overwrite=true", data=body, method="POST",
                                 headers={"kbn-xsrf": "true", "Authorization": auth,
                                          "Content-Type": f"multipart/form-data; boundary={boundary}"})
    try:
        res = json.load(urllib.request.urlopen(req))
    except urllib.error.HTTPError as e:
        sys.exit(f"Kibana import failed: HTTP {e.code}: {e.read().decode()[:800]}")
    print("import success:", res.get("success"), "| objects:", res.get("successCount"))
    for e in res.get("errors", []):
        print("  ERROR", e.get("id"), e.get("error"))

    def api(path, data):
        r = urllib.request.Request(f"{KIBANA}{path}", data=json.dumps(data).encode(), method="POST",
                                   headers={"kbn-xsrf": "true", "Authorization": auth, "Content-Type": "application/json",
                                            "x-elastic-internal-origin": "kibana"})
        try:
            urllib.request.urlopen(r).read()
        except Exception as e:  # settings are cosmetic; never fail the import over them
            print("  (setting skipped)", path, e)
    # Dark mode and open the SOC dashboard by default.
    api("/internal/kibana/settings", {"changes": {"theme:darkMode": "enabled",
                                                  "defaultRoute": "/app/dashboards#/view/soc-overview"}})
    print("Open: http://127.0.0.1:5601/app/dashboards#/view/soc-overview")
    return 0 if res.get("success") else 1


if __name__ == "__main__":
    sys.exit(main())
