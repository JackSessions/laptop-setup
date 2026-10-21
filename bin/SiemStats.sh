#!/usr/bin/env bash
# Waybar module: live SIEM numbers. Uses a read-only Elasticsearch API key (~/.config/siem/readonly.key).
# Shows: open security alerts (24h) and Zeek connections per minute (last 5 min).
key_file="$HOME/.config/siem/readonly.key"
es=http://127.0.0.1:9200
off() { printf '{"text":"󰒃 off","class":"off","tooltip":"SIEM is stopped. Run: siem up"}\n'; exit 0; }
[[ -r $key_file ]] || off
auth="Authorization: ApiKey $(<"$key_file")"
q() { curl -fs -m 3 -H "$auth" -H 'Content-Type: application/json' "$es/$1" -d "$2"; }

alerts=$(q '.alerts-security.alerts-*/_search?size=0' '{"query":{"bool":{"filter":[{"term":{"kibana.alert.workflow_status":"open"}},{"range":{"@timestamp":{"gte":"now-24h"}}}]}},"aggs":{"r":{"terms":{"field":"kibana.alert.rule.name","size":5}},"sev":{"terms":{"field":"kibana.alert.severity"}}}}') || off
conn=$(q 'filebeat-*/_count' '{"query":{"bool":{"filter":[{"term":{"event.dataset":"zeek.connection"}},{"range":{"@timestamp":{"gte":"now-5m"}}}]}}}' | jq -r '.count // 0') || off

jq -nc --argjson a "$alerts" --argjson c "${conn:-0}" '
  ($a.hits.total.value // 0) as $n
  | ([$a.aggregations.sev.buckets[]? | select(.key=="high" or .key=="critical") | .doc_count] | add // 0) as $hi
  | ([$a.aggregations.r.buckets[]? | "\(.key) (\(.doc_count))"] | join("\n")) as $top
  | { text: "󰒃 \($n)  󰖟 \(($c/5)|floor)/m",
      class: (if $hi > 0 then "high" elif $n > 0 then "alerts" else "ok" end),
      tooltip: "Open alerts (24h): \($n)\nHigh/critical: \($hi)\n\n\(if $top == "" then "no open alerts" else $top end)\n\nZeek connections: \($c) in 5 min\nClick: SOC workspace" }'
