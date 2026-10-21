#!/usr/bin/env bash
# One-time (and re-runnable) SIEM install. Run via: sudo bash ~/laptop-setup/setup.sh siem
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
ELK_VERSION="${ELK_VERSION:-9.5.5}"
D=/etc/siem

install -d -m 755 $D
install -d -m 755 -o 1000 -g 0 /var/lib/siem/es
install -d -m 755 /var/lib/siem/filebeat
install -m 644 "$HERE/compose.yml" $D/compose.yml
install -m 644 "$HERE/filebeat.yml" $D/filebeat.yml
install -m 755 "$HERE/siem" /usr/local/bin/siem

# Secrets are generated once and kept root-only.
if [[ ! -f $D/.env ]]; then
  ( umask 077
    cat > $D/.env <<EOF2
ELK_VERSION=$ELK_VERSION
ELASTIC_PASSWORD=$(openssl rand -hex 16)
KIBANA_PASSWORD=$(openssl rand -hex 16)
KIBANA_KEY=$(openssl rand -hex 32)
EOF2
  )
fi
chmod 600 $D/.env
sed -i "s/^ELK_VERSION=.*/ELK_VERSION=$ELK_VERSION/" $D/.env
set -a; . $D/.env; set +a

# Zeek: write JSON logs so Filebeat's zeek module can parse them.
LZ=/opt/zeek/share/zeek/site/local.zeek
if ! grep -q '^@load policy/tuning/json-logs' $LZ; then
  echo '@load policy/tuning/json-logs' >> $LZ
  /opt/zeek/bin/zeekctl deploy || true
fi

podman-compose --env-file $D/.env -f $D/compose.yml pull
podman-compose --env-file $D/.env -f $D/compose.yml up -d elasticsearch

echo "Waiting for Elasticsearch..."
for _ in $(seq 90); do
  curl -fs -u "elastic:$ELASTIC_PASSWORD" 127.0.0.1:9200/_cluster/health >/dev/null 2>&1 && break; sleep 3
done
curl -fs -u "elastic:$ELASTIC_PASSWORD" -H 'Content-Type: application/json' \
  -X POST 127.0.0.1:9200/_security/user/kibana_system/_password -d "{\"password\":\"$KIBANA_PASSWORD\"}" >/dev/null

# Keep disk use bounded: roll over daily/5GB, delete after 14 days.
curl -fs -u "elastic:$ELASTIC_PASSWORD" -H 'Content-Type: application/json' -X PUT 127.0.0.1:9200/_ilm/policy/filebeat -d '{
  "policy":{"phases":{
    "hot":{"actions":{"rollover":{"max_age":"1d","max_primary_shard_size":"5gb"}}},
    "delete":{"min_age":"14d","actions":{"delete":{}}}}}}' >/dev/null

podman-compose --env-file $D/.env -f $D/compose.yml up -d kibana
echo "Waiting for Kibana..."
for _ in $(seq 120); do curl -fs 127.0.0.1:5601/api/status >/dev/null 2>&1 && break; sleep 3; done

# Load Filebeat index templates and Kibana dashboards once.
podman run --rm --net=host --user root -e ELASTIC_PASSWORD="$ELASTIC_PASSWORD" \
  -v $D/filebeat.yml:/usr/share/filebeat/filebeat.yml:ro \
  docker.elastic.co/beats/filebeat:$ELK_VERSION filebeat setup -e --strict.perms=false 2>&1 | tail -3

podman-compose --env-file $D/.env -f $D/compose.yml up -d filebeat
# Dashboards and detection rules as code (run as the invoking user so sudo -n reads the password file).
sudo -u "${SUDO_USER:-root}" python3 -I "$HERE/dashboards.py" || true
sudo -u "${SUDO_USER:-root}" python3 -I "$HERE/rules.py" || true
# Read-only API key for the Waybar SIEM module (kept in the user's home, not the admin password).
UH="$(getent passwd "${SUDO_USER:-root}" | cut -d: -f6)"
if [[ ! -s "$UH/.config/siem/readonly.key" ]]; then
  install -d -m 700 -o "${SUDO_USER:-root}" "$UH/.config/siem"
  curl -fs -u "elastic:$ELASTIC_PASSWORD" -H 'Content-Type: application/json' -X POST 127.0.0.1:9200/_security/api_key -d '{
    "name":"waybar-readonly","role_descriptors":{"read_logs":{"indices":[{"names":["filebeat-*",".alerts-security.alerts-*",".internal.alerts-security.alerts-*"],"privileges":["read"]}]}}}' \
    | python3 -I -c "import json,sys;print(json.load(sys.stdin)['encoded'])" > "$UH/.config/siem/readonly.key" || true
  chown "${SUDO_USER:-root}": "$UH/.config/siem/readonly.key"; chmod 600 "$UH/.config/siem/readonly.key"
fi
echo "SIEM up: http://127.0.0.1:5601  user: elastic  password: run 'siem pass'"
