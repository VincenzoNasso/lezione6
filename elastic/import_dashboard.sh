#!/usr/bin/env bash


set -euo pipefail

ES_URL="${ELASTICSEARCH_URL:-http://localhost:9200}"
KIBANA_URL="${KIBANA_URL:-http://localhost:5601}"
NDJSON="$(dirname "$0")/kibana_dashboard.ndjson"

echo "[import_dashboard] Attendo Elasticsearch..."
until curl -fsSL "${ES_URL}/_cluster/health" | grep -q '"status"'; do
  sleep 5
done
echo "[import_dashboard] Elasticsearch OK."

echo "[import_dashboard] Attendo Kibana..."
until curl -fsSL "${KIBANA_URL}/api/status" | grep -q '"overall"'; do
  sleep 5
done
echo "[import_dashboard] Kibana OK."

echo "[import_dashboard] Importo saved objects..."
curl -fsSL -X POST \
  "${KIBANA_URL}/api/saved_objects/_import?overwrite=true" \
  -H "kbn-xsrf: true" \
  --form file="@${NDJSON}"

echo ""
echo "[import_dashboard] Importazione completata."
echo "  Dashboard SOC: ${KIBANA_URL}/app/dashboards"
