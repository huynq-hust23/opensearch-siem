#!/bin/bash
# create_dashboard.sh
# Creates Attack Dashboard in OpenSearch Dashboards containing the Visualization

OPENSEARCH_URL="http://localhost:5601"
AUTH="admin:StrongP@ssw0rd!"
HEADER_TENANT="securitytenant: global"

echo "Creating Dashboard..."
RESPONSE=$(curl -X POST "$OPENSEARCH_URL/api/saved_objects/dashboard/attack-dashboard" \
  -u "$AUTH" \
  -H "osd-xsrf: true" \
  -H "$HEADER_TENANT" \
  -H "Content-Type: application/json" \
  -d "{
  \"attributes\": {
    \"title\": \"Attack Overview\",
    \"panelsJSON\": \"[{\\\"gridData\\\":{\\\"x\\\":0,\\\"y\\\":0,\\\"w\\\":24,\\\"h\\\":15,\\\"i\\\":\\\"1\\\"},\\\"version\\\":\\\"7.10.0\\\",\\\"panelIndex\\\":\\\"1\\\",\\\"type\\\":\\\"visualization\\\",\\\"id\\\":\\\"viz-attack-types\\\",\\\"embeddableConfig\\\":{}}]\",
    \"optionsJSON\": \"{\\\"useMargins\\\":true,\\\"hidePanelTitles\\\":false}\",
    \"version\": 1,
    \"timeRestore\": false,
    \"kibanaSavedObjectMeta\": {
      \"searchSourceJSON\": \"{\\\"query\\\":{\\\"query\\\":\\\"\\\",\\\"language\\\":\\\"kuery\\\"},\\\"filter\\\":[]}\"
    }
  }
}")

echo "Response: $RESPONSE"
