#!/bin/bash
# create_viz.sh
# Creates Attack Type Visualization in OpenSearch Dashboards

OPENSEARCH_URL="http://localhost:5601"
AUTH="admin:StrongP@ssw0rd!"
HEADER_TENANT="securitytenant: global"

# 1. Get Index Pattern ID (Global)
echo "Fetching Index Pattern ID (Global)..."
INDEX_PATTERN_ID=$(curl -s -u "$AUTH" -H "$HEADER_TENANT" "$OPENSEARCH_URL/api/saved_objects/_find?type=index-pattern&search_fields=title&search=siem-suricata*" | jq -r '.saved_objects[0].id')

if [ -z "$INDEX_PATTERN_ID" ] || [ "$INDEX_PATTERN_ID" == "null" ]; then
    echo "Error: Index Pattern siem-suricata* not found!"
    exit 1
fi

echo "Found Index Pattern ID: $INDEX_PATTERN_ID"

# 2. Field Name (Verify if typical ECS or raw)
# Check if field exists, fallback to suricata.eve.alert.signature.keyword
FIELD_NAME="suricata.eve.alert.signature.keyword"

# 3. Create Visualization
echo "Creating Visualization..."
RESPONSE=$(curl -X POST "$OPENSEARCH_URL/api/saved_objects/visualization/viz-attack-types" \
  -u "$AUTH" \
  -H "osd-xsrf: true" \
  -H "$HEADER_TENANT" \
  -H "Content-Type: application/json" \
  -d "{
  \"attributes\": {
    \"title\": \"Attack Types\",
    \"visState\": \"{\\\"title\\\":\\\"Attack Types\\\",\\\"type\\\":\\\"pie\\\",\\\"params\\\":{\\\"type\\\":\\\"pie\\\",\\\"addTooltip\\\":true,\\\"addLegend\\\":true,\\\"legendPosition\\\":\\\"right\\\",\\\"isDonut\\\":true,\\\"labels\\\":{\\\"show\\\":false,\\\"values\\\":true,\\\"last_level\\\":true,\\\"truncate\\\":100}},\\\"aggs\\\":[{\\\"id\\\":\\\"1\\\",\\\"enabled\\\":true,\\\"type\\\":\\\"count\\\",\\\"schema\\\":\\\"metric\\\",\\\"params\\\":{}},{\\\"id\\\":\\\"2\\\",\\\"enabled\\\":true,\\\"type\\\":\\\"terms\\\",\\\"schema\\\":\\\"segment\\\",\\\"params\\\":{\\\"field\\\":\\\"$FIELD_NAME\\\",\\\"orderBy\\\":\\\"1\\\",\\\"order\\\":\\\"desc\\\",\\\"size\\\":10,\\\"otherBucket\\\":false,\\\"otherBucketLabel\\\":\\\"Other\\\",\\\"missingBucket\\\":false}}]}\",
    \"uiStateJSON\": \"{}\",
    \"description\": \"Breakdown of attack signatures from Suricata alerts\",
    \"version\": 1,
    \"kibanaSavedObjectMeta\": {
      \"searchSourceJSON\": \"{\\\"query\\\":{\\\"query\\\":\\\"suricata.eve.event_type: alert\\\",\\\"language\\\":\\\"kuery\\\"},\\\"filter\\\":[],\\\"index\\\":\\\"$INDEX_PATTERN_ID\\\"}\"
    }
  }
}")

echo "Response: $RESPONSE"
