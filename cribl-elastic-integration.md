# Cribl to Elastic Integration Guide

This guide walks through configuring Cribl Stream to send logs to Elastic Cloud using the Cribl integration for proper ECS field mapping. It uses Fortinet FortiGate logs as an example, but the same approach works for any log source.

## Architecture

```
Log Source → Cribl Stream → Cribl Elastic Output → Elastic Cloud (Cribl Integration)
                                                            ↓
                                                   Target Integration Assets
                                                   (dashboards, alerts, etc.)
```

The Cribl integration in Elastic routes incoming data to the appropriate Fleet integration data streams based on a `_dataId` field. This allows you to leverage pre-built dashboards, alerts, and ECS field mappings from any Elastic integration.

## Prerequisites

- Cribl Stream instance (self-hosted or Cribl Cloud)
- Elastic Cloud deployment (or self-managed Elasticsearch 8.x+)
- A log source sending data to Cribl
- The target Elastic integration installed (e.g., Fortinet, Cisco, Palo Alto)

## Step 1: Install Target Integration Assets in Kibana

The Cribl integration routes data to existing Fleet integration data streams. First, install the assets for your target integration:

1. Open Kibana
2. Navigate to **Management > Integrations**
3. Search for your target integration (e.g., **Fortinet FortiGate**)
4. Click on the integration
5. Go to the **Settings** tab (not "Add Integration")
6. Click **Install [Integration Name] assets**
7. Confirm the installation

**Important**: Do NOT add the integration to a policy. We only need the assets installed (dashboards, index templates, ingest pipelines). The Cribl integration will route data to these data streams.

## Step 2: Install and Configure the Cribl Integration in Kibana

1. In Kibana, navigate to **Management > Integrations**
2. Search for **Cribl**
3. Click **Add Cribl**
4. Configure the integration:
   - **Integration name**: Give it a descriptive name (e.g., `cribl-fortinet`)
   - **Data ID routing**: Map `_dataId` values to Fleet integration data streams
     - Example: `_dataId`: `fortinet` → Data stream: `logs-fortinet_fortigate.log`
5. Select or create an Agent policy (note: Elastic Agent is not required, but a policy must be configured)
6. Click **Save and continue**

### Finding the Correct Data Stream Name

To find the data stream name for your target integration:
1. Go to **Management > Stack Management > Index Management > Index Templates**
2. Search for your integration name (e.g., "fortinet")
3. Note the template name (e.g., `logs-fortinet_fortigate.log`)

## Step 3: Create an API Key in Kibana

1. Navigate to **Management > Stack Management > Security > API Keys**
2. Click **Create API key**
3. Configure:
   - **Name**: `cribl-integration`
   - **Restrict privileges** (optional): If restricting, ensure at least `auto_configure` and `write` permissions for `logs-*` index
4. Click **Create API key**
5. **Copy the Base64 encoded API key** - you'll need this for Cribl

## Step 4: Configure Cribl Source with _dataId Field

The `_dataId` field tells the Cribl integration in Elastic which data stream to route the data to.

1. Open Cribl Stream UI
2. Navigate to **Data > Sources**
3. Click on your source (e.g., Syslog)
4. Under **Configure > Processing Settings > Fields**, add a field:
   - **Name**: `_dataId`
   - **Value**: `'your-data-id'` (e.g., `'fortinet'` - note the quotes for string literals)
5. Click **Save**

## Step 5: Configure Elasticsearch Destination in Cribl

1. In Cribl UI, navigate to **Data > Destinations**
2. Click **Add Destination**
3. Select **Elasticsearch** (or **Elastic Cloud** for cloud deployments)
4. Configure:
   - **Output ID**: Give it a name (e.g., `elastic-cloud`)
   - **Bulk API URLs** or **Cloud Id**: Your Elasticsearch endpoint
   - **Index or Data Stream**: `logs-cribl-default`
   - **API key**: Paste the Base64 encoded API key from Step 3
5. Click **Save**

## Step 6: Create Pipeline to Remove Duplicate Message Field

The Elastic Cribl integration expects the `_raw` field and renames it to `message`. Cribl sends both `_raw` and `message` by default, which causes a conflict and prevents the reroute to the target data stream. We need to remove the `message` field before sending to Elastic.

1. Navigate to **Data > Processing > Pipelines**
2. Click **Add Pipeline**
3. Name it: `remove-message-field`
4. Click **Add Function**
5. Select **Eval**
6. In **Remove Fields**, add: `message`
7. Click **Save**

## Step 7: Create Route in Cribl

1. Navigate to **Data > Routing > Data Routes**
2. Click **Add Route**
3. Configure:
   - **Route Name**: Descriptive name (e.g., `fortinet-to-elastic`)
   - **Filter**: `true` (or filter for specific sources, e.g., `__inputId=='syslog'`)
   - **Pipeline**: `remove-message-field`
   - **Output**: Your Elasticsearch destination (e.g., `elastic-cloud`)
4. Click **Save**
5. **Drag the route above "Default"** - Routes are evaluated top-to-bottom, first match wins
6. Click **Version Control > Commit & Deploy** (top right)

## Step 8: Verify Data Flow

### Check Cribl is Receiving Data

In Cribl UI:
1. Go to **Monitoring > Sources**
2. Verify your source shows incoming events ("Events In")

### Check Cribl is Sending Data

In Cribl UI:
1. Go to **Monitoring > Destinations**
2. Verify your Elasticsearch destination shows outgoing events ("Events Out")

### Check Data in Kibana

1. Open Kibana
2. Go to **Discover**
3. Create or select data view for your target data stream (e.g., `logs-fortinet_fortigate.log-*`)
4. You should see logs with ECS-mapped fields
5. Check **Analytics > Dashboard** for pre-built dashboards from your integration

## Troubleshooting

### Data appears in logs-cribl-default but not in target data stream

This usually means the reroute isn't working. Check:

1. **_dataId field is present**: Look at a document in `logs-cribl-default` and verify it has the `_dataId` field with the correct value

2. **Cribl integration mapping**: Verify the mapping in the Cribl integration matches your `_dataId` value exactly

3. **Message field conflict**: If you see `"error.message": "field [message] already exists"`, ensure you're using the pipeline from Step 6 to remove the `message` field

### No data in Cribl

```bash
# Check your source is receiving data
# In Cribl: Monitoring > Sources

# Check the source port is listening (example for syslog on port 9514)
ss -tlnup | grep 9514
```

### No data leaving Cribl to Elastic

1. Check the route is active and positioned above "Default"
2. Check destination configuration (API key, endpoint URL)
3. View Cribl logs for errors:
   ```bash
   sudo tail -f /opt/cribl/log/cribl.log
   ```

### Authentication errors

- Ensure the API key is Base64 encoded
- Verify the API key has `auto_configure` and `write` permissions for `logs-*`

### Finding the correct data stream name

```bash
# List all index templates
curl -s -u "elastic:PASSWORD" "https://ELASTICSEARCH_URL/_index_template" | jq -r '.index_templates[].name' | grep -i YOUR_INTEGRATION

# Check what data streams exist
curl -s -u "elastic:PASSWORD" "https://ELASTICSEARCH_URL/_data_stream" | jq -r '.data_streams[].name'
```

## Example: Fortinet FortiGate Logs

For Fortinet FortiGate logs:

| Setting | Value |
|---------|-------|
| Integration assets | Fortinet FortiGate |
| `_dataId` value | `fortinet` |
| Target data stream | `logs-fortinet_fortigate.log` |
| Kibana data view | `logs-fortinet_fortigate.log-*` |

## Reference

- [Elastic Cribl Integration Documentation](https://www.elastic.co/docs/reference/integrations/cribl)
- [Cribl Elastic Cloud Output Documentation](https://docs.cribl.io/stream/destinations-elastic-cloud/)
- [Cribl Elasticsearch Output Documentation](https://docs.cribl.io/stream/destinations-elastic/)
