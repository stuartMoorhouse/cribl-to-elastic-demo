# Sending Custom Data to Elasticsearch via Cribl

This guide explains how to ingest custom data (data without an existing Elastic Integration) into Elasticsearch using Cribl Stream and the Elastic Cribl Integration.

## Overview

When sending custom data through Cribl to Elasticsearch, you have two main options:

1. **Direct to Elasticsearch**: Send data directly to a custom index or data stream
2. **Via the Cribl Integration**: Use the Elastic Cribl Integration with `_dataId` routing to leverage Elastic's integration framework

This guide focuses on **Option 2**, which provides better visibility in the Cribl Integration dashboard and follows Elastic's data stream conventions.

## Architecture

```
┌─────────────┐     ┌─────────────────┐     ┌──────────────────────────────┐
│ Data Source │────▶│  Cribl Stream   │────▶│  logs-cribl-default          │
│             │     │  (_dataId=test) │     │  (Cribl Integration)         │
└─────────────┘     └─────────────────┘     └──────────────┬───────────────┘
                                                          │
                                                          ▼
                                           ┌──────────────────────────────┐
                                           │  Reroute Processor           │
                                           │  (logs-cribl-default@custom) │
                                           └──────────────┬───────────────┘
                                                          │
                                                          ▼
                                           ┌──────────────────────────────┐
                                           │  logs-test-default           │
                                           │  (Custom Data Stream)        │
                                           │  + Custom Ingest Pipeline    │
                                           └──────────────────────────────┘
```

## Prerequisites

- Elasticsearch cluster (8.8+ recommended for reroute processor)
- Kibana access
- Cribl Stream with Elasticsearch destination configured
- The Elastic Cribl Integration installed

## Step-by-Step Configuration

### Step 1: Create the ILM Policy

Define how long data should be retained and when it should roll over.

```
PUT _ilm/policy/logs-test-policy
{
  "policy": {
    "phases": {
      "hot": {
        "min_age": "0ms",
        "actions": {
          "rollover": {
            "max_age": "30d",
            "max_primary_shard_size": "50gb"
          }
        }
      },
      "delete": {
        "min_age": "90d",
        "actions": {
          "delete": {}
        }
      }
    }
  }
}
```

### Step 2: Create the Custom Ingest Pipeline

This pipeline parses your custom data and maps it to ECS fields. Adjust the grok pattern to match your data format.

```
PUT _ingest/pipeline/logs-test-default
{
  "description": "Parse and enrich custom data from Cribl",
  "processors": [
    {
      "set": {
        "field": "data_stream.type",
        "value": "logs"
      }
    },
    {
      "set": {
        "field": "data_stream.dataset",
        "value": "test"
      }
    },
    {
      "set": {
        "field": "data_stream.namespace",
        "value": "default"
      }
    },
    {
      "set": {
        "field": "event.dataset",
        "value": "test"
      }
    },
    {
      "grok": {
        "field": "message",
        "patterns": [
          "%{IP:source.ip} - - \\[%{HTTPDATE:_tmp.timestamp}\\] \"%{WORD:http.request.method} %{URIPATHPARAM:url.path} HTTP/%{NUMBER:http.version}\" %{NUMBER:http.response.status_code} %{NUMBER:http.response.bytes}"
        ],
        "ignore_failure": true
      }
    },
    {
      "date": {
        "field": "_tmp.timestamp",
        "formats": ["dd/MMM/yyyy:HH:mm:ss Z"],
        "target_field": "@timestamp",
        "ignore_failure": true
      }
    },
    {
      "convert": {
        "field": "http.response.status_code",
        "type": "integer",
        "ignore_failure": true
      }
    },
    {
      "convert": {
        "field": "http.response.bytes",
        "type": "integer",
        "ignore_failure": true
      }
    },
    {
      "set": {
        "field": "event.category",
        "value": ["web"]
      }
    },
    {
      "set": {
        "field": "event.type",
        "value": ["access"]
      }
    },
    {
      "remove": {
        "field": "_tmp",
        "ignore_failure": true
      }
    },
    {
      "remove": {
        "field": "_dataId",
        "ignore_failure": true
      }
    }
  ]
}
```

### Step 3: Create the Component Templates

#### Mappings Template
```
PUT _component_template/logs-test-mappings
{
  "template": {
    "mappings": {
      "properties": {
        "@timestamp": { "type": "date" },
        "message": { "type": "text" },
        "data_stream": {
          "properties": {
            "type": { "type": "constant_keyword", "value": "logs" },
            "dataset": { "type": "constant_keyword", "value": "test" },
            "namespace": { "type": "constant_keyword", "value": "default" }
          }
        },
        "event": {
          "properties": {
            "category": { "type": "keyword" },
            "type": { "type": "keyword" },
            "dataset": { "type": "keyword" }
          }
        },
        "source": {
          "properties": {
            "ip": { "type": "ip" }
          }
        },
        "http": {
          "properties": {
            "request": {
              "properties": {
                "method": { "type": "keyword" }
              }
            },
            "response": {
              "properties": {
                "status_code": { "type": "integer" },
                "bytes": { "type": "integer" }
              }
            },
            "version": { "type": "keyword" }
          }
        },
        "url": {
          "properties": {
            "path": { "type": "keyword" }
          }
        }
      }
    }
  }
}
```

#### Settings Template
```
PUT _component_template/logs-test-settings
{
  "template": {
    "settings": {
      "index": {
        "default_pipeline": "logs-test-default",
        "lifecycle": {
          "name": "logs-test-policy"
        },
        "number_of_shards": 1,
        "number_of_replicas": 1
      }
    }
  }
}
```

### Step 4: Create the Index Template
```
PUT _index_template/logs-test-template
{
  "index_patterns": ["logs-test-*"],
  "data_stream": {},
  "composed_of": [
    "logs-test-mappings",
    "logs-test-settings"
  ],
  "priority": 500,
  "_meta": {
    "description": "Template for custom test data from Cribl"
  }
}
```

### Step 5: Create the Data Stream
```
PUT _data_stream/logs-test-default
```

### Step 6: Configure the Reroute Processor

This is the key step that routes data from `logs-cribl-default` to your custom data stream based on the `_dataId` field.

```
PUT _ingest/pipeline/logs-cribl-default@custom
{
  "description": "Route Cribl data to appropriate data streams based on _dataId",
  "processors": [
    {
      "reroute": {
        "tag": "route-to-test",
        "if": "ctx?._dataId == 'test'",
        "destination": "logs-test-default"
      }
    }
  ]
}
```

> **Note**: The reroute processor immediately stops processing the current pipeline and routes the document to the new destination, where it will be processed by that destination's default pipeline (`logs-test-default`).

## Cribl Configuration

### Destination Settings

Configure your Elasticsearch destination in Cribl with:

| Setting | Value |
|---------|-------|
| **Index or Data Stream** | `logs-cribl-default` |
| **API Key** | Base64-encoded Elastic API key with write permissions to `logs-*` |

### Adding the `_dataId` Field

In your Cribl pipeline, add an **Eval** function to set the `_dataId` field:

```javascript
_dataId = 'test'
```

Alternatively, you can set this in the source configuration under **Fields**.

## Testing the Configuration

### Send a Test Document
```
POST logs-cribl-default/_doc
{
  "@timestamp": "2025-01-15T10:00:00.000Z",
  "_dataId": "test",
  "message": "192.168.1.100 - - [15/Jan/2025:10:00:00 +0000] \"GET /api/users HTTP/1.1\" 200 1234"
}
```

### Verify the Document Was Routed and Parsed
GET logs-test-default/_search
```json
{
  "size": 10,
  "sort": [{ "@timestamp": "desc" }]
}
```

Expected result should show ECS-mapped fields:

```
{
  "_source": {
    "@timestamp": "2025-01-15T10:00:00.000Z",
    "message": "192.168.1.100 - - [15/Jan/2025:10:00:00 +0000] \"GET /api/users HTTP/1.1\" 200 1234",
    "source": {
      "ip": "192.168.1.100"
    },
    "http": {
      "request": {
        "method": "GET"
      },
      "response": {
        "status_code": 200,
        "bytes": 1234
      },
      "version": "1.1"
    },
    "url": {
      "path": "/api/users"
    },
    "event": {
      "category": ["web"],
      "type": ["access"],
      "dataset": "test"
    },
    "data_stream": {
      "type": "logs",
      "dataset": "test",
      "namespace": "default"
    }
  }
}
```

## Adding Additional Custom Data Sources

To add another custom data source, repeat the process:

1. Create a new ingest pipeline (e.g., `logs-myapp-default`)
2. Create component templates for `logs-myapp-*`
3. Create an index template for `logs-myapp-*`
4. Create the data stream `logs-myapp-default`
5. Add another reroute condition to the `logs-cribl-default@custom` pipeline:

```
PUT _ingest/pipeline/logs-cribl-default@custom
{
  "description": "Route Cribl data to appropriate data streams based on _dataId",
  "processors": [
    {
      "reroute": {
        "tag": "route-to-test",
        "if": "ctx?._dataId == 'test'",
        "destination": "logs-test-default"
      }
    },
    {
      "reroute": {
        "tag": "route-to-myapp",
        "if": "ctx?._dataId == 'myapp'",
        "destination": "logs-myapp-default"
      }
    }
  ]
}
```

## Cleanup Commands

If you need to remove the configuration:

```
DELETE _data_stream/logs-test-default
DELETE _index_template/logs-test-template
DELETE _component_template/logs-test-mappings
DELETE _component_template/logs-test-settings
DELETE _ingest/pipeline/logs-test-default
DELETE _ingest/pipeline/logs-cribl-default@custom
DELETE _ilm/policy/logs-test-policy
```

## Troubleshooting

### Data Not Appearing in Custom Data Stream

1. Verify the `_dataId` field is being set in Cribl
2. Check that the reroute processor condition matches exactly
3. Verify the `logs-cribl-default@custom` pipeline exists

### Parsing Errors

1. Test your grok pattern using Kibana's Grok Debugger (**Dev Tools → Grok Debugger**)
2. Check the ingest pipeline simulate API:

POST _ingest/pipeline/logs-test-default/_simulate
```json
{
  "docs": [
    {
      "_source": {
        "message": "192.168.1.100 - - [15/Jan/2025:10:00:00 +0000] \"GET /api/users HTTP/1.1\" 200 1234"
      }
    }
  ]
}
```

### Permission Errors

Ensure your API key has:
- `auto_configure` permission on `logs-*`
- `write` permission on `logs-*`

## References

- [Elastic Cribl Integration Documentation](https://docs.elastic.co/integrations/cribl)
- [Cribl Elasticsearch Destination](https://docs.cribl.io/stream/destinations-elastic/)
- [Elasticsearch Reroute Processor](https://www.elastic.co/guide/en/elasticsearch/reference/current/reroute-processor.html)
- [Elastic Common Schema (ECS)](https://www.elastic.co/guide/en/ecs/current/index.html)
