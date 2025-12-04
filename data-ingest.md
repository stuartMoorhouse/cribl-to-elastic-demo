# Data Ingest: Cribl to Elasticsearch

This document explains the data journey for each data source sent from Cribl to Elasticsearch.

## Overview

Data sent from Cribl arrives at `logs-cribl-default` and is processed by the Cribl integration's ingest pipelines. The `cribl-routing-pipeline` routes data to the appropriate destination based on the `_dataId` field.

## Current Data Sources

| Data Source | `_dataId` | Destination | Integration |
|-------------|-----------|-------------|-------------|
| Checkpoint | `checkpoint` | `logs-checkpoint.firewall-default` | Checkpoint |
| Fortinet | `fortinet` | `logs-fortinet_fortigate.log-default` | Fortinet FortiGate |
| Linux (Auditd) | `linux` | `logs-auditd.log-default` | Auditd |
| PowerShell | `powershell` | `logs-windows.powershell-default` | Windows |
| Windows Forwarded | `windows` | `logs-windows.forwarded-default` | Windows |
| Windows Events | `winlog` | `logs-system.security-default` | System |

## Pipeline Execution Order

```
Cribl sends to logs-cribl-default
         ↓
logs-cribl-1.0.0 (main pipeline)
    ├── set ecs.version
    ├── append tags
    ├── rename _raw → message
    ├── cribl-routing-pipeline        ← Routes by _dataId
    ├── global@custom
    ├── logs@custom
    ├── logs-cribl.integration@custom
    └── logs-cribl@custom             ← Custom parsing/routing
         ↓
Document written to final destination
```

## Windows Events: The Special Case

Windows Event data requires XML parsing to extract structured fields (`winlog.*`). Unlike other data sources, the raw XML must be parsed before it can be routed to the correct destination.

### Option A: Parse in Elasticsearch

| Step | Pipeline | Action |
|------|----------|--------|
| 1 | `cribl-routing-pipeline` | No `winlog` route configured (data passes through) |
| 2 | `logs-cribl@custom` | Calls `cribl-winlog-xml-parser` to parse XML |
| 3 | `logs-cribl@custom` | Reroutes to `logs-system.security-default` based on `winlog.channel` |

**Pros:**
- No changes required in Cribl

**Cons:**
- Custom pipeline to maintain in Elasticsearch
- Parsing with Painless regex is less efficient

### Option B: Parse in Cribl

| Step | Location | Action |
|------|----------|--------|
| 1 | Cribl Pipeline | Use `C.Text.parseWinEvent()` to parse XML |
| 2 | Cribl Pipeline | Structure output to match `winlog.*` field format |
| 3 | `cribl-routing-pipeline` | Route `winlog` → `system.security` |

**Pros:**
- Uses Cribl's built-in parser
- Simpler Elasticsearch configuration
- Better performance (parsing happens before ingestion)

**Cons:**
- Requires Cribl pipeline changes
- May need field mapping to match Elastic Agent format exactly

## Data Journey Comparison

### Structured Data (Checkpoint, Fortinet, etc.)

```
Cribl                     Elasticsearch
  │                            │
  │  Structured JSON           │
  ├───────────────────────────►│
  │                            │
  │                      cribl-routing-pipeline
  │                      routes by _dataId
  │                            │
  │                            ▼
  │                      Final destination
  │                      (e.g., logs-checkpoint.firewall-default)
```

### Windows Events - Option A (Parse in Elasticsearch)

```
Cribl                     Elasticsearch
  │                            │
  │  Raw XML string            │
  ├───────────────────────────►│
  │                            │
  │                      cribl-routing-pipeline
  │                      (no winlog route - passes through)
  │                            │
  │                      logs-cribl@custom
  │                      ├── Parse XML → winlog.* fields
  │                      └── Reroute by winlog.channel
  │                            │
  │                            ▼
  │                      logs-system.security-default
```

### Windows Events - Option B (Parse in Cribl)

```
Cribl                     Elasticsearch
  │                            │
  │  C.Text.parseWinEvent()    │
  │  converts XML → JSON       │
  │                            │
  │  Structured JSON           │
  ├───────────────────────────►│
  │                            │
  │                      cribl-routing-pipeline
  │                      routes winlog → system.security
  │                            │
  │                            ▼
  │                      logs-system.security-default
```

## Why Parsing Matters

Elastic Security detection rules expect specific field structures:

| Field | Description | Required For |
|-------|-------------|--------------|
| `winlog.event_id` | Windows Event ID (integer) | All detection rules |
| `winlog.channel` | Event log channel | Routing and filtering |
| `winlog.event_data.*` | Event-specific fields | Rule conditions |
| `event.code` | ECS event code | Cross-platform rules |
| `event.action` | Human-readable action | Alert descriptions |

Without parsing, these fields don't exist - only raw XML in the `message` field.

## Recommendations

1. **For simplest maintenance**: Parse in Cribl using `C.Text.parseWinEvent()`
2. **For Elastic Agent parity**: Ensure field names match `winlog.*` structure
3. **For detection rules**: Route to `logs-system.security-default` so rules can find the data