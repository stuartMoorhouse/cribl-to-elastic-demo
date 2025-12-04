# Windows Event XML Parser for Cribl Integration

This ingest pipeline converts raw Windows Event XML (as received from Cribl) into the format that Elastic Agent produces, enabling full compatibility with the Windows/System integration's enrichment pipelines and Elastic Security detection rules.

## Overview

When Elastic Agent collects Windows events, it:
1. Reads from the Windows Event Log API
2. Parses the XML into structured JSON fields (`winlog.*`)
3. Maps common fields to ECS (`user.*`, `source.*`, `process.*`, etc.)

This pipeline replicates that process for raw XML data arriving via Cribl.

## Installation

Run these commands in Kibana Dev Console in order.

---

## Step 1: Create the XML Parser Pipeline

This is the main pipeline that converts XML to Elastic Agent format:

```
PUT _ingest/pipeline/cribl-winlog-xml-parser
{
  "description": "Convert raw Windows Event XML to Elastic Agent format for Windows integration compatibility",
  "processors": [
    {
      "set": {
        "description": "Preserve original message",
        "field": "event.original",
        "value": "{{{message}}}",
        "if": "ctx.message != null"
      }
    },
    {
      "xml": {
        "description": "Parse XML message",
        "field": "message",
        "target_field": "_xml",
        "ignore_failure": true
      }
    },
    {
      "script": {
        "description": "Extract System fields from Windows Event XML",
        "lang": "painless",
        "ignore_failure": true,
        "source": """
          if (ctx._xml?.Event?.System == null) {
            return;
          }
          
          def system = ctx._xml.Event.System;
          
          // Initialize winlog object
          ctx.winlog = [:];
          
          // Basic event identification
          ctx.winlog.channel = system.Channel;
          ctx.winlog.event_id = system.EventID instanceof Map ? system.EventID[''] : system.EventID;
          ctx.winlog.provider_name = system.Provider?.Name;
          ctx.winlog.provider_guid = system.Provider?.Guid;
          ctx.winlog.record_id = system.EventRecordID;
          ctx.winlog.computer_name = system.Computer;
          ctx.winlog.task = system.Task;
          ctx.winlog.opcode = system.Opcode;
          ctx.winlog.version = system.Version;
          ctx.winlog.api = "wineventlog";
          
          // Keywords
          if (system.Keywords != null) {
            ctx.winlog.keywords = [system.Keywords];
          }
          
          // Process information
          if (system.Execution != null) {
            ctx.winlog.process = [:];
            if (system.Execution.ProcessID != null) {
              try {
                ctx.winlog.process.pid = Integer.parseInt(system.Execution.ProcessID.toString());
              } catch (Exception e) {
                ctx.winlog.process.pid = system.Execution.ProcessID;
              }
            }
            if (system.Execution.ThreadID != null) {
              ctx.winlog.process.thread = [:];
              try {
                ctx.winlog.process.thread.id = Integer.parseInt(system.Execution.ThreadID.toString());
              } catch (Exception e) {
                ctx.winlog.process.thread.id = system.Execution.ThreadID;
              }
            }
          }
          
          // Activity ID / Correlation
          if (system.Correlation != null && system.Correlation.ActivityID != null) {
            ctx.winlog.activity_id = system.Correlation.ActivityID;
          }
          
          // Level mapping
          if (system.Level != null) {
            def levelMap = [
              '0': 'Information',
              '1': 'Critical',
              '2': 'Error',
              '3': 'Warning',
              '4': 'Information',
              '5': 'Verbose'
            ];
            ctx.winlog.level = levelMap.getOrDefault(system.Level.toString(), 'Information');
          }
          
          // Time created
          if (system.TimeCreated?.SystemTime != null) {
            ctx.winlog.time_created = system.TimeCreated.SystemTime;
          }
        """
      }
    },
    {
      "script": {
        "description": "Extract EventData fields",
        "lang": "painless",
        "ignore_failure": true,
        "source": """
          if (ctx._xml?.Event?.EventData?.Data == null) {
            return;
          }
          
          ctx.winlog.event_data = [:];
          def data = ctx._xml.Event.EventData.Data;
          
          if (data instanceof List) {
            for (item in data) {
              if (item instanceof Map && item.Name != null) {
                def value = item[''];
                if (value != null && value != '') {
                  ctx.winlog.event_data[item.Name] = value;
                }
              }
            }
          } else if (data instanceof Map && data.Name != null) {
            def value = data[''];
            if (value != null && value != '') {
              ctx.winlog.event_data[data.Name] = value;
            }
          }
        """
      }
    },
    {
      "script": {
        "description": "Extract UserData fields (for events that use UserData instead of EventData)",
        "lang": "painless",
        "ignore_failure": true,
        "source": """
          if (ctx._xml?.Event?.UserData == null || ctx.winlog?.event_data != null) {
            return;
          }
          
          ctx.winlog.user_data = [:];
          
          def userData = ctx._xml.Event.UserData;
          
          // UserData can have various nested structures
          for (entry in userData.entrySet()) {
            if (entry.getValue() instanceof Map) {
              for (subEntry in entry.getValue().entrySet()) {
                if (subEntry.getValue() != null) {
                  ctx.winlog.user_data[subEntry.getKey()] = subEntry.getValue().toString();
                }
              }
            }
          }
        """
      }
    },
    {
      "set": {
        "description": "Set host.name from computer_name",
        "field": "host.name",
        "value": "{{{winlog.computer_name}}}",
        "if": "ctx.winlog?.computer_name != null"
      }
    },
    {
      "set": {
        "description": "Set event.code",
        "field": "event.code",
        "value": "{{{winlog.event_id}}}",
        "if": "ctx.winlog?.event_id != null"
      }
    },
    {
      "set": {
        "description": "Set event.provider",
        "field": "event.provider",
        "value": "{{{winlog.provider_name}}}",
        "if": "ctx.winlog?.provider_name != null"
      }
    },
    {
      "set": {
        "field": "event.kind",
        "value": "event"
      }
    },
    {
      "set": {
        "field": "event.module",
        "value": "windows"
      }
    },
    {
      "date": {
        "description": "Parse timestamp from TimeCreated",
        "field": "winlog.time_created",
        "target_field": "@timestamp",
        "formats": [
          "yyyy-MM-dd'T'HH:mm:ss.SSSSSSSSS'Z'",
          "yyyy-MM-dd'T'HH:mm:ss.SSSSSS'Z'",
          "yyyy-MM-dd'T'HH:mm:ss.SSS'Z'",
          "yyyy-MM-dd'T'HH:mm:ss'Z'",
          "ISO8601"
        ],
        "if": "ctx.winlog?.time_created != null",
        "ignore_failure": true
      }
    },
    {
      "script": {
        "description": "Map common Security event fields to ECS",
        "lang": "painless",
        "ignore_failure": true,
        "source": """
          if (ctx.winlog?.event_data == null) {
            return;
          }
          
          def ed = ctx.winlog.event_data;
          
          // Initialize objects as needed
          if (ctx.user == null) ctx.user = [:];
          if (ctx.source == null) ctx.source = [:];
          if (ctx.process == null) ctx.process = [:];
          if (ctx.related == null) ctx.related = [:];
          
          // User fields (Target user is primary for logon events)
          if (ed.TargetUserName != null && ed.TargetUserName != '-' && ed.TargetUserName != '') {
            ctx.user.name = ed.TargetUserName;
            ctx.user.id = ed.TargetUserSid;
            ctx.user.domain = ed.TargetDomainName;
            
            // Build related.user array
            def relatedUsers = [];
            relatedUsers.add(ed.TargetUserName);
            if (ed.SubjectUserName != null && ed.SubjectUserName != '-' && ed.SubjectUserName != '') {
              relatedUsers.add(ed.SubjectUserName);
            }
            ctx.related.user = relatedUsers;
          } else if (ed.SubjectUserName != null && ed.SubjectUserName != '-' && ed.SubjectUserName != '') {
            ctx.user.name = ed.SubjectUserName;
            ctx.user.id = ed.SubjectUserSid;
            ctx.user.domain = ed.SubjectDomainName;
            ctx.related.user = [ed.SubjectUserName];
          }
          
          // Source IP (for network logons)
          if (ed.IpAddress != null && ed.IpAddress != '-' && ed.IpAddress != '') {
            ctx.source.ip = ed.IpAddress;
            if (ctx.related.ip == null) ctx.related.ip = [];
            ctx.related.ip.add(ed.IpAddress);
          }
          
          // Source port
          if (ed.IpPort != null && ed.IpPort != '-' && ed.IpPort != '0') {
            try {
              ctx.source.port = Integer.parseInt(ed.IpPort);
            } catch (Exception e) {}
          }
          
          // Workstation name
          if (ed.WorkstationName != null && ed.WorkstationName != '-' && ed.WorkstationName != '') {
            ctx.source.domain = ed.WorkstationName;
          }
          
          // Process fields
          if (ed.ProcessName != null && ed.ProcessName != '-') {
            ctx.process.executable = ed.ProcessName;
          }
          if (ed.ProcessId != null && ed.ProcessId != '0x0') {
            try {
              if (ed.ProcessId.startsWith('0x')) {
                ctx.process.pid = Integer.parseInt(ed.ProcessId.substring(2), 16);
              } else {
                ctx.process.pid = Integer.parseInt(ed.ProcessId);
              }
            } catch (Exception e) {}
          }
          if (ed.NewProcessName != null) {
            ctx.process.executable = ed.NewProcessName;
          }
          if (ed.NewProcessId != null) {
            try {
              if (ed.NewProcessId.startsWith('0x')) {
                ctx.process.pid = Integer.parseInt(ed.NewProcessId.substring(2), 16);
              } else {
                ctx.process.pid = Integer.parseInt(ed.NewProcessId);
              }
            } catch (Exception e) {}
          }
          if (ed.CommandLine != null) {
            ctx.process.command_line = ed.CommandLine;
          }
          
          // Parent process
          if (ed.ParentProcessName != null) {
            if (ctx.process.parent == null) ctx.process.parent = [:];
            ctx.process.parent.executable = ed.ParentProcessName;
          }
        """
      }
    },
    {
      "script": {
        "description": "Set event.action and event.outcome for common Security events",
        "lang": "painless",
        "ignore_failure": true,
        "source": """
          if (ctx.winlog?.event_id == null || ctx.winlog?.channel != 'Security') {
            return;
          }
          
          def eventId = ctx.winlog.event_id.toString();
          
          // Initialize event object
          if (ctx.event == null) ctx.event = [:];
          
          // Event action and outcome mappings
          def actionMap = [
            // Logon events
            '4624': 'logged-in',
            '4625': 'logon-failed',
            '4634': 'logged-off',
            '4647': 'logged-off',
            '4648': 'explicit-credential-logon',
            '4672': 'assigned-special-privileges',
            '4768': 'kerberos-authentication-ticket-requested',
            '4769': 'kerberos-service-ticket-requested',
            '4770': 'kerberos-service-ticket-renewed',
            '4771': 'kerberos-preauth-failed',
            '4776': 'credential-validated',
            
            // Account management
            '4720': 'created-user-account',
            '4722': 'enabled-user-account',
            '4723': 'change-password-attempt',
            '4724': 'reset-password-attempt',
            '4725': 'disabled-user-account',
            '4726': 'deleted-user-account',
            '4727': 'created-security-group',
            '4728': 'added-member-to-security-group',
            '4729': 'removed-member-from-security-group',
            '4730': 'deleted-security-group',
            '4731': 'created-security-group',
            '4732': 'added-member-to-security-group',
            '4733': 'removed-member-from-security-group',
            '4734': 'deleted-security-group',
            '4735': 'modified-security-group',
            '4737': 'modified-security-group',
            '4738': 'modified-user-account',
            '4740': 'locked-out-user-account',
            '4741': 'created-computer-account',
            '4742': 'modified-computer-account',
            '4743': 'deleted-computer-account',
            '4754': 'created-security-group',
            '4755': 'modified-security-group',
            '4756': 'added-member-to-security-group',
            '4757': 'removed-member-from-security-group',
            '4758': 'deleted-security-group',
            
            // Process events
            '4688': 'created-process',
            '4689': 'terminated-process',
            
            // Object access
            '4656': 'requested-handle-to-object',
            '4658': 'closed-handle-to-object',
            '4660': 'deleted-object',
            '4661': 'requested-handle-to-object',
            '4662': 'operation-performed-on-object',
            '4663': 'attempted-to-access-object',
            '4670': 'changed-permissions-on-object',
            
            // Policy changes
            '4719': 'changed-audit-policy',
            '4739': 'changed-domain-policy',
            '4817': 'changed-auditing-settings',
            
            // Service events
            '4697': 'service-installed',
            
            // Scheduled tasks
            '4698': 'scheduled-task-created',
            '4699': 'scheduled-task-deleted',
            '4700': 'scheduled-task-enabled',
            '4701': 'scheduled-task-disabled',
            '4702': 'scheduled-task-updated'
          ];
          
          // Success events
          def successEvents = ['4624', '4634', '4647', '4648', '4672', '4720', '4722', '4724', '4725', '4726', 
                               '4727', '4728', '4729', '4730', '4731', '4732', '4733', '4734', '4735', '4737',
                               '4738', '4740', '4741', '4742', '4743', '4754', '4755', '4756', '4757', '4758',
                               '4688', '4689', '4656', '4658', '4660', '4661', '4662', '4663', '4670', '4697',
                               '4698', '4699', '4700', '4701', '4702', '4768', '4769', '4770', '4776'];
          
          // Failure events
          def failureEvents = ['4625', '4771'];
          
          if (actionMap.containsKey(eventId)) {
            ctx.event.action = actionMap.get(eventId);
          }
          
          if (successEvents.contains(eventId)) {
            ctx.event.outcome = 'success';
          } else if (failureEvents.contains(eventId)) {
            ctx.event.outcome = 'failure';
          }
          
          // Event category mappings
          def categoryMap = [
            '4624': ['authentication'],
            '4625': ['authentication'],
            '4634': ['authentication'],
            '4647': ['authentication'],
            '4648': ['authentication'],
            '4672': ['authentication'],
            '4768': ['authentication'],
            '4769': ['authentication'],
            '4770': ['authentication'],
            '4771': ['authentication'],
            '4776': ['authentication'],
            '4720': ['iam'],
            '4722': ['iam'],
            '4723': ['iam'],
            '4724': ['iam'],
            '4725': ['iam'],
            '4726': ['iam'],
            '4738': ['iam'],
            '4740': ['iam'],
            '4741': ['iam'],
            '4742': ['iam'],
            '4743': ['iam'],
            '4727': ['iam'],
            '4728': ['iam'],
            '4729': ['iam'],
            '4730': ['iam'],
            '4731': ['iam'],
            '4732': ['iam'],
            '4733': ['iam'],
            '4734': ['iam'],
            '4735': ['iam'],
            '4737': ['iam'],
            '4754': ['iam'],
            '4755': ['iam'],
            '4756': ['iam'],
            '4757': ['iam'],
            '4758': ['iam'],
            '4688': ['process'],
            '4689': ['process'],
            '4697': ['configuration'],
            '4698': ['configuration'],
            '4699': ['configuration'],
            '4700': ['configuration'],
            '4701': ['configuration'],
            '4702': ['configuration']
          ];
          
          if (categoryMap.containsKey(eventId)) {
            ctx.event.category = categoryMap.get(eventId);
          }
          
          // Event type mappings  
          def typeMap = [
            '4624': ['start'],
            '4625': ['start'],
            '4634': ['end'],
            '4647': ['end'],
            '4648': ['start'],
            '4672': ['info'],
            '4768': ['start'],
            '4769': ['start'],
            '4770': ['start'],
            '4771': ['start'],
            '4776': ['info'],
            '4720': ['creation', 'user'],
            '4722': ['change', 'user'],
            '4723': ['change', 'user'],
            '4724': ['change', 'user'],
            '4725': ['change', 'user'],
            '4726': ['deletion', 'user'],
            '4738': ['change', 'user'],
            '4740': ['change', 'user'],
            '4741': ['creation'],
            '4742': ['change'],
            '4743': ['deletion'],
            '4727': ['creation', 'group'],
            '4728': ['change', 'group'],
            '4729': ['change', 'group'],
            '4730': ['deletion', 'group'],
            '4731': ['creation', 'group'],
            '4732': ['change', 'group'],
            '4733': ['change', 'group'],
            '4734': ['deletion', 'group'],
            '4735': ['change', 'group'],
            '4737': ['change', 'group'],
            '4754': ['creation', 'group'],
            '4755': ['change', 'group'],
            '4756': ['change', 'group'],
            '4757': ['change', 'group'],
            '4758': ['deletion', 'group'],
            '4688': ['start'],
            '4689': ['end'],
            '4697': ['creation'],
            '4698': ['creation'],
            '4699': ['deletion'],
            '4700': ['change'],
            '4701': ['change'],
            '4702': ['change']
          ];
          
          if (typeMap.containsKey(eventId)) {
            ctx.event.type = typeMap.get(eventId);
          }
        """
      }
    },
    {
      "script": {
        "description": "Map Logon Type to human readable value",
        "lang": "painless",
        "ignore_failure": true,
        "source": """
          if (ctx.winlog?.event_data?.LogonType == null) {
            return;
          }
          
          def logonTypeMap = [
            '0': 'System',
            '2': 'Interactive',
            '3': 'Network',
            '4': 'Batch',
            '5': 'Service',
            '7': 'Unlock',
            '8': 'NetworkCleartext',
            '9': 'NewCredentials',
            '10': 'RemoteInteractive',
            '11': 'CachedInteractive',
            '12': 'CachedRemoteInteractive',
            '13': 'CachedUnlock'
          ];
          
          def logonType = ctx.winlog.event_data.LogonType.toString();
          
          if (ctx.winlog.logon == null) ctx.winlog.logon = [:];
          ctx.winlog.logon.type = logonTypeMap.getOrDefault(logonType, 'Unknown');
          
          // Also set as string in logon.id
          if (ctx.winlog.event_data.TargetLogonId != null) {
            ctx.winlog.logon.id = ctx.winlog.event_data.TargetLogonId;
          }
        """
      }
    },
    {
      "script": {
        "description": "Handle Sysmon events",
        "lang": "painless",
        "ignore_failure": true,
        "source": """
          if (ctx.winlog?.channel != 'Microsoft-Windows-Sysmon/Operational') {
            return;
          }
          
          if (ctx.event == null) ctx.event = [:];
          ctx.event.module = 'sysmon';
          ctx.event.category = ['process'];
          
          def eventId = ctx.winlog?.event_id?.toString();
          
          // Sysmon event mappings
          def sysmonActions = [
            '1': 'Process Create',
            '2': 'File creation time changed',
            '3': 'Network connection detected',
            '4': 'Sysmon service state changed',
            '5': 'Process terminated',
            '6': 'Driver loaded',
            '7': 'Image loaded',
            '8': 'CreateRemoteThread detected',
            '9': 'RawAccessRead detected',
            '10': 'Process accessed',
            '11': 'File created',
            '12': 'Registry object added or deleted',
            '13': 'Registry value set',
            '14': 'Registry object renamed',
            '15': 'File stream created',
            '16': 'Sysmon config state changed',
            '17': 'Named pipe created',
            '18': 'Named pipe connected',
            '19': 'WMI filter',
            '20': 'WMI consumer',
            '21': 'WMI consumer filter',
            '22': 'DNS query',
            '23': 'File Delete archived',
            '24': 'Clipboard changed',
            '25': 'Process tampering',
            '26': 'File Delete logged'
          ];
          
          if (sysmonActions.containsKey(eventId)) {
            ctx.event.action = sysmonActions.get(eventId);
          }
        """
      }
    },
    {
      "remove": {
        "description": "Clean up temporary fields",
        "field": ["_xml", "_dataId", "winlog.time_created"],
        "ignore_failure": true,
        "ignore_missing": true
      }
    }
  ],
  "on_failure": [
    {
      "set": {
        "field": "error.message",
        "value": "Processor {{ _ingest.on_failure_processor_type }} with tag {{ _ingest.on_failure_processor_tag }} failed: {{ _ingest.on_failure_message }}"
      }
    }
  ]
}
```

---

## Step 2: Update the Cribl Routing Pipeline

Update the `logs-cribl-default@custom` pipeline to use the parser before routing:

```
PUT _ingest/pipeline/logs-cribl-default@custom
{
  "description": "Parse and route Cribl data to appropriate data streams",
  "processors": [
    {
      "pipeline": {
        "name": "cribl-winlog-xml-parser",
        "description": "Parse Windows Event XML to Elastic Agent format",
        "if": "ctx?._dataId == 'winlog' && ctx?.message != null && ctx.message.contains('<Event')"
      }
    },
    {
      "reroute": {
        "tag": "route-to-security",
        "description": "Route Security channel events to System integration",
        "if": "ctx?.winlog?.channel == 'Security'",
        "destination": "logs-system.security-default"
      }
    },
    {
      "reroute": {
        "tag": "route-to-sysmon",
        "description": "Route Sysmon events to Windows integration",
        "if": "ctx?.winlog?.channel == 'Microsoft-Windows-Sysmon/Operational'",
        "destination": "logs-windows.sysmon_operational-default"
      }
    },
    {
      "reroute": {
        "tag": "route-to-powershell",
        "description": "Route PowerShell events to Windows integration",
        "if": "ctx?.winlog?.channel != null && ctx.winlog.channel.contains('PowerShell')",
        "destination": "logs-windows.powershell_operational-default"
      }
    },
    {
      "reroute": {
        "tag": "route-to-application",
        "description": "Route Application channel events to System integration",
        "if": "ctx?.winlog?.channel == 'Application'",
        "destination": "logs-system.application-default"
      }
    },
    {
      "reroute": {
        "tag": "route-to-system",
        "description": "Route System channel events to System integration",
        "if": "ctx?.winlog?.channel == 'System'",
        "destination": "logs-system.system-default"
      }
    }
  ]
}
```

---

## Step 3: Ensure Required Integrations Are Installed

For the routing to work, you need to install the integration assets in Kibana:

1. Go to **Management → Integrations**
2. Search for and install:
   - **System** integration (for Security, Application, System logs)
   - **Windows** integration (for Sysmon, PowerShell logs)
3. For each, go to **Settings → Install assets**

---

## Step 4: Configure Cribl

### Destination Settings

| Setting | Value |
|---------|-------|
| **Index or Data Stream** | `logs-cribl-default` |
| **API Key** | Base64-encoded Elastic API key |

### API Key Permissions

```
{
  "indices": [
    {
      "names": ["logs-*"],
      "privileges": ["auto_configure", "create_doc", "write"]
    }
  ]
}
```

### Set the `_dataId` Field

In your Cribl pipeline, add an **Eval** function:

```javascript
_dataId = 'winlog'
```

---

## Testing

### Test the Parser Directly

```
POST _ingest/pipeline/cribl-winlog-xml-parser/_simulate
{
  "docs": [
    {
      "_source": {
        "@timestamp": "2025-12-04T10:00:00.000Z",
        "_dataId": "winlog",
        "message": "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Security-Auditing' Guid='{54849625-5478-4994-a5ba-3e3b0328c30d}'/><EventID>4624</EventID><Version>2</Version><Level>0</Level><Task>12544</Task><Opcode>0</Opcode><Keywords>0x8020000000000000</Keywords><TimeCreated SystemTime='2025-12-04T10:00:00.1234567Z'/><EventRecordID>123456789</EventRecordID><Correlation ActivityID='{00000000-0000-0000-0000-000000000000}'/><Execution ProcessID='888' ThreadID='999'/><Channel>Security</Channel><Computer>DC01.corp.example.com</Computer><Security/></System><EventData><Data Name='SubjectUserSid'>S-1-5-18</Data><Data Name='SubjectUserName'>DC01$</Data><Data Name='SubjectDomainName'>CORP</Data><Data Name='SubjectLogonId'>0x3e7</Data><Data Name='TargetUserSid'>S-1-5-21-1234567890-1234567890-1234567890-1001</Data><Data Name='TargetUserName'>admin</Data><Data Name='TargetDomainName'>CORP</Data><Data Name='TargetLogonId'>0x12345678</Data><Data Name='LogonType'>3</Data><Data Name='LogonProcessName'>NtLmSsp</Data><Data Name='AuthenticationPackageName'>NTLM</Data><Data Name='WorkstationName'>WORKSTATION01</Data><Data Name='LogonGuid'>{00000000-0000-0000-0000-000000000000}</Data><Data Name='TransmittedServices'>-</Data><Data Name='LmPackageName'>NTLM V2</Data><Data Name='KeyLength'>128</Data><Data Name='ProcessId'>0x0</Data><Data Name='ProcessName'>-</Data><Data Name='IpAddress'>192.168.1.100</Data><Data Name='IpPort'>49152</Data><Data Name='ImpersonationLevel'>%%1833</Data><Data Name='RestrictedAdminMode'>-</Data><Data Name='TargetOutboundUserName'>-</Data><Data Name='TargetOutboundDomainName'>-</Data><Data Name='VirtualAccount'>%%1843</Data><Data Name='TargetLinkedLogonId'>0x0</Data><Data Name='ElevatedToken'>%%1842</Data></EventData></Event>"
      }
    }
  ]
}
```

### Expected Output

The simulated output should include:

```
{
  "@timestamp": "2025-12-04T10:00:00.123Z",
  "event": {
    "code": "4624",
    "action": "logged-in",
    "outcome": "success",
    "category": ["authentication"],
    "type": ["start"],
    "kind": "event",
    "module": "windows",
    "provider": "Microsoft-Windows-Security-Auditing",
    "original": "<Event>...</Event>"
  },
  "winlog": {
    "channel": "Security",
    "event_id": "4624",
    "provider_name": "Microsoft-Windows-Security-Auditing",
    "computer_name": "DC01.corp.example.com",
    "record_id": "123456789",
    "process": {
      "pid": 888,
      "thread": { "id": 999 }
    },
    "logon": {
      "type": "Network",
      "id": "0x12345678"
    },
    "event_data": {
      "TargetUserName": "admin",
      "TargetDomainName": "CORP",
      "LogonType": "3",
      "IpAddress": "192.168.1.100",
      "IpPort": "49152"
    }
  },
  "user": {
    "name": "admin",
    "domain": "CORP",
    "id": "S-1-5-21-1234567890-1234567890-1234567890-1001"
  },
  "source": {
    "ip": "192.168.1.100",
    "port": 49152,
    "domain": "WORKSTATION01"
  },
  "host": {
    "name": "DC01.corp.example.com"
  },
  "related": {
    "ip": ["192.168.1.100"],
    "user": ["admin", "DC01$"]
  }
}
```

### Send Test Data via Cribl Path

```
POST logs-cribl-default/_doc
{
  "@timestamp": "2025-12-04T10:00:00.000Z",
  "_dataId": "winlog",
  "message": "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Security-Auditing' Guid='{54849625-5478-4994-a5ba-3e3b0328c30d}'/><EventID>4624</EventID><Version>2</Version><Level>0</Level><Task>12544</Task><Opcode>0</Opcode><Keywords>0x8020000000000000</Keywords><TimeCreated SystemTime='2025-12-04T10:00:00.1234567Z'/><EventRecordID>123456789</EventRecordID><Correlation/><Execution ProcessID='888' ThreadID='999'/><Channel>Security</Channel><Computer>DC01.corp.example.com</Computer><Security/></System><EventData><Data Name='SubjectUserSid'>S-1-5-18</Data><Data Name='SubjectUserName'>DC01$</Data><Data Name='SubjectDomainName'>CORP</Data><Data Name='SubjectLogonId'>0x3e7</Data><Data Name='TargetUserSid'>S-1-5-21-1234567890-1234567890-1234567890-1001</Data><Data Name='TargetUserName'>admin</Data><Data Name='TargetDomainName'>CORP</Data><Data Name='TargetLogonId'>0x12345678</Data><Data Name='LogonType'>3</Data><Data Name='LogonProcessName'>NtLmSsp</Data><Data Name='AuthenticationPackageName'>NTLM</Data><Data Name='WorkstationName'>WORKSTATION01</Data><Data Name='LogonGuid'>{00000000-0000-0000-0000-000000000000}</Data><Data Name='TransmittedServices'>-</Data><Data Name='LmPackageName'>NTLM V2</Data><Data Name='KeyLength'>128</Data><Data Name='ProcessId'>0x0</Data><Data Name='ProcessName'>-</Data><Data Name='IpAddress'>192.168.1.100</Data><Data Name='IpPort'>49152</Data></EventData></Event>"
}
```

### Verify Data in Correct Data Stream

```
GET logs-system.security-default/_search
{
  "size": 1,
  "sort": [{"@timestamp": "desc"}],
  "query": {
    "term": { "event.code": "4624" }
  }
}
```

---

## Supported Event Mappings

### Security Events

| Event ID | event.action | event.outcome | event.category |
|----------|--------------|---------------|----------------|
| 4624 | logged-in | success | authentication |
| 4625 | logon-failed | failure | authentication |
| 4634 | logged-off | success | authentication |
| 4648 | explicit-credential-logon | success | authentication |
| 4672 | assigned-special-privileges | success | authentication |
| 4688 | created-process | success | process |
| 4689 | terminated-process | success | process |
| 4720 | created-user-account | success | iam |
| 4726 | deleted-user-account | success | iam |
| 4728 | added-member-to-security-group | success | iam |
| 4768 | kerberos-authentication-ticket-requested | success | authentication |
| 4769 | kerberos-service-ticket-requested | success | authentication |
| 4771 | kerberos-preauth-failed | failure | authentication |

### Sysmon Events

| Event ID | event.action |
|----------|--------------|
| 1 | Process Create |
| 3 | Network connection detected |
| 5 | Process terminated |
| 7 | Image loaded |
| 10 | Process accessed |
| 11 | File created |
| 12-14 | Registry events |
| 22 | DNS query |

### Logon Types

| Value | winlog.logon.type |
|-------|-------------------|
| 2 | Interactive |
| 3 | Network |
| 4 | Batch |
| 5 | Service |
| 7 | Unlock |
| 10 | RemoteInteractive |
| 11 | CachedInteractive |

---

## Cleanup

```
DELETE _ingest/pipeline/cribl-winlog-xml-parser
DELETE _ingest/pipeline/logs-cribl-default@custom
```

---

## Compatibility Notes

This parser produces output that is compatible with:

- ✅ Elastic Security detection rules
- ✅ Windows/System integration dashboards
- ✅ SIEM app correlation
- ✅ `event.action`, `event.outcome` filtering
- ✅ `related.user`, `related.ip` enrichment
- ✅ `winlog.logon.type` human-readable values

Some advanced features from Elastic Agent that require additional work:
- ⚠️ Full `message` field recreation (Elastic Agent builds a human-readable message)
- ⚠️ `ecs.version` field population
- ⚠️ `agent.*` fields (would need to be faked or set via Cribl)