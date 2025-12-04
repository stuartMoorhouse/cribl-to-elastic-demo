# Windows Event XML Parser for Cribl Integration

This ingest pipeline converts raw Windows Event XML (as received from Cribl) into the format that Elastic Agent produces, enabling full compatibility with the Windows/System integration's enrichment pipelines and Elastic Security detection rules.

## Overview

When Elastic Agent collects Windows events, it:
1. Reads from the Windows Event Log API
2. Parses the XML into structured JSON fields (`winlog.*`)
3. Maps common fields to ECS (`user.*`, `source.*`, `process.*`, etc.)

This pipeline replicates that process for raw XML data arriving via Cribl using **only processors available on all Elasticsearch licenses** (script, set, date, remove).

## Installation

Run these commands in Kibana Dev Console in order.

---

## Step 1: Create the XML Parser Pipeline

This pipeline uses Painless regex to parse Windows Event XML:

```
PUT _ingest/pipeline/cribl-winlog-xml-parser
{
  "description": "Convert raw Windows Event XML to Elastic Agent format for Windows integration compatibility",
  "processors": [
    {
      "set": {
        "description": "Preserve original message",
        "field": "event.original",
        "copy_from": "message",
        "if": "ctx.message != null"
      }
    },
    {
      "script": {
        "description": "Extract System fields from Windows Event XML using regex",
        "lang": "painless",
        "ignore_failure": false,
        "source": """
          if (ctx.message == null) {
            throw new Exception('No message field');
          }
          
          String xml = ctx.message;
          ctx.winlog = [:];
          ctx.winlog.api = 'wineventlog';
          
          // Helper function to extract XML attribute or element
          // Pattern: Name='value' or <n>value</n>
          
          // Provider Name
          def providerMatch = /Provider Name='([^']*)'/.matcher(xml);
          if (providerMatch.find()) {
            ctx.winlog.provider_name = providerMatch.group(1);
          }
          
          // Provider Guid
          def guidMatch = /Guid='\{?([^}']*)\}?'/.matcher(xml);
          if (guidMatch.find()) {
            ctx.winlog.provider_guid = '{' + guidMatch.group(1) + '}';
          }
          
          // EventID - handle both <EventID>123</EventID> and <EventID Qualifiers='0'>123</EventID>
          def eventIdMatch = /<EventID[^>]*>(\d+)<\/EventID>/.matcher(xml);
          if (eventIdMatch.find()) {
            ctx.winlog.event_id = eventIdMatch.group(1);
          }
          
          // Version
          def versionMatch = /<Version>(\d+)<\/Version>/.matcher(xml);
          if (versionMatch.find()) {
            ctx.winlog.version = versionMatch.group(1);
          }
          
          // Level
          def levelMatch = /<Level>(\d+)<\/Level>/.matcher(xml);
          if (levelMatch.find()) {
            def levelNum = levelMatch.group(1);
            def levelMap = ['0': 'Information', '1': 'Critical', '2': 'Error', '3': 'Warning', '4': 'Information', '5': 'Verbose'];
            ctx.winlog.level = levelMap.getOrDefault(levelNum, 'Information');
          }
          
          // Task
          def taskMatch = /<Task>(\d+)<\/Task>/.matcher(xml);
          if (taskMatch.find()) {
            ctx.winlog.task = taskMatch.group(1);
          }
          
          // Opcode
          def opcodeMatch = /<Opcode>(\d+)<\/Opcode>/.matcher(xml);
          if (opcodeMatch.find()) {
            ctx.winlog.opcode = opcodeMatch.group(1);
          }
          
          // Keywords
          def keywordsMatch = /<Keywords>([^<]+)<\/Keywords>/.matcher(xml);
          if (keywordsMatch.find()) {
            ctx.winlog.keywords = [keywordsMatch.group(1)];
          }
          
          // TimeCreated
          def timeMatch = /TimeCreated SystemTime='([^']+)'/.matcher(xml);
          if (timeMatch.find()) {
            ctx.winlog.time_created = timeMatch.group(1);
          }
          
          // EventRecordID
          def recordMatch = /<EventRecordID>(\d+)<\/EventRecordID>/.matcher(xml);
          if (recordMatch.find()) {
            ctx.winlog.record_id = recordMatch.group(1);
          }
          
          // Correlation ActivityID
          def activityMatch = /ActivityID='\{?([^}']+)\}?'/.matcher(xml);
          if (activityMatch.find()) {
            ctx.winlog.activity_id = '{' + activityMatch.group(1) + '}';
          }
          
          // Execution ProcessID and ThreadID
          def execMatch = /Execution ProcessID='(\d+)' ThreadID='(\d+)'/.matcher(xml);
          if (execMatch.find()) {
            ctx.winlog.process = [:];
            ctx.winlog.process.pid = Integer.parseInt(execMatch.group(1));
            ctx.winlog.process.thread = [:];
            ctx.winlog.process.thread.id = Integer.parseInt(execMatch.group(2));
          }
          
          // Channel
          def channelMatch = /<Channel>([^<]+)<\/Channel>/.matcher(xml);
          if (channelMatch.find()) {
            ctx.winlog.channel = channelMatch.group(1);
          }
          
          // Computer
          def computerMatch = /<Computer>([^<]+)<\/Computer>/.matcher(xml);
          if (computerMatch.find()) {
            ctx.winlog.computer_name = computerMatch.group(1);
          }
          
          // Security UserID
          def securityMatch = /Security UserID='([^']+)'/.matcher(xml);
          if (securityMatch.find()) {
            ctx.winlog.user = [:];
            ctx.winlog.user.identifier = securityMatch.group(1);
          }
        """
      }
    },
    {
      "script": {
        "description": "Extract EventData fields using regex",
        "lang": "painless",
        "ignore_failure": true,
        "source": """
          if (ctx.message == null) {
            return;
          }
          
          String xml = ctx.message;
          ctx.winlog.event_data = [:];
          
          // Match all <Data Name='X'>Y</Data> patterns
          // Using a loop to find all matches
          def pattern = /<Data Name='([^']+)'>([^<]*)<\/Data>/;
          def matcher = pattern.matcher(xml);
          
          while (matcher.find()) {
            def name = matcher.group(1);
            def value = matcher.group(2);
            if (value != null && value.length() > 0) {
              ctx.winlog.event_data[name] = value;
            }
          }
          
          // Also check for empty Data elements (self-closing or empty)
          // <Data Name='X'/> or <Data Name='X'></Data>
        """
      }
    },
    {
      "script": {
        "description": "Extract UserData fields (for events that use UserData instead of EventData)",
        "lang": "painless",
        "ignore_failure": true,
        "source": """
          if (ctx.message == null || (ctx.winlog?.event_data != null && ctx.winlog.event_data.size() > 0)) {
            return;
          }
          
          String xml = ctx.message;
          
          // Check if there's a UserData section
          if (!xml.contains('<UserData>')) {
            return;
          }
          
          ctx.winlog.user_data = [:];
          
          // Extract UserData content - generic pattern for nested elements
          // This handles structures like <UserData><EventXML><Field>Value</Field></EventXML></UserData>
          def pattern = /<([A-Za-z][A-Za-z0-9_]*)>([^<]+)<\/\1>/;
          def matcher = pattern.matcher(xml);
          
          while (matcher.find()) {
            def name = matcher.group(1);
            def value = matcher.group(2);
            // Skip known container elements
            if (name != 'UserData' && name != 'EventData' && name != 'System' && name != 'Event' && value != null && value.trim().length() > 0) {
              ctx.winlog.user_data[name] = value.trim();
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
            def relatedUsers = new ArrayList();
            relatedUsers.add(ed.TargetUserName);
            if (ed.SubjectUserName != null && ed.SubjectUserName != '-' && ed.SubjectUserName != '') {
              relatedUsers.add(ed.SubjectUserName);
            }
            ctx.related.user = relatedUsers;
          } else if (ed.SubjectUserName != null && ed.SubjectUserName != '-' && ed.SubjectUserName != '') {
            ctx.user.name = ed.SubjectUserName;
            ctx.user.id = ed.SubjectUserSid;
            ctx.user.domain = ed.SubjectDomainName;
            def relatedUsers = new ArrayList();
            relatedUsers.add(ed.SubjectUserName);
            ctx.related.user = relatedUsers;
          }
          
          // Source IP (for network logons)
          if (ed.IpAddress != null && ed.IpAddress != '-' && ed.IpAddress != '') {
            ctx.source.ip = ed.IpAddress;
            if (ctx.related.ip == null) ctx.related.ip = new ArrayList();
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
          if (ctx.winlog?.event_id == null) {
            return;
          }
          
          def eventId = ctx.winlog.event_id.toString();
          def channel = ctx.winlog?.channel;
          
          // Initialize event object
          if (ctx.event == null) ctx.event = [:];
          
          // Security channel events
          if (channel == 'Security') {
            // Event action mappings
            def actionMap = [
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
              '4688': 'created-process',
              '4689': 'terminated-process',
              '4656': 'requested-handle-to-object',
              '4658': 'closed-handle-to-object',
              '4660': 'deleted-object',
              '4661': 'requested-handle-to-object',
              '4662': 'operation-performed-on-object',
              '4663': 'attempted-to-access-object',
              '4670': 'changed-permissions-on-object',
              '4719': 'changed-audit-policy',
              '4739': 'changed-domain-policy',
              '4817': 'changed-auditing-settings',
              '4697': 'service-installed',
              '4698': 'scheduled-task-created',
              '4699': 'scheduled-task-deleted',
              '4700': 'scheduled-task-enabled',
              '4701': 'scheduled-task-disabled',
              '4702': 'scheduled-task-updated'
            ];
            
            if (actionMap.containsKey(eventId)) {
              ctx.event.action = actionMap.get(eventId);
            }
            
            // Failure events
            def failureEvents = ['4625', '4771', '4772', '4773', '4774', '4775'];
            
            if (failureEvents.contains(eventId)) {
              ctx.event.outcome = 'failure';
            } else if (actionMap.containsKey(eventId)) {
              ctx.event.outcome = 'success';
            }
            
            // Event category mappings
            def authEvents = ['4624', '4625', '4634', '4647', '4648', '4672', '4768', '4769', '4770', '4771', '4776'];
            def iamEvents = ['4720', '4722', '4723', '4724', '4725', '4726', '4727', '4728', '4729', '4730', '4731', '4732', '4733', '4734', '4735', '4737', '4738', '4740', '4741', '4742', '4743', '4754', '4755', '4756', '4757', '4758'];
            def processEvents = ['4688', '4689'];
            def configEvents = ['4697', '4698', '4699', '4700', '4701', '4702'];
            
            if (authEvents.contains(eventId)) {
              ctx.event.category = ['authentication'];
            } else if (iamEvents.contains(eventId)) {
              ctx.event.category = ['iam'];
            } else if (processEvents.contains(eventId)) {
              ctx.event.category = ['process'];
            } else if (configEvents.contains(eventId)) {
              ctx.event.category = ['configuration'];
            }
            
            // Event type mappings
            def startEvents = ['4624', '4625', '4648', '4768', '4769', '4770', '4771', '4688'];
            def endEvents = ['4634', '4647', '4689'];
            
            if (startEvents.contains(eventId)) {
              ctx.event.type = ['start'];
            } else if (endEvents.contains(eventId)) {
              ctx.event.type = ['end'];
            }
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
          ctx.winlog.logon.type = logonTypeMap.getOrDefault(logonType, 'Unknown (' + logonType + ')');
          
          // Also set logon.id
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
            '26': 'File Delete logged',
            '27': 'File Block Executable',
            '28': 'File Block Shredding',
            '29': 'File Executable Detected'
          ];
          
          if (sysmonActions.containsKey(eventId)) {
            ctx.event.action = sysmonActions.get(eventId);
          }
          
          // Set categories based on event type
          def processEvents = ['1', '5', '6', '7', '8', '10', '25'];
          def networkEvents = ['3', '22'];
          def fileEvents = ['2', '11', '15', '23', '26', '27', '28', '29'];
          def registryEvents = ['12', '13', '14'];
          
          if (processEvents.contains(eventId)) {
            ctx.event.category = ['process'];
          } else if (networkEvents.contains(eventId)) {
            ctx.event.category = ['network'];
          } else if (fileEvents.contains(eventId)) {
            ctx.event.category = ['file'];
          } else if (registryEvents.contains(eventId)) {
            ctx.event.category = ['registry'];
          }
        """
      }
    },
    {
      "script": {
        "description": "Handle PowerShell events",
        "lang": "painless",
        "ignore_failure": true,
        "source": """
          def channel = ctx.winlog?.channel;
          if (channel == null || !channel.contains('PowerShell')) {
            return;
          }
          
          if (ctx.event == null) ctx.event = [:];
          ctx.event.module = 'powershell';
          ctx.event.category = ['process'];
          
          def eventId = ctx.winlog?.event_id?.toString();
          
          def powershellActions = [
            '400': 'Engine Started',
            '403': 'Engine Stopped',
            '600': 'Provider Started',
            '800': 'Pipeline Execution Details',
            '4103': 'Module Logging',
            '4104': 'Script Block Logging',
            '4105': 'Script Block Invocation Start',
            '4106': 'Script Block Invocation End'
          ];
          
          if (powershellActions.containsKey(eventId)) {
            ctx.event.action = powershellActions.get(eventId);
          }
        """
      }
    },
    {
      "remove": {
        "description": "Clean up temporary fields",
        "field": ["_dataId", "winlog.time_created"],
        "ignore_failure": true,
        "ignore_missing": true
      }
    }
  ],
  "on_failure": [
    {
      "set": {
        "field": "error.message",
        "value": "Pipeline failed at processor [{{ _ingest.on_failure_processor_type }}]: {{ _ingest.on_failure_message }}"
      }
    },
    {
      "set": {
        "field": "event.kind",
        "value": "pipeline_error"
      }
    }
  ]
}
```

---

## Step 2: Create the Cribl Routing Pipeline

This routes incoming Cribl data through the parser and to the correct data streams:

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

## Step 3: Testing

### Test with Your Sample Event (4662)

```
POST _ingest/pipeline/cribl-winlog-xml-parser/_simulate
{
  "docs": [
    {
      "_source": {
        "@timestamp": "2025-12-04T09:23:56.834Z",
        "_dataId": "winlog",
        "message": "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Security-Auditing' Guid='{54849625-5478-4994-A5BA-3E3B0328C30D}'/><EventID>4662</EventID><Version>0</Version><Level>0</Level><Task>14080</Task><Opcode>0</Opcode><Keywords>0x8020000000000000</Keywords><TimeCreated SystemTime='2025-12-04T09:23:56.8347053Z'/><EventRecordID>25912222</EventRecordID><Correlation ActivityID='{96DCEF1A-40CF-0002-02F0-DC96CF40DB01}'/><Execution ProcessID='772' ThreadID='5780'/><Channel>Security</Channel><Computer>dc-yourdc.ad.yourdc.org</Computer><Security/></System><EventData><Data Name='SubjectUserSid'>S-1-5-21-1234567890-1234567890-1234567890-12345</Data><Data Name='SubjectUserName'>youruser$</Data><Data Name='SubjectDomainName'>YOURDC</Data><Data Name='SubjectLogonId'>0x3e7</Data><Data Name='ObjectServer'>DS</Data><Data Name='ObjectType'>%{19195a5b-6da0-11d0-afd3-00c04fd930c9}</Data><Data Name='ObjectName'>%{9b026da6-0d3c-465c-8bee-5199d7165cba}</Data><Data Name='OperationType'>Object Access</Data><Data Name='HandleId'>0x0</Data><Data Name='AccessList'>%%7688</Data><Data Name='AccessMask'>0x100</Data><Data Name='Properties'>%%7688</Data><Data Name='AdditionalInfo'>-</Data><Data Name='AdditionalInfo2'></Data></EventData></Event>"
      }
    }
  ]
}
```

### Test with a 4624 Logon Event

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

### Expected Output for 4624

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
    "provider": "Microsoft-Windows-Security-Auditing"
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

---

## Step 4: Configure Cribl

### Destination Settings

| Setting | Value |
|---------|-------|
| **Index or Data Stream** | `logs-cribl-default` |
| **API Key** | Base64-encoded Elastic API key |

### API Key Permissions

```
POST /_security/api_key
{
  "name": "cribl-winlog-ingestion",
  "role_descriptors": {
    "cribl_writer": {
      "cluster": ["monitor"],
      "indices": [
        {
          "names": ["logs-*"],
          "privileges": ["auto_configure", "create_doc", "write", "view_index_metadata"]
        }
      ]
    }
  }
}
```

### Set the `_dataId` Field in Cribl

In your Cribl pipeline, add an **Eval** function:

```javascript
_dataId = 'winlog'
```

Also ensure `message` is a string:

```javascript
message = typeof message === 'object' ? JSON.stringify(message) : message
```

---

## Step 5: Install Required Integration Assets

For routing to work, install the integration assets in Kibana:

1. Go to **Management → Integrations**
2. Search for and install:
   - **System** integration (for Security, Application, System logs)
   - **Windows** integration (for Sysmon, PowerShell logs)
3. For each, go to **Settings → Install assets**

---

## Supported Event Mappings

### Security Events

| Event ID | event.action | event.outcome | event.category |
|----------|--------------|---------------|----------------|
| 4624 | logged-in | success | authentication |
| 4625 | logon-failed | failure | authentication |
| 4634 | logged-off | success | authentication |
| 4648 | explicit-credential-logon | success | authentication |
| 4662 | operation-performed-on-object | success | - |
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

| Event ID | event.action | event.category |
|----------|--------------|----------------|
| 1 | Process Create | process |
| 3 | Network connection detected | network |
| 5 | Process terminated | process |
| 7 | Image loaded | process |
| 10 | Process accessed | process |
| 11 | File created | file |
| 12-14 | Registry events | registry |
| 22 | DNS query | network |

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

This parser produces output compatible with:

- ✅ Elastic Security detection rules
- ✅ Windows/System integration dashboards
- ✅ SIEM app correlation
- ✅ `event.action`, `event.outcome` filtering
- ✅ `related.user`, `related.ip` enrichment
- ✅ `winlog.logon.type` human-readable values
- ✅ All Elasticsearch license levels (no special plugins required)

## Processors Used

This pipeline uses only standard processors available on all Elasticsearch clusters:

| Processor | Purpose |
|-----------|---------|
| `set` | Copy and set field values |
| `script` | Painless regex parsing and field mapping |
| `date` | Parse timestamps |
| `remove` | Clean up temporary fields |
| `pipeline` | Call sub-pipelines |
| `reroute` | Route to different data streams |