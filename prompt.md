# Claude Code Prompt: Cribl-to-Elastic Demo Infrastructure

## Context

I need to demonstrate a log ingestion workflow where multiple log sources send data through Cribl Stream into an existing Elastic cluster. 

## Objective

Create Terraform configuration to deploy AWS infrastructure that demonstrates:

1. **Linux server** generating Auditd logs → forwarded to Cribl
2. **Windows server** generating Security Event logs → forwarded to Cribl  
3. **Fortinet log simulator** generating synthetic FortiGate-format syslog → sent to Cribl
4. **Cribl Stream** (free tier) receiving all logs and forwarding to my Elastic Agent endpoint

## Architecture

```
┌─────────────────────┐
│ Linux EC2 (Auditd)  │──┐
└─────────────────────┘  │
                         │    ┌─────────────────┐     ┌─────────────────────────┐
┌─────────────────────┐  │    │                 │     │                         │
│ Windows EC2         │──┼───▶│  Cribl Stream   │────▶│  Elastic Agent          │
│ (Security Events)   │  │    │  (EC2 - Free)   │     │  (Cribl Integration)    │
└─────────────────────┘  │    │                 │     │  [EXISTING - NOT BUILT] │
                         │    └─────────────────┘     └─────────────────────────┘
┌─────────────────────┐  │
│ Fortinet Simulator  │──┘
│ (Python on Linux)   │
└─────────────────────┘
```

## Requirements

### General

- All resources in a single AWS region (eu-north-1 preferred, or allow variable override)
- Use a dedicated VPC with public subnet for simplicity
- Security groups allowing necessary traffic between components
- Use t3.micro or t3.small instances where possible (cost optimization)
- Tag all resources with `Project = "cribl-elastic-demo"` and `Environment = "test"`
- Output all relevant connection information (IPs, URLs, credentials)

### Variables Required

```hcl
variable "elastic_agent_endpoint" {
  description = "URL of the Elastic Agent Cribl Integration endpoint (e.g., http://10.0.1.50:8080)"
  type        = string
}

variable "aws_region" {
  description = "AWS region for deployment"
  type        = string
  default     = "eu-north-1"
}

variable "ssh_public_key" {
  description = "SSH public key for EC2 access"
  type        = string
}

variable "allowed_ssh_cidr" {
  description = "CIDR block allowed to SSH (e.g., your IP)"
  type        = string
}

variable "windows_admin_password" {
  description = "Administrator password for Windows instance"
  type        = string
  sensitive   = true
}
```

### 1. Cribl Stream Server (Linux EC2)

**Instance**: t3.small (Cribl needs slightly more resources)  
**OS**: Ubuntu 22.04 LTS or Amazon Linux 2023

**User data / provisioning script should**:

1. Download and install Cribl Stream (free tier)
   ```bash
   curl -Lso - $(curl -s https://cdn.cribl.io/dl/latest) | tar zxvf -
   ```

2. Configure Cribl to start on boot

3. Create a syslog source listening on:
   - UDP 9514
   - TCP 9514

4. Create an HTTP destination pointing to `var.elastic_agent_endpoint`
   - Method: POST
   - Format: ndjson
   - Compression: gzip (if supported)

5. Create a basic passthrough route sending all syslog data to the Elastic destination

6. Output the Cribl admin URL and default credentials

**Security group**:
- Inbound: 9000 (Cribl UI), 9514 (syslog UDP/TCP), 22 (SSH from allowed CIDR)
- Outbound: All (needs to reach Elastic endpoint)

### 2. Linux Auditd Server (EC2)

**Instance**: t3.micro  
**OS**: Ubuntu 22.04 LTS or Amazon Linux 2023

**User data / provisioning script should**:

1. Install and enable auditd
   ```bash
   # Ubuntu
   apt-get update && apt-get install -y auditd audispd-plugins rsyslog
   
   # Amazon Linux
   yum install -y audit rsyslog
   ```

2. Configure basic audit rules:
   ```bash
   # /etc/audit/rules.d/demo.rules
   -w /etc/passwd -p wa -k identity
   -w /etc/shadow -p wa -k identity
   -w /etc/sudoers -p wa -k sudoers
   -a always,exit -F arch=b64 -S execve -k commands
   ```

3. Configure rsyslog to forward audit.log to Cribl:
   ```bash
   # /etc/rsyslog.d/50-audit-to-cribl.conf
   module(load="imfile")
   
   input(type="imfile"
         File="/var/log/audit/audit.log"
         Tag="auditd:"
         Severity="info"
         Facility="local6")
   
   local6.* @@CRIBL_PRIVATE_IP:9514
   ```

4. Restart services

5. Create a script at `/usr/local/bin/generate-audit-events.sh` that triggers various audit events for demo purposes:
   ```bash
   #!/bin/bash
   # Generate demo audit events
   cat /etc/passwd > /dev/null
   cat /etc/shadow 2>/dev/null || true
   sudo -l
   ls /root 2>/dev/null || true
   ```

**Security group**:
- Inbound: 22 (SSH from allowed CIDR)
- Outbound: 9514 to Cribl security group

### 3. Windows Security Events Server (EC2)

**Instance**: t3.small (Windows needs more resources)  
**OS**: Windows Server 2022 Base

**User data / provisioning script should**:

1. Enable PowerShell remoting for configuration

2. Enable advanced audit policies:
   ```powershell
   # Enable command-line logging in process creation events
   Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" -Name "ProcessCreationIncludeCmdLine_Enabled" -Value 1 -Type DWord -Force
   
   # Enable various audit categories
   auditpol /set /subcategory:"Logon" /success:enable /failure:enable
   auditpol /set /subcategory:"Logoff" /success:enable
   auditpol /set /subcategory:"Account Lockout" /failure:enable
   auditpol /set /subcategory:"User Account Management" /success:enable /failure:enable
   auditpol /set /subcategory:"Process Creation" /success:enable
   ```

3. Install and configure NXLog Community Edition to forward Windows Security events to Cribl:
   ```xml
   # nxlog.conf
   <Input in_security>
       Module      im_msvistalog
       Query       <QueryList><Query><Select Path="Security">*</Select></Query></QueryList>
   </Input>
   
   <Output out_cribl>
       Module      om_tcp
       Host        CRIBL_PRIVATE_IP
       Port        9514
       Exec        to_syslog_bsd();
   </Output>
   
   <Route security_to_cribl>
       Path        in_security => out_cribl
   </Route>
   ```

4. Create a scheduled task or script to generate demo security events:
   ```powershell
   # Generate failed logon (4625)
   $null = Start-Process -FilePath "net" -ArgumentList "use \\localhost\c$ /user:fakeuser wrongpassword" -NoNewWindow -Wait 2>$null
   
   # Create and delete test user (4720, 4726)
   net user DemoTestUser P@ssw0rd123! /add 2>$null
   net user DemoTestUser /delete 2>$null
   ```

**Security group**:
- Inbound: 3389 (RDP from allowed CIDR), 5985-5986 (WinRM from allowed CIDR)
- Outbound: 9514 to Cribl security group, 443 (for NXLog download)

### 4. Fortinet Log Simulator (on Cribl server or separate micro instance)

Since Fortinet software requires licensing, create a Python-based log simulator that generates realistic FortiGate syslog messages.

**Can run on the Cribl server itself** or a separate t3.micro instance.

**Create `/opt/fortinet-simulator/fortinet_log_generator.py`**:

```python
#!/usr/bin/env python3
"""
Fortinet FortiGate Log Simulator
Generates realistic syslog messages in FortiGate format
"""

import socket
import random
import time
from datetime import datetime

CRIBL_HOST = "localhost"  # or Cribl private IP if separate instance
CRIBL_PORT = 9514

# Sample data for realistic logs
SRC_IPS = ["192.168.1." + str(i) for i in range(10, 50)]
DST_IPS = ["8.8.8.8", "1.1.1.1", "208.67.222.222", "151.101.1.140", "104.244.42.1"]
ACTIONS = ["accept", "accept", "accept", "deny", "drop"]  # Weighted toward accept
SERVICES = ["HTTPS", "HTTP", "DNS", "SSH", "SMTP", "FTP"]
POLICY_IDS = [1, 2, 3, 5, 10, 15]

def generate_traffic_log():
    """Generate a FortiGate traffic log"""
    now = datetime.now()
    return (
        f'date={now.strftime("%Y-%m-%d")} '
        f'time={now.strftime("%H:%M:%S")} '
        f'devname="FGT-DEMO-01" '
        f'devid="FG100E1234567890" '
        f'logid="0000000013" '
        f'type="traffic" '
        f'subtype="forward" '
        f'level="notice" '
        f'vd="root" '
        f'srcip={random.choice(SRC_IPS)} '
        f'srcport={random.randint(1024, 65535)} '
        f'srcintf="port1" '
        f'dstip={random.choice(DST_IPS)} '
        f'dstport={random.choice([80, 443, 53, 22, 25])} '
        f'dstintf="port2" '
        f'policyid={random.choice(POLICY_IDS)} '
        f'sessionid={random.randint(100000, 999999)} '
        f'proto=6 '
        f'action="{random.choice(ACTIONS)}" '
        f'duration={random.randint(1, 300)} '
        f'sentbyte={random.randint(100, 50000)} '
        f'rcvdbyte={random.randint(100, 100000)} '
        f'service="{random.choice(SERVICES)}"'
    )

def generate_utm_log():
    """Generate a FortiGate UTM/threat log"""
    now = datetime.now()
    threats = [
        ("eicar", "virus", "EICAR_TEST_FILE"),
        ("malware", "virus", "W32/Malware.TEST"),
        ("intrusion", "ips", "Apache.Struts.OGNL.Remote.Code.Execution"),
    ]
    threat = random.choice(threats)
    return (
        f'date={now.strftime("%Y-%m-%d")} '
        f'time={now.strftime("%H:%M:%S")} '
        f'devname="FGT-DEMO-01" '
        f'devid="FG100E1234567890" '
        f'logid="0211008192" '
        f'type="utm" '
        f'subtype="{threat[1]}" '
        f'level="warning" '
        f'vd="root" '
        f'srcip={random.choice(SRC_IPS)} '
        f'dstip={random.choice(DST_IPS)} '
        f'action="blocked" '
        f'service="{random.choice(SERVICES)}" '
        f'threatname="{threat[2]}" '
        f'msg="Threat detected and blocked"'
    )

def generate_event_log():
    """Generate a FortiGate system event log"""
    now = datetime.now()
    events = [
        ("system", "System configuration changed by admin"),
        ("user", "Administrator admin logged in from 192.168.1.100"),
        ("vpn", "SSL VPN tunnel established for user demo_user"),
    ]
    event = random.choice(events)
    return (
        f'date={now.strftime("%Y-%m-%d")} '
        f'time={now.strftime("%H:%M:%S")} '
        f'devname="FGT-DEMO-01" '
        f'devid="FG100E1234567890" '
        f'logid="0100032001" '
        f'type="event" '
        f'subtype="{event[0]}" '
        f'level="information" '
        f'vd="root" '
        f'msg="{event[1]}"'
    )

def send_log(sock, message):
    """Send syslog message"""
    # Wrap in syslog format (facility=local0, severity=notice)
    priority = 134  # local0.info
    syslog_msg = f"<{priority}>{message}"
    sock.sendto(syslog_msg.encode(), (CRIBL_HOST, CRIBL_PORT))

def main():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    
    generators = [
        (generate_traffic_log, 0.7),   # 70% traffic logs
        (generate_utm_log, 0.15),      # 15% UTM logs  
        (generate_event_log, 0.15),    # 15% event logs
    ]
    
    print(f"Starting Fortinet log simulator, sending to {CRIBL_HOST}:{CRIBL_PORT}")
    print("Press Ctrl+C to stop")
    
    try:
        while True:
            # Select log type based on weights
            r = random.random()
            cumulative = 0
            for generator, weight in generators:
                cumulative += weight
                if r <= cumulative:
                    log = generator()
                    send_log(sock, log)
                    print(f"Sent: {log[:80]}...")
                    break
            
            # Random delay between 0.5 and 3 seconds
            time.sleep(random.uniform(0.5, 3))
    
    except KeyboardInterrupt:
        print("\nSimulator stopped")
    finally:
        sock.close()

if __name__ == "__main__":
    main()
```

**Create systemd service `/etc/systemd/system/fortinet-simulator.service`**:

```ini
[Unit]
Description=Fortinet Log Simulator
After=network.target

[Service]
Type=simple
ExecStart=/usr/bin/python3 /opt/fortinet-simulator/fortinet_log_generator.py
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

## Terraform Structure

```
cribl-demo-infra/
├── main.tf              # Provider config, VPC, subnets
├── variables.tf         # All input variables
├── outputs.tf           # Connection info, URLs, IPs
├── security_groups.tf   # All security group definitions
├── cribl.tf             # Cribl EC2 instance + user data
├── linux_auditd.tf      # Linux Auditd EC2 instance + user data
├── windows.tf           # Windows EC2 instance + user data
├── templates/
│   ├── cribl_userdata.sh
│   ├── linux_auditd_userdata.sh
│   ├── windows_userdata.ps1
│   └── fortinet_simulator.py
└── terraform.tfvars.example
```

## Expected Outputs

```hcl
output "cribl_public_ip" {
  description = "Cribl Stream public IP"
}

output "cribl_admin_url" {
  description = "Cribl admin console URL"
  value       = "http://${aws_instance.cribl.public_ip}:9000"
}

output "cribl_default_credentials" {
  description = "Default Cribl credentials"
  value       = "admin / admin (change immediately)"
}

output "linux_auditd_public_ip" {
  description = "Linux Auditd server public IP for SSH"
}

output "windows_public_ip" {
  description = "Windows server public IP for RDP"
}

output "demo_commands" {
  description = "Commands to generate test events"
  value = <<-EOT
    # SSH to Linux and run:
    /usr/local/bin/generate-audit-events.sh
    
    # RDP to Windows and run in PowerShell:
    C:\demo\generate-security-events.ps1
    
    # Fortinet simulator runs automatically on Cribl server
    # Check status: systemctl status fortinet-simulator
  EOT
}
```

## Post-Deployment Manual Steps

After Terraform applies, document these manual verification steps:

1. **Access Cribl UI** at the output URL, change default password
2. **Verify sources** are receiving data (Monitoring → Sources)
3. **Check HTTP destination** is connected to Elastic endpoint
4. **SSH to Linux box**, run demo script, verify events in Cribl
5. **RDP to Windows box**, run demo script, verify events in Cribl
6. **Check Fortinet simulator** is running and sending logs
7. **Verify in Elastic** that data is arriving in expected indices

## Cost Estimate

| Resource | Type | Estimated Monthly Cost |
|----------|------|----------------------|
| Cribl EC2 | t3.small | ~$15 |
| Linux Auditd EC2 | t3.micro | ~$8 |
| Windows EC2 | t3.small | ~$15 |
| Data transfer | Minimal | ~$1 |
| **Total** | | **~$39/month** |

*Note: Costs can be reduced by stopping instances when not in use. Consider adding lifecycle rules or a destroy reminder.*

## Additional Notes

- The Fortinet simulator is a workaround for the lack of free Fortinet software. For a customer demo, explain this generates "representative FortiGate-format logs" to validate the integration pipeline.
- All user data scripts should be idempotent where possible.
- Consider adding a `terraform destroy` reminder or TTL tag for cost management.
- The Windows instance will take longer to provision (~5-10 minutes for user data to complete).

## Success Criteria

The infrastructure is complete when:

1. ✅ All three log types visible in Cribl Live Data view
2. ✅ Cribl HTTP destination shows healthy connection to Elastic
3. ✅ Events appear in Kibana Discover with correct field parsing
4. ✅ Each source type distinguishable by metadata/tags