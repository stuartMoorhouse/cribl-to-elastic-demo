# Data source to get latest Ubuntu AMI
data "aws_ami" "ubuntu" {
  most_recent = true
  owners      = [var.ubuntu_ami_owner]

  filter {
    name   = "name"
    values = [var.ubuntu_ami_name_filter]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
}

# SSH Key Pair
resource "aws_key_pair" "demo" {
  key_name   = "cribl-elastic-demo-key"
  public_key = file(pathexpand(var.ssh_public_key_path))

  tags = {
    Name = "cribl-elastic-demo-key"
  }
}

# Cribl Stream Server
resource "aws_instance" "cribl" {
  ami                    = data.aws_ami.ubuntu.id
  instance_type          = "t3.small"
  key_name               = aws_key_pair.demo.key_name
  subnet_id              = aws_subnet.public.id
  vpc_security_group_ids = [aws_security_group.cribl.id]

  root_block_device {
    volume_size = 20
    volume_type = "gp3"
  }

  user_data = <<-EOF
              #!/bin/bash
              set -e

              # Log all output to file for debugging
              exec > >(tee -a /var/log/cribl-setup.log)
              exec 2>&1

              echo "=========================================="
              echo "Cribl Stream Server Setup"
              echo "Starting: $(date)"
              echo "=========================================="

              # Set hostname
              echo "[1/7] Setting hostname..."
              hostnamectl set-hostname cribl-stream

              # Update system
              echo "[2/7] Updating system packages..."
              export DEBIAN_FRONTEND=noninteractive
              apt-get update -qq
              apt-get upgrade -y -qq

              # Install dependencies
              echo "[3/7] Installing dependencies..."
              apt-get install -y -qq curl wget python3

              # Create cribl user
              echo "[4/7] Creating cribl user..."
              useradd -r -m -d /opt/cribl -s /bin/bash cribl || true

              # Download and install Cribl Stream
              echo "[5/7] Installing Cribl Stream..."
              cd /opt
              curl -Lso - $(curl -s https://cdn.cribl.io/dl/latest) | tar zxvf -
              chown -R cribl:cribl /opt/cribl

              # Create systemd service
              echo "[6/7] Creating systemd service..."
              cat > /etc/systemd/system/cribl.service << 'CRIBLSVC'
              [Unit]
              Description=Cribl Stream
              After=network.target

              [Service]
              Type=forking
              User=cribl
              Group=cribl
              ExecStart=/opt/cribl/bin/cribl start
              ExecStop=/opt/cribl/bin/cribl stop
              ExecReload=/opt/cribl/bin/cribl restart
              Restart=always
              RestartSec=10

              [Install]
              WantedBy=multi-user.target
              CRIBLSVC

              # Enable and start Cribl
              systemctl daemon-reload
              systemctl enable cribl
              systemctl start cribl

              # Wait for Cribl to start
              echo "Waiting for Cribl to start..."
              sleep 20

              # Configure Syslog source via local config file
              echo "Configuring Cribl Syslog source..."
              cat > /opt/cribl/local/cribl/inputs.yml << 'INPUTSYML'
inputs:
  syslog:
    disabled: false
    type: syslog
    host: "0.0.0.0"
    tcpPort: 9514
    udpPort: 9514
    sendToRoutes: true
    tls:
      disabled: true
    enableProxyHeader: false
    maxActiveCxn: 1000
    timestampTimezone: local
INPUTSYML

              chown cribl:cribl /opt/cribl/local/cribl/inputs.yml
              echo "Syslog source configured on port 9514 (TCP and UDP)"

              # Restart Cribl to pick up the new config
              echo "Restarting Cribl to apply configuration..."
              systemctl restart cribl

              # Wait for restart and verify port is listening
              sleep 15
              for i in {1..10}; do
                if ss -tlnup | grep -q ":9514"; then
                  echo "Cribl syslog port 9514 is now listening"
                  break
                fi
                echo "Waiting for syslog port... ($i/10)"
                sleep 3
              done

              # Start Fortinet simulator now that Cribl is configured
              echo "Starting Fortinet simulator..."
              systemctl start fortinet-simulator

              # Install Fortinet log simulator
              echo "[7/7] Installing Fortinet log simulator..."
              mkdir -p /opt/fortinet-simulator
              cat > /opt/fortinet-simulator/fortinet_log_generator.py << 'FORTISIM'
              #!/usr/bin/env python3
              """
              Fortinet FortiGate Log Simulator
              Generates realistic syslog messages in FortiGate format
              """

              import socket
              import random
              import time
              from datetime import datetime

              CRIBL_HOST = "localhost"
              CRIBL_PORT = 9514

              # Sample data for realistic logs
              SRC_IPS = ["192.168.1." + str(i) for i in range(10, 50)]
              DST_IPS = ["8.8.8.8", "1.1.1.1", "208.67.222.222", "151.101.1.140", "104.244.42.1"]
              ACTIONS = ["accept", "accept", "accept", "deny", "drop"]
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
                  priority = 134  # local0.info
                  syslog_msg = f"<{priority}>{message}"
                  sock.sendto(syslog_msg.encode(), (CRIBL_HOST, CRIBL_PORT))

              def main():
                  sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

                  generators = [
                      (generate_traffic_log, 0.7),
                      (generate_utm_log, 0.15),
                      (generate_event_log, 0.15),
                  ]

                  print(f"Starting Fortinet log simulator, sending to {CRIBL_HOST}:{CRIBL_PORT}")
                  print("Press Ctrl+C to stop")

                  try:
                      while True:
                          r = random.random()
                          cumulative = 0
                          for generator, weight in generators:
                              cumulative += weight
                              if r <= cumulative:
                                  log = generator()
                                  send_log(sock, log)
                                  print(f"Sent: {log[:80]}...")
                                  break
                          time.sleep(random.uniform(0.5, 3))
                  except KeyboardInterrupt:
                      print("\nSimulator stopped")
                  finally:
                      sock.close()

              if __name__ == "__main__":
                  main()
              FORTISIM

              chmod +x /opt/fortinet-simulator/fortinet_log_generator.py
              chown -R cribl:cribl /opt/fortinet-simulator

              # Create systemd service for Fortinet simulator
              cat > /etc/systemd/system/fortinet-simulator.service << 'FORTISVC'
              [Unit]
              Description=Fortinet Log Simulator
              After=network.target cribl.service

              [Service]
              Type=simple
              User=cribl
              Group=cribl
              ExecStart=/usr/bin/python3 /opt/fortinet-simulator/fortinet_log_generator.py
              Restart=always
              RestartSec=5

              [Install]
              WantedBy=multi-user.target
              FORTISVC

              systemctl daemon-reload
              systemctl enable fortinet-simulator
              # Note: fortinet-simulator is started above after Cribl syslog source is configured

              # Install Windows Security Event Log simulator
              echo "[8/8] Installing Windows Security Event Log simulator..."
              mkdir -p /opt/windows-event-simulator
              cat > /opt/windows-event-simulator/windows_event_generator.py << 'WINSIM'
              #!/usr/bin/env python3
              """
              Windows Security Event Log Simulator
              Generates realistic Windows Security Event XML messages
              Mimics events from Microsoft-Windows-Security-Auditing provider
              """

              import socket
              import random
              import time
              import uuid
              from datetime import datetime

              CRIBL_HOST = "localhost"
              CRIBL_PORT = 9514

              # Sample data for realistic events
              DOMAIN = "CONTOSO"
              COMPUTERS = ["DC01.contoso.local", "DC02.contoso.local", "WS001.contoso.local", "WS002.contoso.local"]
              USERS = ["Administrator", "jsmith", "mjohnson", "agarcia", "bwilson", "clee"]
              SERVICE_ACCOUNTS = ["DC01$", "DC02$", "YOURDC$", "svc_backup", "svc_sql"]
              SOURCE_IPS = ["192.168.1." + str(i) for i in range(10, 100)] + ["10.0.0." + str(i) for i in range(1, 50)]
              WORKSTATIONS = ["WORKSTATION" + str(i).zfill(2) for i in range(1, 20)]

              # Active Directory object GUIDs (common schema classes)
              AD_OBJECT_TYPES = [
                  ("%{bf967a86-0de6-11d0-a285-00aa003049e2}", "computer"),
                  ("%{bf967aba-0de6-11d0-a285-00aa003049e2}", "user"),
                  ("%{bf967a9c-0de6-11d0-a285-00aa003049e2}", "group"),
                  ("%{19195a5b-6da0-11d0-afd3-00c04fd930c9}", "domain"),
                  ("%{f30e3bc2-9ff0-11d1-b603-0000f80367c1}", "gPLink"),
              ]

              # Access rights for 4662 events
              ACCESS_RIGHTS = [
                  ("%%1537", "0x10000", "DELETE"),
                  ("%%7688", "0x100", "Control Access"),
                  ("%%1538", "0x20000", "READ_CONTROL"),
                  ("%%1539", "0x40000", "WRITE_DAC"),
                  ("%%1540", "0x80000", "WRITE_OWNER"),
              ]

              # Logon types
              LOGON_TYPES = [
                  ("2", "Interactive"),
                  ("3", "Network"),
                  ("4", "Batch"),
                  ("5", "Service"),
                  ("7", "Unlock"),
                  ("10", "RemoteInteractive"),
                  ("11", "CachedInteractive"),
              ]

              # Failure status codes for 4625
              FAILURE_STATUS = [
                  ("0xc000006d", "0xc000006a", "Bad username or password"),
                  ("0xc0000234", "0x0", "Account locked out"),
                  ("0xc0000072", "0x0", "Account disabled"),
                  ("0xc000006f", "0x0", "Logon outside allowed hours"),
                  ("0xc0000070", "0x0", "Logon from unauthorized workstation"),
                  ("0xc0000193", "0x0", "Account expired"),
              ]


              def generate_sid():
                  """Generate a realistic-looking SID"""
                  return f"S-1-5-21-{random.randint(1000000000, 9999999999)}-{random.randint(1000000000, 9999999999)}-{random.randint(1000000000, 9999999999)}-{random.randint(1000, 9999)}"


              def generate_logon_id():
                  """Generate a logon ID in hex format"""
                  return f"0x{random.randint(0x10000, 0xffffff):x}"


              def generate_activity_id():
                  """Generate an activity GUID"""
                  return "{" + str(uuid.uuid4()).upper() + "}"


              def get_timestamp():
                  """Get current timestamp in Windows Event format"""
                  return datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.") + f"{random.randint(0, 9999999):07d}Z"


              def generate_4624_logon():
                  """Generate Event ID 4624 - Successful Logon"""
                  computer = random.choice(COMPUTERS)
                  user = random.choice(USERS)
                  logon_type = random.choice(LOGON_TYPES)
                  src_ip = random.choice(SOURCE_IPS)
                  workstation = random.choice(WORKSTATIONS)

                  return f"""<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Security-Auditing' Guid='{{54849625-5478-4994-A5BA-3E3B0328C30D}}'/><EventID>4624</EventID><Version>2</Version><Level>0</Level><Task>12544</Task><Opcode>0</Opcode><Keywords>0x8020000000000000</Keywords><TimeCreated SystemTime='{get_timestamp()}'/><EventRecordID>{random.randint(100000, 999999)}</EventRecordID><Correlation ActivityID='{generate_activity_id()}'/><Execution ProcessID='{random.randint(400, 900)}' ThreadID='{random.randint(100, 9999)}'/><Channel>Security</Channel><Computer>{computer}</Computer><Security/></System><EventData><Data Name='SubjectUserSid'>S-1-5-18</Data><Data Name='SubjectUserName'>{computer.split('.')[0]}$</Data><Data Name='SubjectDomainName'>{DOMAIN}</Data><Data Name='SubjectLogonId'>0x3e7</Data><Data Name='TargetUserSid'>{generate_sid()}</Data><Data Name='TargetUserName'>{user}</Data><Data Name='TargetDomainName'>{DOMAIN}</Data><Data Name='TargetLogonId'>{generate_logon_id()}</Data><Data Name='LogonType'>{logon_type[0]}</Data><Data Name='LogonProcessName'>NtLmSsp</Data><Data Name='AuthenticationPackageName'>NTLM</Data><Data Name='WorkstationName'>{workstation}</Data><Data Name='LogonGuid'>{{00000000-0000-0000-0000-000000000000}}</Data><Data Name='TransmittedServices'>-</Data><Data Name='LmPackageName'>NTLM V2</Data><Data Name='KeyLength'>128</Data><Data Name='ProcessId'>0x0</Data><Data Name='ProcessName'>-</Data><Data Name='IpAddress'>{src_ip}</Data><Data Name='IpPort'>{random.randint(49152, 65535)}</Data><Data Name='ImpersonationLevel'>%%1833</Data><Data Name='RestrictedAdminMode'>-</Data><Data Name='TargetOutboundUserName'>-</Data><Data Name='TargetOutboundDomainName'>-</Data><Data Name='VirtualAccount'>%%1843</Data><Data Name='TargetLinkedLogonId'>0x0</Data><Data Name='ElevatedToken'>%%1842</Data></EventData></Event>"""


              def generate_4625_failed_logon():
                  """Generate Event ID 4625 - Failed Logon"""
                  computer = random.choice(COMPUTERS)
                  user = random.choice(USERS + ["invaliduser", "hacker", "test"])
                  logon_type = random.choice(LOGON_TYPES[:3])  # Only common types for failures
                  src_ip = random.choice(SOURCE_IPS)
                  workstation = random.choice(WORKSTATIONS)
                  failure = random.choice(FAILURE_STATUS)

                  return f"""<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Security-Auditing' Guid='{{54849625-5478-4994-A5BA-3E3B0328C30D}}'/><EventID>4625</EventID><Version>0</Version><Level>0</Level><Task>12546</Task><Opcode>0</Opcode><Keywords>0x8010000000000000</Keywords><TimeCreated SystemTime='{get_timestamp()}'/><EventRecordID>{random.randint(100000, 999999)}</EventRecordID><Correlation/><Execution ProcessID='{random.randint(400, 900)}' ThreadID='{random.randint(100, 9999)}'/><Channel>Security</Channel><Computer>{computer}</Computer><Security/></System><EventData><Data Name='SubjectUserSid'>S-1-5-18</Data><Data Name='SubjectUserName'>{computer.split('.')[0]}$</Data><Data Name='SubjectDomainName'>{DOMAIN}</Data><Data Name='SubjectLogonId'>0x3e7</Data><Data Name='TargetUserSid'>S-1-0-0</Data><Data Name='TargetUserName'>{user}</Data><Data Name='TargetDomainName'>{DOMAIN}</Data><Data Name='Status'>{failure[0]}</Data><Data Name='FailureReason'>%%2307</Data><Data Name='SubStatus'>{failure[1]}</Data><Data Name='LogonType'>{logon_type[0]}</Data><Data Name='LogonProcessName'>NtLmSsp</Data><Data Name='AuthenticationPackageName'>NTLM</Data><Data Name='WorkstationName'>{workstation}</Data><Data Name='TransmittedServices'>-</Data><Data Name='LmPackageName'>-</Data><Data Name='KeyLength'>0</Data><Data Name='ProcessId'>0x0</Data><Data Name='ProcessName'>-</Data><Data Name='IpAddress'>{src_ip}</Data><Data Name='IpPort'>{random.randint(49152, 65535)}</Data></EventData></Event>"""


              def generate_4662_ds_access():
                  """Generate Event ID 4662 - Directory Service Access"""
                  computer = random.choice(COMPUTERS[:2])  # Usually on DCs
                  user = random.choice(SERVICE_ACCOUNTS + USERS)
                  obj_type = random.choice(AD_OBJECT_TYPES)
                  access = random.choice(ACCESS_RIGHTS)

                  return f"""<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Security-Auditing' Guid='{{54849625-5478-4994-A5BA-3E3B0328C30D}}'/><EventID>4662</EventID><Version>0</Version><Level>0</Level><Task>14080</Task><Opcode>0</Opcode><Keywords>0x8020000000000000</Keywords><TimeCreated SystemTime='{get_timestamp()}'/><EventRecordID>{random.randint(100000, 999999)}</EventRecordID><Correlation ActivityID='{generate_activity_id()}'/><Execution ProcessID='{random.randint(400, 900)}' ThreadID='{random.randint(100, 9999)}'/><Channel>Security</Channel><Computer>{computer}</Computer><Security/></System><EventData><Data Name='SubjectUserSid'>{generate_sid()}</Data><Data Name='SubjectUserName'>{user}</Data><Data Name='SubjectDomainName'>{DOMAIN}</Data><Data Name='SubjectLogonId'>{generate_logon_id()}</Data><Data Name='ObjectServer'>DS</Data><Data Name='ObjectType'>{obj_type[0]}</Data><Data Name='ObjectName'>%{{{str(uuid.uuid4())}}}</Data><Data Name='OperationType'>Object Access</Data><Data Name='HandleId'>0x0</Data><Data Name='AccessList'>{access[0]}</Data><Data Name='AccessMask'>{access[1]}</Data><Data Name='Properties'>{access[0]} {obj_type[0]}</Data><Data Name='AdditionalInfo'>-</Data><Data Name='AdditionalInfo2'></Data></EventData></Event>"""


              def generate_4672_special_privileges():
                  """Generate Event ID 4672 - Special Privileges Assigned"""
                  computer = random.choice(COMPUTERS)
                  user = random.choice(USERS[:2] + SERVICE_ACCOUNTS)  # Usually admins

                  privileges = [
                      "SeSecurityPrivilege",
                      "SeBackupPrivilege",
                      "SeRestorePrivilege",
                      "SeTakeOwnershipPrivilege",
                      "SeDebugPrivilege",
                      "SeSystemEnvironmentPrivilege",
                      "SeLoadDriverPrivilege",
                      "SeImpersonatePrivilege",
                      "SeEnableDelegationPrivilege",
                  ]
                  assigned_privs = random.sample(privileges, random.randint(2, 5))
                  priv_list = "\n\t\t\t".join(assigned_privs)

                  return f"""<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Security-Auditing' Guid='{{54849625-5478-4994-A5BA-3E3B0328C30D}}'/><EventID>4672</EventID><Version>0</Version><Level>0</Level><Task>12548</Task><Opcode>0</Opcode><Keywords>0x8020000000000000</Keywords><TimeCreated SystemTime='{get_timestamp()}'/><EventRecordID>{random.randint(100000, 999999)}</EventRecordID><Correlation/><Execution ProcessID='{random.randint(400, 900)}' ThreadID='{random.randint(100, 9999)}'/><Channel>Security</Channel><Computer>{computer}</Computer><Security/></System><EventData><Data Name='SubjectUserSid'>{generate_sid()}</Data><Data Name='SubjectUserName'>{user}</Data><Data Name='SubjectDomainName'>{DOMAIN}</Data><Data Name='SubjectLogonId'>{generate_logon_id()}</Data><Data Name='PrivilegeList'>{priv_list}</Data></EventData></Event>"""


              def generate_4688_process_creation():
                  """Generate Event ID 4688 - Process Creation"""
                  computer = random.choice(COMPUTERS)
                  user = random.choice(USERS)

                  processes = [
                      ("C:\\Windows\\System32\\cmd.exe", "C:\\Windows\\System32\\cmd.exe /c whoami"),
                      ("C:\\Windows\\System32\\powershell.exe", "powershell.exe -ExecutionPolicy Bypass -File script.ps1"),
                      ("C:\\Windows\\System32\\net.exe", "net user"),
                      ("C:\\Windows\\System32\\tasklist.exe", "tasklist /v"),
                      ("C:\\Program Files\\Microsoft Office\\Office16\\WINWORD.EXE", "WINWORD.EXE /n document.docx"),
                      ("C:\\Windows\\System32\\notepad.exe", "notepad.exe C:\\temp\\notes.txt"),
                  ]
                  proc = random.choice(processes)
                  parent_proc = "C:\\Windows\\System32\\svchost.exe" if random.random() > 0.5 else "C:\\Windows\\explorer.exe"

                  return f"""<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Security-Auditing' Guid='{{54849625-5478-4994-A5BA-3E3B0328C30D}}'/><EventID>4688</EventID><Version>2</Version><Level>0</Level><Task>13312</Task><Opcode>0</Opcode><Keywords>0x8020000000000000</Keywords><TimeCreated SystemTime='{get_timestamp()}'/><EventRecordID>{random.randint(100000, 999999)}</EventRecordID><Correlation/><Execution ProcessID='{random.randint(400, 900)}' ThreadID='{random.randint(100, 9999)}'/><Channel>Security</Channel><Computer>{computer}</Computer><Security/></System><EventData><Data Name='SubjectUserSid'>{generate_sid()}</Data><Data Name='SubjectUserName'>{user}</Data><Data Name='SubjectDomainName'>{DOMAIN}</Data><Data Name='SubjectLogonId'>{generate_logon_id()}</Data><Data Name='NewProcessId'>0x{random.randint(0x100, 0xffff):x}</Data><Data Name='NewProcessName'>{proc[0]}</Data><Data Name='TokenElevationType'>%%1936</Data><Data Name='ProcessId'>0x{random.randint(0x100, 0xffff):x}</Data><Data Name='CommandLine'>{proc[1]}</Data><Data Name='TargetUserSid'>S-1-0-0</Data><Data Name='TargetUserName'>-</Data><Data Name='TargetDomainName'>-</Data><Data Name='TargetLogonId'>0x0</Data><Data Name='ParentProcessName'>{parent_proc}</Data><Data Name='MandatoryLabel'>S-1-16-8192</Data></EventData></Event>"""


              def generate_4768_kerberos_tgt():
                  """Generate Event ID 4768 - Kerberos TGT Request"""
                  computer = random.choice(COMPUTERS[:2])  # Only on DCs
                  user = random.choice(USERS)
                  src_ip = random.choice(SOURCE_IPS)

                  return f"""<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Security-Auditing' Guid='{{54849625-5478-4994-A5BA-3E3B0328C30D}}'/><EventID>4768</EventID><Version>0</Version><Level>0</Level><Task>14339</Task><Opcode>0</Opcode><Keywords>0x8020000000000000</Keywords><TimeCreated SystemTime='{get_timestamp()}'/><EventRecordID>{random.randint(100000, 999999)}</EventRecordID><Correlation/><Execution ProcessID='{random.randint(400, 900)}' ThreadID='{random.randint(100, 9999)}'/><Channel>Security</Channel><Computer>{computer}</Computer><Security/></System><EventData><Data Name='TargetUserName'>{user}</Data><Data Name='TargetDomainName'>{DOMAIN}.LOCAL</Data><Data Name='TargetSid'>{generate_sid()}</Data><Data Name='ServiceName'>krbtgt</Data><Data Name='ServiceSid'>S-1-5-21-0-0-0-502</Data><Data Name='TicketOptions'>0x40810010</Data><Data Name='Status'>0x0</Data><Data Name='TicketEncryptionType'>0x12</Data><Data Name='PreAuthType'>2</Data><Data Name='IpAddress'>::ffff:{src_ip}</Data><Data Name='IpPort'>{random.randint(49152, 65535)}</Data><Data Name='CertIssuerName'></Data><Data Name='CertSerialNumber'></Data><Data Name='CertThumbprint'></Data></EventData></Event>"""


              def send_log(sock, message):
                  """Send syslog message with Windows Event XML"""
                  priority = 134  # local0.info
                  syslog_msg = f"<{priority}>{message}"
                  sock.sendto(syslog_msg.encode(), (CRIBL_HOST, CRIBL_PORT))


              def main():
                  sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

                  # Event generators with weights (frequency)
                  generators = [
                      (generate_4624_logon, 0.35),           # Successful logons - most common
                      (generate_4625_failed_logon, 0.10),    # Failed logons
                      (generate_4662_ds_access, 0.15),       # Directory Service Access
                      (generate_4672_special_privileges, 0.10),  # Special privileges
                      (generate_4688_process_creation, 0.20),    # Process creation
                      (generate_4768_kerberos_tgt, 0.10),    # Kerberos TGT
                  ]

                  print(f"Starting Windows Security Event simulator, sending to {CRIBL_HOST}:{CRIBL_PORT}")
                  print("Generating events: 4624, 4625, 4662, 4672, 4688, 4768")
                  print("Press Ctrl+C to stop")

                  try:
                      while True:
                          r = random.random()
                          cumulative = 0
                          for generator, weight in generators:
                              cumulative += weight
                              if r <= cumulative:
                                  log = generator()
                                  send_log(sock, log)
                                  # Extract event ID for logging
                                  event_id = log.split("<EventID>")[1].split("</EventID>")[0] if "<EventID>" in log else "?"
                                  print(f"Sent Event ID {event_id}: {log[:100]}...")
                                  break
                          time.sleep(random.uniform(1, 5))
                  except KeyboardInterrupt:
                      print("\nSimulator stopped")
                  finally:
                      sock.close()


              if __name__ == "__main__":
                  main()
              WINSIM

              chmod +x /opt/windows-event-simulator/windows_event_generator.py
              chown -R cribl:cribl /opt/windows-event-simulator

              # Create systemd service for Windows Event simulator
              cat > /etc/systemd/system/windows-event-simulator.service << 'WINSVC'
              [Unit]
              Description=Windows Security Event Log Simulator
              After=network.target cribl.service

              [Service]
              Type=simple
              User=cribl
              Group=cribl
              ExecStart=/usr/bin/python3 /opt/windows-event-simulator/windows_event_generator.py
              Restart=always
              RestartSec=5

              [Install]
              WantedBy=multi-user.target
              WINSVC

              systemctl daemon-reload
              systemctl enable windows-event-simulator
              # Start after Cribl is fully configured
              systemctl start windows-event-simulator

              # Get IP addresses
              PRIVATE_IP=$(hostname -I | awk '{print $1}')
              PUBLIC_IP=$(curl -s http://169.254.169.254/latest/meta-data/public-ipv4 2>/dev/null || echo "N/A")

              # Create info file
              cat > /home/ubuntu/cribl-info.txt << ENDCONFIG
              Cribl Elastic Demo - Cribl Stream Server
              Generated: $(date)

              Server Information:
                Hostname: $(hostname)
                Private IP: $PRIVATE_IP
                Public IP: $PUBLIC_IP

              Cribl Stream:
                Admin URL: http://$PUBLIC_IP:9000
                Default Credentials: admin / admin (CHANGE IMMEDIATELY)
                Installation: /opt/cribl
                Service: cribl.service

              Syslog Input (configure in Cribl):
                TCP Port: 9514
                UDP Port: 9514

              Fortinet Simulator:
                Script: /opt/fortinet-simulator/fortinet_log_generator.py
                Service: fortinet-simulator.service
                Status: systemctl status fortinet-simulator
                Start: sudo systemctl start fortinet-simulator

              Service Commands:
                sudo systemctl status cribl
                sudo systemctl restart cribl
                sudo journalctl -u cribl -f

              Setup Log: /var/log/cribl-setup.log

              Post-Setup Tasks:
                1. Access Cribl UI and change default password
                2. Add Syslog source (UDP/TCP 9514)
                3. Add HTTP destination pointing to Elastic Agent endpoint
                4. Create route from syslog source to HTTP destination
                5. Start Fortinet simulator: sudo systemctl start fortinet-simulator
              ENDCONFIG

              chown ubuntu:ubuntu /home/ubuntu/cribl-info.txt

              echo ""
              echo "=========================================="
              echo "Cribl Stream Setup Complete!"
              echo "Completed: $(date)"
              echo "=========================================="
              echo ""
              echo "Admin URL: http://$PUBLIC_IP:9000"
              echo "Default credentials: admin / admin"
              EOF

  tags = {
    Name = "cribl-stream"
    Role = "cribl"
  }
}
