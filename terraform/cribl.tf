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
              sleep 15

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
              # Don't start yet - wait for Cribl to be configured with syslog source
              # systemctl start fortinet-simulator

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
