# Linux Auditd Server
resource "aws_instance" "linux_auditd" {
  ami                    = data.aws_ami.ubuntu.id
  instance_type          = "t3.micro"
  key_name               = aws_key_pair.demo.key_name
  subnet_id              = aws_subnet.public.id
  vpc_security_group_ids = [aws_security_group.linux_auditd.id]

  root_block_device {
    volume_size = 10
    volume_type = "gp3"
  }

  user_data = <<-EOF
              #!/bin/bash
              set -e

              # Log all output to file for debugging
              exec > >(tee -a /var/log/auditd-setup.log)
              exec 2>&1

              echo "=========================================="
              echo "Linux Auditd Server Setup"
              echo "Starting: $(date)"
              echo "=========================================="

              # Set hostname
              echo "[1/6] Setting hostname..."
              hostnamectl set-hostname linux-auditd

              # Update system
              echo "[2/6] Updating system packages..."
              export DEBIAN_FRONTEND=noninteractive
              apt-get update -qq
              apt-get upgrade -y -qq

              # Install auditd and rsyslog
              echo "[3/6] Installing auditd and rsyslog..."
              apt-get install -y -qq auditd audispd-plugins rsyslog

              # Configure audit rules
              echo "[4/6] Configuring audit rules..."
              cat > /etc/audit/rules.d/demo.rules << 'AUDITRULES'
              # Delete all existing rules
              -D

              # Set buffer size
              -b 8192

              # Monitor identity files
              -w /etc/passwd -p wa -k identity
              -w /etc/shadow -p wa -k identity
              -w /etc/group -p wa -k identity
              -w /etc/gshadow -p wa -k identity

              # Monitor sudoers
              -w /etc/sudoers -p wa -k sudoers
              -w /etc/sudoers.d/ -p wa -k sudoers

              # Monitor command execution
              -a always,exit -F arch=b64 -S execve -k commands
              -a always,exit -F arch=b32 -S execve -k commands

              # Monitor network connections
              -a always,exit -F arch=b64 -S connect -k network
              -a always,exit -F arch=b32 -S connect -k network

              # Monitor file access
              -a always,exit -F arch=b64 -S open -S openat -F exit=-EACCES -k access
              -a always,exit -F arch=b64 -S open -S openat -F exit=-EPERM -k access

              # Make config immutable (must be last rule)
              -e 2
              AUDITRULES

              # Restart auditd to apply rules
              service auditd restart

              # Configure rsyslog to forward to Cribl
              echo "[5/6] Configuring rsyslog to forward to Cribl..."
              CRIBL_IP="${aws_instance.cribl.private_ip}"

              cat > /etc/rsyslog.d/50-audit-to-cribl.conf << RSYSLOGCONF
              # Load imfile module for reading files
              module(load="imfile" PollingInterval="10")

              # Read audit.log
              input(type="imfile"
                    File="/var/log/audit/audit.log"
                    Tag="auditd:"
                    Severity="info"
                    Facility="local6"
                    PersistStateInterval="100")

              # Forward to Cribl
              local6.* @@$CRIBL_IP:9514
              RSYSLOGCONF

              # Restart rsyslog
              systemctl restart rsyslog

              # Create demo script
              echo "[6/6] Creating demo event script..."
              cat > /usr/local/bin/generate-audit-events.sh << 'DEMOSCRIPT'
              #!/bin/bash
              echo "Generating audit events for demo..."

              # Trigger identity file access
              echo "Reading identity files..."
              cat /etc/passwd > /dev/null
              cat /etc/shadow 2>/dev/null || true
              cat /etc/group > /dev/null

              # Trigger sudoers access
              echo "Checking sudo privileges..."
              sudo -l 2>/dev/null || true

              # Trigger command execution
              echo "Running various commands..."
              ls /root 2>/dev/null || true
              whoami
              id
              uname -a
              netstat -tlnp 2>/dev/null || ss -tlnp

              # Trigger file access
              echo "Accessing files..."
              cat /etc/ssh/sshd_config > /dev/null 2>&1 || true

              echo ""
              echo "Audit events generated! Check /var/log/audit/audit.log"
              echo "Events should appear in Cribl shortly."
              DEMOSCRIPT

              chmod +x /usr/local/bin/generate-audit-events.sh

              # Get IP addresses
              PRIVATE_IP=$(hostname -I | awk '{print $1}')
              PUBLIC_IP=$(curl -s http://169.254.169.254/latest/meta-data/public-ipv4 2>/dev/null || echo "N/A")

              # Create info file
              cat > /home/ubuntu/linux-auditd-info.txt << ENDCONFIG
              Cribl Elastic Demo - Linux Auditd Server
              Generated: $(date)

              Server Information:
                Hostname: $(hostname)
                Private IP: $PRIVATE_IP
                Public IP: $PUBLIC_IP

              Auditd Configuration:
                Rules: /etc/audit/rules.d/demo.rules
                Log: /var/log/audit/audit.log
                Service: auditd

              Rsyslog Configuration:
                Config: /etc/rsyslog.d/50-audit-to-cribl.conf
                Forwarding to: $CRIBL_IP:9514 (TCP)

              Demo Script:
                /usr/local/bin/generate-audit-events.sh

              Useful Commands:
                # View audit log
                sudo tail -f /var/log/audit/audit.log

                # Check audit rules
                sudo auditctl -l

                # Check rsyslog status
                sudo systemctl status rsyslog

                # Generate test events
                /usr/local/bin/generate-audit-events.sh

              Setup Log: /var/log/auditd-setup.log
              ENDCONFIG

              chown ubuntu:ubuntu /home/ubuntu/linux-auditd-info.txt

              echo ""
              echo "=========================================="
              echo "Linux Auditd Setup Complete!"
              echo "Completed: $(date)"
              echo "=========================================="
              echo ""
              echo "Forwarding audit logs to: $CRIBL_IP:9514"
              EOF

  tags = {
    Name = "linux-auditd"
    Role = "linux-auditd"
  }

  depends_on = [aws_instance.cribl]
}
