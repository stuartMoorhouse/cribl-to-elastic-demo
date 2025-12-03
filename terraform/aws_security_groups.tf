# Security Group for Cribl Stream Server
resource "aws_security_group" "cribl" {
  name        = "cribl-elastic-demo-cribl-sg"
  description = "Security group for Cribl Stream server"
  vpc_id      = aws_vpc.main.id

  # SSH access from allowed CIDR
  ingress {
    description = "SSH from allowed CIDR"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = [var.allowed_ssh_cidr]
  }

  # Cribl UI access from allowed CIDR
  ingress {
    description = "Cribl UI from allowed CIDR"
    from_port   = 9000
    to_port     = 9000
    protocol    = "tcp"
    cidr_blocks = [var.allowed_ssh_cidr]
  }

  # Syslog TCP from VPC (internal log sources)
  ingress {
    description = "Syslog TCP from VPC"
    from_port   = 9514
    to_port     = 9514
    protocol    = "tcp"
    cidr_blocks = [var.vpc_cidr]
  }

  # Syslog UDP from VPC (internal log sources)
  ingress {
    description = "Syslog UDP from VPC"
    from_port   = 9514
    to_port     = 9514
    protocol    = "udp"
    cidr_blocks = [var.vpc_cidr]
  }

  # All outbound traffic (needs to reach Elastic endpoint)
  egress {
    description = "All outbound traffic"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "cribl-elastic-demo-cribl-sg"
    Role = "cribl"
  }
}

# Security Group for Linux Auditd Server
resource "aws_security_group" "linux_auditd" {
  name        = "cribl-elastic-demo-linux-auditd-sg"
  description = "Security group for Linux Auditd server"
  vpc_id      = aws_vpc.main.id

  # SSH access from allowed CIDR
  ingress {
    description = "SSH from allowed CIDR"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = [var.allowed_ssh_cidr]
  }

  # All outbound traffic (needs to reach Cribl on 9514)
  egress {
    description = "All outbound traffic"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "cribl-elastic-demo-linux-auditd-sg"
    Role = "linux-auditd"
  }
}

# Security Group for Windows Server
resource "aws_security_group" "windows" {
  name        = "cribl-elastic-demo-windows-sg"
  description = "Security group for Windows Security Events server"
  vpc_id      = aws_vpc.main.id

  # RDP access from allowed CIDR
  ingress {
    description = "RDP from allowed CIDR"
    from_port   = 3389
    to_port     = 3389
    protocol    = "tcp"
    cidr_blocks = [var.allowed_ssh_cidr]
  }

  # WinRM access from allowed CIDR
  ingress {
    description = "WinRM from allowed CIDR"
    from_port   = 5985
    to_port     = 5986
    protocol    = "tcp"
    cidr_blocks = [var.allowed_ssh_cidr]
  }

  # All outbound traffic (needs to reach Cribl on 9514 and download NXLog)
  egress {
    description = "All outbound traffic"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "cribl-elastic-demo-windows-sg"
    Role = "windows"
  }
}
