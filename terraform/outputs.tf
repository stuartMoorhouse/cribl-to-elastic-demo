# Cribl Stream Outputs
output "cribl_public_ip" {
  description = "Cribl Stream public IP"
  value       = aws_instance.cribl.public_ip
}

output "cribl_private_ip" {
  description = "Cribl Stream private IP (for internal forwarding)"
  value       = aws_instance.cribl.private_ip
}

output "cribl_admin_url" {
  description = "Cribl admin console URL"
  value       = "http://${aws_instance.cribl.public_ip}:9000"
}

output "cribl_default_credentials" {
  description = "Default Cribl credentials"
  value       = "admin / admin (change immediately)"
}

output "cribl_ssh_command" {
  description = "SSH command to connect to Cribl server"
  value       = "ssh -i ${trimsuffix(var.ssh_public_key_path, ".pub")} ubuntu@${aws_instance.cribl.public_ip}"
}

# Linux Auditd Outputs
output "linux_auditd_public_ip" {
  description = "Linux Auditd server public IP for SSH"
  value       = aws_instance.linux_auditd.public_ip
}

output "linux_auditd_private_ip" {
  description = "Linux Auditd server private IP"
  value       = aws_instance.linux_auditd.private_ip
}

output "linux_auditd_ssh_command" {
  description = "SSH command to connect to Linux Auditd server"
  value       = "ssh -i ${trimsuffix(var.ssh_public_key_path, ".pub")} ubuntu@${aws_instance.linux_auditd.public_ip}"
}

# Windows Outputs
output "windows_public_ip" {
  description = "Windows server public IP for RDP"
  value       = aws_instance.windows.public_ip
}

output "windows_private_ip" {
  description = "Windows server private IP"
  value       = aws_instance.windows.private_ip
}

output "windows_rdp_command" {
  description = "RDP connection info"
  value       = "Connect via RDP to ${aws_instance.windows.public_ip} as Administrator"
}

# Elastic Cloud Outputs
output "elastic_deployment" {
  description = "Elastic Cloud deployment information"
  value = {
    deployment_id      = ec_deployment.cribl_demo.id
    deployment_name    = ec_deployment.cribl_demo.name
    elasticsearch_url  = ec_deployment.cribl_demo.elasticsearch.https_endpoint
    kibana_url         = ec_deployment.cribl_demo.kibana.https_endpoint
    elasticsearch_user = ec_deployment.cribl_demo.elasticsearch_username
    cloud_id           = ec_deployment.cribl_demo.elasticsearch.cloud_id
    version            = ec_deployment.cribl_demo.version
  }
}

output "elastic_password" {
  description = "Elastic deployment password (sensitive)"
  value       = ec_deployment.cribl_demo.elasticsearch_password
  sensitive   = true
}

output "elastic_agent_fleet_url" {
  description = "Fleet Server URL for Elastic Agent (integrations server)"
  value       = ec_deployment.cribl_demo.integrations_server.https_endpoint
}

# Demo Commands
output "demo_commands" {
  description = "Commands to generate test events"
  value       = <<-EOT

    CRIBL TO ELASTIC DEMO
    =====================

    1. Access Cribl Stream:
       URL: http://${aws_instance.cribl.public_ip}:9000
       Credentials: admin / admin (change immediately!)

    2. Access Kibana:
       URL: ${ec_deployment.cribl_demo.kibana.https_endpoint}
       User: ${ec_deployment.cribl_demo.elasticsearch_username}
       Pass: Run 'terraform output elastic_password' to view

    3. Generate test events:

       # SSH to Linux and run:
       ssh -i ${trimsuffix(var.ssh_public_key_path, ".pub")} ubuntu@${aws_instance.linux_auditd.public_ip}
       /usr/local/bin/generate-audit-events.sh

       # RDP to Windows and run in PowerShell:
       C:\generate-security-events.ps1

       # Start Fortinet simulator on Cribl server:
       ssh -i ${trimsuffix(var.ssh_public_key_path, ".pub")} ubuntu@${aws_instance.cribl.public_ip}
       sudo systemctl start fortinet-simulator
       sudo systemctl status fortinet-simulator

    POST-DEPLOYMENT SETUP:
    ----------------------
    1. Access Cribl UI, change default password
    2. Add Syslog source (UDP/TCP port 9514)
    3. Configure HTTP destination for Elastic Agent endpoint
    4. Create route from syslog to HTTP destination
    5. Start Fortinet simulator
    6. Verify data in Kibana Discover

  EOT
}

# Quick Start
output "quick_start" {
  description = "Quick start summary"
  value       = <<-EOT

    QUICK START
    ===========

    Cribl Admin: http://${aws_instance.cribl.public_ip}:9000 (admin/admin)
    Kibana: ${ec_deployment.cribl_demo.kibana.https_endpoint}

    SSH to Cribl:  ssh -i ${trimsuffix(var.ssh_public_key_path, ".pub")} ubuntu@${aws_instance.cribl.public_ip}
    SSH to Linux:  ssh -i ${trimsuffix(var.ssh_public_key_path, ".pub")} ubuntu@${aws_instance.linux_auditd.public_ip}
    RDP to Windows: ${aws_instance.windows.public_ip} (Administrator)

    View Elastic password: terraform output elastic_password

  EOT
}
