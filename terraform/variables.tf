# AWS Configuration
variable "aws_region" {
  description = "AWS region for deployment"
  type        = string
  default     = "eu-north-1"
}

variable "vpc_cidr" {
  description = "CIDR block for VPC"
  type        = string
  default     = "10.0.0.0/16"
}

variable "allowed_ssh_cidr" {
  description = "CIDR block allowed to SSH/RDP to VMs (e.g., 203.0.113.0/32 for your IP). Get your IP: curl -s https://checkip.amazonaws.com"
  type        = string

  validation {
    condition     = var.allowed_ssh_cidr != ""
    error_message = "allowed_ssh_cidr must be specified with your IP (e.g., 203.0.113.0/32). Find your IP: curl -s https://checkip.amazonaws.com"
  }

  validation {
    condition     = can(regex("^\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}/\\d{1,2}$", var.allowed_ssh_cidr))
    error_message = "allowed_ssh_cidr must be a valid CIDR notation (e.g., 203.0.113.0/32)"
  }
}

variable "ssh_public_key_path" {
  description = "Path to SSH public key for EC2 instance access"
  type        = string
  default     = "~/.ssh/id_ed25519.pub"
}

variable "ssh_private_key_path" {
  description = "Path to SSH private key for remote provisioning"
  type        = string
  default     = "~/.ssh/id_ed25519"
}

variable "windows_admin_password" {
  description = "Administrator password for Windows instance (min 8 chars, must include uppercase, lowercase, number, special char)"
  type        = string
  sensitive   = true

  validation {
    condition     = length(var.windows_admin_password) >= 8
    error_message = "Windows admin password must be at least 8 characters"
  }
}

# Elastic Cloud Configuration
variable "ec_region" {
  description = "Elastic Cloud region"
  type        = string
  default     = "aws-eu-north-1"
}

variable "elastic_version" {
  description = "Elastic Stack version"
  type        = string
  default     = "8.17.0"
}

variable "deployment_template_id" {
  description = "Elastic Cloud deployment template"
  type        = string
  default     = "aws-storage-optimized"
}

variable "elasticsearch_size" {
  description = "Elasticsearch instance size"
  type        = string
  default     = "4g"
}

variable "elasticsearch_zone_count" {
  description = "Number of availability zones for Elasticsearch"
  type        = number
  default     = 1
}

variable "kibana_size" {
  description = "Kibana instance size"
  type        = string
  default     = "1g"
}

variable "kibana_zone_count" {
  description = "Number of availability zones for Kibana"
  type        = number
  default     = 1
}

variable "integrations_server_size" {
  description = "Integrations server instance size"
  type        = string
  default     = "1g"
}

variable "integrations_server_zone_count" {
  description = "Number of availability zones for Integrations server"
  type        = number
  default     = 1
}

# AMI Configuration
variable "ubuntu_ami_owner" {
  description = "Owner ID for Ubuntu AMI"
  type        = string
  default     = "099720109477" # Canonical
}

variable "ubuntu_ami_name_filter" {
  description = "Name filter for Ubuntu AMI"
  type        = string
  default     = "ubuntu/images/hvm-ssd/ubuntu-jammy-22.04-amd64-server-*"
}

variable "windows_ami_owner" {
  description = "Owner ID for Windows AMI"
  type        = string
  default     = "801119661308" # Amazon
}

variable "windows_ami_name_filter" {
  description = "Name filter for Windows Server 2022 AMI"
  type        = string
  default     = "Windows_Server-2022-English-Full-Base-*"
}
