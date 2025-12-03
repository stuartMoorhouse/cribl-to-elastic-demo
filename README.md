# Cribl to Elastic Demo

A Terraform-based demo environment that streams simulated Fortinet firewall logs through Cribl Stream into Elastic Cloud.

## Architecture

```
┌─────────────────────┐      ┌─────────────────────┐      ┌─────────────────────┐
│  Fortinet Simulator │─────▶│    Cribl Stream     │─────▶│   Elastic Cloud     │
│   (Python script)   │      │   (Log processor)   │      │  (Elasticsearch +   │
│                     │ UDP  │                     │ HTTP │      Kibana)        │
│   Syslog @ 9514     │      │   Port 9514         │      │                     │
└─────────────────────┘      └─────────────────────┘      └─────────────────────┘
        │                              │
        └──────────────────────────────┘
              Same EC2 instance
```

## What Gets Deployed

- **Cribl Stream EC2** (t3.small) - Log processing with built-in Fortinet log simulator
- **Elastic Cloud Deployment** - Elasticsearch, Kibana, and Fleet/Integrations Server

The Fortinet simulator generates realistic FortiGate firewall logs including:
- Traffic logs (accept/deny actions)
- UTM/threat logs (virus, IPS detections)
- System event logs (admin logins, VPN connections)

## Prerequisites

1. AWS CLI configured with credentials
2. Elastic Cloud API key (set as `EC_API_KEY` environment variable)
3. SSH key pair at `~/.ssh/id_ed25519` (or configure different path)
4. Terraform installed

## Quick Start

```bash
# 1. Clone and configure
cd terraform
cp terraform.tfvars.example terraform.tfvars

# 2. Edit terraform.tfvars - set your IP for SSH access
#    Get your IP: curl -s https://checkip.amazonaws.com
#    Set: allowed_ssh_cidr = "YOUR_IP/32"

# 3. Set Elastic Cloud API key
export EC_API_KEY="your-elastic-cloud-api-key"

# 4. Deploy
terraform init
terraform apply --auto-approve

# 5. View connection details
terraform output
terraform output elastic_password
```

## Post-Deployment Setup

### 1. Access Cribl Stream

```bash
# Get the URL
terraform output cribl_admin_url
```

Default credentials: `admin` / `admin` (change immediately)

### 2. Verify Fortinet Simulator is Running

```bash
# SSH to Cribl server
ssh -i ~/.ssh/id_ed25519 ubuntu@$(terraform output -raw cribl_public_ip)

# Check simulator status
sudo systemctl status fortinet-simulator

# View simulator output
sudo journalctl -u fortinet-simulator -f
```

### 3. Configure Cribl HTTP Destination for Elastic

In Cribl Stream UI:

1. Go to **Data > Destinations > Add Destination**
2. Select **HTTP** (or **Elastic** if available)
3. Configure the destination to send to your Elastic endpoint
4. Create a **Route** from the Syslog source to the HTTP destination

### 4. Access Kibana

```bash
# Get Kibana URL
terraform output -json elastic_deployment | jq -r '.kibana_url'

# Get password
terraform output elastic_password
```

User: `elastic`

## Terraform Outputs

| Output | Description |
|--------|-------------|
| `cribl_admin_url` | Cribl Stream web UI URL |
| `cribl_ssh_command` | SSH command to access Cribl server |
| `elastic_deployment` | Elastic Cloud deployment details |
| `elastic_password` | Elasticsearch password (sensitive) |
| `quick_start` | Quick reference for all endpoints |

## Useful Commands

```bash
# SSH to Cribl server
$(terraform output -raw cribl_ssh_command)

# View Cribl logs
sudo journalctl -u cribl -f

# View Fortinet simulator logs
sudo journalctl -u fortinet-simulator -f

# Restart Fortinet simulator
sudo systemctl restart fortinet-simulator

# Check syslog port is listening
ss -tlnup | grep 9514
```

## Cleanup

```bash
terraform destroy --auto-approve
```

## Troubleshooting

### No data in Cribl

1. Check the syslog source is configured and listening:
   ```bash
   ss -tlnup | grep 9514
   ```

2. Check the Fortinet simulator is running:
   ```bash
   sudo systemctl status fortinet-simulator
   ```

3. View Cribl worker logs:
   ```bash
   sudo tail -f /opt/cribl/log/cribl.log
   ```

### Cribl syslog port not listening

The syslog source is configured via `/opt/cribl/local/cribl/inputs.yml`. Restart Cribl if needed:
```bash
sudo systemctl restart cribl
```

## File Structure

```
terraform/
├── providers.tf          # AWS, Elastic Cloud, TLS providers
├── variables.tf          # Input variables
├── outputs.tf            # Output values
├── network.tf            # VPC, subnet, security groups
├── cribl.tf              # Cribl Stream EC2 + Fortinet simulator
├── elastic.tf            # Elastic Cloud deployment
├── terraform.tfvars      # Your configuration (not in git)
└── terraform.tfvars.example
```
