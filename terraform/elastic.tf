# Retrieve the latest Elastic Stack version
data "ec_stack" "latest" {
  version_regex = var.elastic_version
  region        = var.ec_region
}

# Elastic Cloud deployment for Cribl demo
resource "ec_deployment" "cribl_demo" {
  name                   = "cribl-elastic-demo"
  region                 = var.ec_region
  version                = data.ec_stack.latest.version
  deployment_template_id = var.deployment_template_id

  elasticsearch = {
    hot = {
      size        = var.elasticsearch_size
      zone_count  = var.elasticsearch_zone_count
      autoscaling = {}
    }
  }

  kibana = {
    size       = var.kibana_size
    zone_count = var.kibana_zone_count
  }

  integrations_server = {
    size       = var.integrations_server_size
    zone_count = var.integrations_server_zone_count
  }

  tags = {
    environment = "test"
    purpose     = "cribl-demo"
    project     = "cribl-elastic-demo"
  }
}
