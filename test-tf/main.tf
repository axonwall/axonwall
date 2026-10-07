terraform {
  required_providers {
    axonwall = {
      source = "registry.terraform.io/axonwall/axonwall"
    }
  }
}

provider "axonwall" {
  endpoint = "http://localhost:3000/api/v1"
  token    = "dev-test-token-123"
}

resource "axonwall_desired_state" "test" {
  state_json = jsonencode({
    version = 1
    system = {
      hostname = "axonwall-tf"
      domain = "local"
      dnsServers = ["8.8.8.8"]
      timezone = "UTC"
      flowtableOffload = false
      antiLockout = {
        enabled = true
        interface = "lan"
        ports = [22, 443]
      }
    }
    network = {
      interfaces = []
    }
    firewall = {
      aliases = []
      rules = []
    }
  })
}
