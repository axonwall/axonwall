# Terraform / OpenTofu Provider for Axonwall (`terraform-provider-axonwall`)

Official HashiCorp Terraform Plugin Framework provider (`axonwall`) for declarative Infrastructure-as-Code (IaC) lifecycle management of Axonwall Next-Generation Firewalls, Cloud-Init zero-touch provisioning seeds, OpenZFS NAS pools, K3s clusters, and KVM/LXC workloads.

---

## Features

- **`axonwall_desired_state` Resource**: Reconciles the complete declarative `DesiredState` JSON schema against `/api/v1/state` and `/api/v1/apply` with atomic `nftables` compilation and Commit-Confirm rollback protection.
- **`axonwall_cloudinit_config` Data Source**: Renders validated `#cloud-config` YAML user-data payloads for unattended bare-metal ISO (`--unattended` / `cidata.iso`) and Cloud QCOW2 (`Proxmox VE`, `KVM/libvirt`, `OpenStack`) deployments, including A/B or ZFSBootMenu storage layouts, LUKS2 + TPM 2.0 PCR auto-unlock, SSH keys, Zero-Touch Provisioning (ZTP) enrollment, and initial `DesiredState`.

---

## Building & Local Installation

```bash
cd apps/terraform-provider-axonwall
go build -o terraform-provider-axonwall .
```

To use your locally compiled binary with Terraform or OpenTofu, add a `dev_overrides` block to `~/.terraformrc` (or `~/.tofurc`):

```hcl
provider_installation {
  dev_overrides {
    "axonwall/axonwall" = "/home/youruser/git/axonwall/apps/terraform-provider-axonwall"
  }
  direct {}
}
```

---

## Provider Configuration

```hcl
terraform {
  required_providers {
    axonwall = {
      source  = "axonwall/axonwall"
      version = "~> 0.11.64"
    }
  }
}

provider "axonwall" {
  endpoint = "https://10.80.0.200:2966/api/v1"
  token    = var.axonwall_api_token
}
```

### Provider Schema

| Attribute | Type | Required | Description |
| :--- | :--- | :--- | :--- |
| `endpoint` | `string` | Optional | Axonwall REST API base URL (defaults to `http://localhost:3000/api/v1`; use `https://<host>:2966/api/v1` on production appliances). |
| `token` | `string` (Sensitive) | Optional | Bearer token for Axonwall API authentication. |

---

## Resource: `axonwall_desired_state`

Manages the appliance's declarative desired state via `GET /state` and `POST /apply`.

```hcl
resource "axonwall_desired_state" "perimeter_fw" {
  state_json = jsonencode({
    version = 1
    system = {
      hostname         = "axonwall-edge-01"
      domain           = "corp.internal"
      timezone         = "UTC"
      flowtableOffload = true
    }
    interfaces = [
      {
        name        = "wan"
        device      = "eth0"
        role        = "wan"
        type        = "dhcp"
        enabled     = true
      },
      {
        name        = "lan"
        device      = "eth1"
        role        = "lan"
        type        = "static"
        ipv4Address = "10.80.0.1/24"
        enabled     = true
      }
    ]
    rules = [
      {
        action      = "pass"
        direction   = "in"
        interface   = "lan"
        protocol    = "any"
        source      = "lan_net"
        destination = "any"
        description = "Allow LAN outbound"
      }
    ]
  })
}
```

---

## Data Source: `axonwall_cloudinit_config`

Generates reproducible `#cloud-config` YAML (`data.axonwall_cloudinit_config.<name>.rendered`) ready to pass directly into Proxmox VE, libvirt/QEMU `cloudinit_disk`, or `xorriso` NoCloud ISOs:

```hcl
data "axonwall_cloudinit_config" "branch_fw" {
  hostname                = "branch-fw-01"
  fqdn                    = "branch-fw-01.corp.internal"
  timezone                = "America/Chicago"
  admin_username          = "admin"
  admin_password_hash     = var.admin_sha512_hash
  ssh_authorized_keys     = [var.ops_ssh_pubkey]

  # Zero-Touch Provisioning (ZTP) to central Fleet Controller
  ztp_enabled             = true
  ztp_controller_url      = "https://ctrl.corp.internal:2966"
  ztp_enrollment_token    = var.ztp_enrollment_token

  # Dual-Root A/B + System RAID1 + LUKS2 with TPM 2.0 auto-unlock
  storage_layout_mode          = "standard_ab"
  storage_target_disks         = ["/dev/nvme0n1", "/dev/nvme1n1"]
  storage_system_raid_enabled  = true
  storage_standby_enabled      = true
  storage_encryption_enabled   = true
  storage_tpm2_auto_unlock     = true
  storage_separate_log_partition = true
  storage_log_size_gb          = 10

  desired_state_json = jsonencode({
    capabilities = {
      firewallEnabled = true
      nasEnabled      = true
      k3sEnabled      = true
    }
  })
}

output "cloud_config_yaml" {
  value     = data.axonwall_cloudinit_config.branch_fw.rendered
  sensitive = true
}
```

---

## Running Tests

```bash
cd apps/terraform-provider-axonwall
go test -v ./internal/provider/...
```
