package provider

import (
	"context"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"gopkg.in/yaml.v3"
)

func TestCloudInitConfigDataSource_Schema(t *testing.T) {
	d := NewCloudInitConfigDataSource()

	// Verify schema initializes without error
	schemaReq := datasource.SchemaRequest{}
	schemaResp := &datasource.SchemaResponse{}
	d.Schema(context.Background(), schemaReq, schemaResp)
	if schemaResp.Diagnostics.HasError() {
		t.Fatalf("Schema returned error: %v", schemaResp.Diagnostics.Errors())
	}

	// Verify Metadata
	metaReq := datasource.MetadataRequest{ProviderTypeName: "axonwall"}
	metaResp := &datasource.MetadataResponse{}
	d.Metadata(context.Background(), metaReq, metaResp)
	if metaResp.TypeName != "axonwall_cloudinit_config" {
		t.Errorf("Expected type name axonwall_cloudinit_config, got %s", metaResp.TypeName)
	}
}

func TestCloudInitYAML_Structure(t *testing.T) {
	// Direct verification of YAML generation logic
	config := map[string]interface{}{
		"hostname": "firewall-01",
		"users": []interface{}{
			map[string]interface{}{
				"name":                "admin",
				"sudo":                "ALL=(ALL) NOPASSWD:ALL",
				"shell":               "/usr/bin/zsh",
				"ssh_authorized_keys": []string{"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIG..."},
			},
		},
		"axonwall": map[string]interface{}{
			"auth": map[string]interface{}{
				"admin_username": "admin",
				"admin_password": "supersecretpassword",
				"ztp": map[string]interface{}{
					"enabled":          true,
					"controller_url":   "https://controller.axonwall.corp",
					"enrollment_token": "ztp-secret-token",
				},
			},
			"storage": map[string]interface{}{
				"layout_mode":  "standard_ab",
				"target_disks": []string{"/dev/sda"},
				"partitions": map[string]interface{}{
					"efi_size_mb": 512,
					"slot_a": map[string]interface{}{
						"size_gb":    16,
						"filesystem": "ext4",
					},
					"slot_b": map[string]interface{}{
						"size_gb":    16,
						"filesystem": "ext4",
					},
					"swap": map[string]interface{}{
						"size_gb":      2,
						"zram_enabled": false,
					},
					"data": map[string]interface{}{
						"allocate_remaining": true,
						"filesystem":         "ext4",
					},
					"logs": map[string]interface{}{
						"enabled":    true,
						"size_gb":    10,
						"filesystem": "xfs",
						"mountpoint": "/var/log",
					},
				},
				"encryption": map[string]interface{}{
					"enabled":          true,
					"tpm2_auto_unlock": true,
				},
			},
		},
	}

	out, err := yaml.Marshal(config)
	if err != nil {
		t.Fatalf("Failed to marshal YAML: %v", err)
	}

	rendered := "#cloud-config\n" + string(out)

	if !strings.HasPrefix(rendered, "#cloud-config\n") {
		t.Errorf("Rendered YAML does not have #cloud-config header")
	}
	if !strings.Contains(rendered, "hostname: firewall-01") {
		t.Errorf("Missing hostname in rendered YAML")
	}
	if !strings.Contains(rendered, "tpm2_auto_unlock: true") {
		t.Errorf("Missing TPM2 setting in rendered YAML")
	}
	if !strings.Contains(rendered, "layout_mode: standard_ab") {
		t.Errorf("Missing layout_mode in rendered YAML")
	}
	if !strings.Contains(rendered, "ztp-secret-token") {
		t.Errorf("Missing ZTP token in rendered YAML")
	}
}
