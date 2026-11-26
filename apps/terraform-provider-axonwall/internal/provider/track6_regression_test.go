package provider

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-go/tftypes"
)

func TestTrack6_DesiredStateSensitivePlanModifierAndNoDrift(t *testing.T) {
	ctx := context.Background()
	res := NewDesiredStateResource().(*DesiredStateResource)

	var sResp resource.SchemaResponse
	res.Schema(ctx, resource.SchemaRequest{}, &sResp)
	if sResp.Diagnostics.HasError() {
		t.Fatalf("Schema error: %v", sResp.Diagnostics)
	}
	attr := sResp.Schema.Attributes["state_json"]
	if !attr.IsSensitive() {
		t.Fatalf("expected state_json attribute to have Sensitive: true")
	}

	// Test semanticJSONPlanModifier ignores whitespace and key order differences.
	pm := semanticJSONPlanModifier{}
	planReq := planmodifier.StringRequest{
		PlanValue:  types.StringValue("{\n  \"version\": 1,\n  \"system\": { \"hostname\": \"gw1\", \"domain\": \"local\" }\n}"),
		StateValue: types.StringValue(`{"system":{"domain":"local","hostname":"gw1"},"version":1}`),
	}
	planResp := &planmodifier.StringResponse{PlanValue: planReq.PlanValue}
	pm.PlanModifyString(ctx, planReq, planResp)
	if !planResp.PlanValue.Equal(planReq.StateValue) {
		t.Fatalf("expected semantically equal JSON to preserve StateValue without diff, got %q", planResp.PlanValue.ValueString())
	}

	// Test Read against server-expanded response containing extra defaults and secrets.
	serverBody := `{
	  "version": 1,
	  "system": {"hostname": "gw1", "domain": "local", "antiLockout": {"enabled": true}},
	  "interfaces": [{"name": "lan", "device": "eth1", "mtu": 1500, "id": "srv-uuid"}],
	  "wireguard": {"privateKey": "TOP_SECRET_WG_KEY"},
	  "mcp": {"keys": [{"token": "SECRET_MCP_TOKEN"}]}
	}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(serverBody))
	}))
	defer srv.Close()

	res.client = &AxonwallClient{Endpoint: srv.URL, Token: "tok", Client: srv.Client()}

	priorJSON := `{"interfaces":[{"device":"eth1","name":"lan"}],"system":{"domain":"local","hostname":"gw1"},"version":1}`
	objType := sResp.Schema.Type().TerraformType(ctx).(tftypes.Object)
	rawState := tftypes.NewValue(objType, map[string]tftypes.Value{
		"state_json": tftypes.NewValue(tftypes.String, priorJSON),
	})
	readResp := resource.ReadResponse{State: tfsdk.State{Schema: sResp.Schema, Raw: rawState}}
	res.Read(ctx, resource.ReadRequest{State: tfsdk.State{Schema: sResp.Schema, Raw: rawState}}, &readResp)
	if readResp.Diagnostics.HasError() {
		t.Fatalf("Read failed: %v", readResp.Diagnostics)
	}
	var got types.String
	_ = readResp.State.GetAttribute(ctx, path.Root("state_json"), &got)
	if got.ValueString() != priorJSON {
		t.Fatalf("expected server-expanded defaults not to cause perpetual drift; got:\n%s", got.ValueString())
	}
	if strings.Contains(got.ValueString(), "TOP_SECRET_WG_KEY") || strings.Contains(got.ValueString(), "SECRET_MCP_TOKEN") {
		t.Fatalf("Read leaked unmanaged appliance secrets into Terraform state")
	}

	// Verify real out-of-band drift on a managed key IS detected.
	driftedPrior := `{"system":{"hostname":"old-gw"},"version":1}`
	rawDrifted := tftypes.NewValue(objType, map[string]tftypes.Value{
		"state_json": tftypes.NewValue(tftypes.String, driftedPrior),
	})
	driftResp := resource.ReadResponse{State: tfsdk.State{Schema: sResp.Schema, Raw: rawDrifted}}
	res.Read(ctx, resource.ReadRequest{State: tfsdk.State{Schema: sResp.Schema, Raw: rawDrifted}}, &driftResp)
	var gotDrifted types.String
	_ = driftResp.State.GetAttribute(ctx, path.Root("state_json"), &gotDrifted)
	if !strings.Contains(gotDrifted.ValueString(), `"hostname":"gw1"`) {
		t.Fatalf("expected managed field drift to be reflected in state, got %s", gotDrifted.ValueString())
	}
}

func TestTrack6_ApplyStateFailsOnBadConfirmBody(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []struct {
		name        string
		confirmBody string
	}{
		{name: "empty body", confirmBody: ""},
		{name: "html proxy page", confirmBody: "<html><body>502 Bad Gateway</body></html>"},
		{name: "missing success", confirmBody: `{"status":"ok"}`},
		{name: "status error", confirmBody: `{"status":"error","error":"not pending"}`},
		{name: "success false", confirmBody: `{"status":"ok","data":{"success":false,"message":"rollback already fired"}}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/apply" {
					_, _ = w.Write([]byte(`{"status":"ok","data":{"success":true,"jobId":"j1"}}`))
					return
				}
				_, _ = w.Write([]byte(tc.confirmBody))
			}))
			defer srv.Close()

			res := &DesiredStateResource{
				client: &AxonwallClient{Endpoint: srv.URL, Token: "tok", Client: srv.Client()},
			}
			if err := res.applyState(ctx, `{"version":1}`); err == nil {
				t.Fatalf("expected applyState to fail when /confirm returned %q", tc.confirmBody)
			}
		})
	}
}

func TestTrack6_CloudInitEmitsV0162FlatKeysGuardsEmptyZTPAndValidates(t *testing.T) {
	ctx := context.Background()
	ds := NewCloudInitConfigDataSource().(*CloudInitConfigDataSource)
	var sResp datasource.SchemaResponse
	ds.Schema(ctx, datasource.SchemaRequest{}, &sResp)

	objType := sResp.Schema.Type().TerraformType(ctx).(tftypes.Object)
	vals := make(map[string]tftypes.Value, len(objType.AttributeTypes))
	for k, typ := range objType.AttributeTypes {
		vals[k] = tftypes.NewValue(typ, nil)
	}
	vals["hostname"] = tftypes.NewValue(tftypes.String, "edge-01")
	vals["edition"] = tftypes.NewValue(tftypes.String, "axonwall")
	vals["install_mode"] = tftypes.NewValue(tftypes.String, "zbm")
	vals["allow_wipe_existing"] = tftypes.NewValue(tftypes.Bool, true)
	vals["starter_packs"] = tftypes.NewValue(tftypes.List{ElementType: tftypes.String}, []tftypes.Value{
		tftypes.NewValue(tftypes.String, "enterprise-ngfw"),
	})
	vals["ztp_enabled"] = tftypes.NewValue(tftypes.Bool, true)
	vals["ztp_controller_url"] = tftypes.NewValue(tftypes.String, "")
	vals["ztp_enrollment_token"] = tftypes.NewValue(tftypes.String, "")
	vals["storage_target_disks"] = tftypes.NewValue(tftypes.List{ElementType: tftypes.String}, []tftypes.Value{
		tftypes.NewValue(tftypes.String, "/dev/nvme0n1"),
		tftypes.NewValue(tftypes.String, "/dev/nvme1n1"),
	})
	vals["storage_system_raid_enabled"] = tftypes.NewValue(tftypes.Bool, true)
	vals["storage_root_size_gb"] = tftypes.NewValue(tftypes.Number, 24)
	vals["storage_encryption_enabled"] = tftypes.NewValue(tftypes.Bool, true)
	vals["storage_tpm2_auto_unlock"] = tftypes.NewValue(tftypes.Bool, true)
	vals["zfs_alloc_mode"] = tftypes.NewValue(tftypes.String, "remainder")
	vals["zfs_raid_topology"] = tftypes.NewValue(tftypes.String, "mirror")

	raw := tftypes.NewValue(objType, vals)
	req := datasource.ReadRequest{Config: tfsdk.Config{Schema: sResp.Schema, Raw: raw}}
	resp := datasource.ReadResponse{State: tfsdk.State{Schema: sResp.Schema}}
	ds.Read(ctx, req, &resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("Read error: %v", resp.Diagnostics)
	}
	var renderedVal types.String
	_ = resp.State.GetAttribute(ctx, path.Root("rendered"), &renderedVal)
	rendered := renderedVal.ValueString()

	for _, want := range []string{
		"edition: axonwall",
		"install_mode: zbm",
		"target_disk: /dev/nvme0n1",
		"system_raid_disks:",
		"allow_wipe_existing: true",
		"slot_size_gb: 24",
		"luks_enabled: true",
		"luks_tpm2: true",
		"zfs_alloc_mode: remainder",
		"zfs_raid_topology: mirror",
		"starter_packs:",
	} {
		if !strings.Contains(rendered, want) {
			t.Fatalf("expected %q in rendered cloud-config, got:\n%s", want, rendered)
		}
	}
	if strings.Contains(rendered, "controller_url:") || strings.Contains(rendered, "enrollment_token:") {
		t.Fatalf("expected empty ztp_controller_url/ztp_enrollment_token to be omitted, got:\n%s", rendered)
	}

	// Verify numeric range & enum validators reject out-of-bounds values.
	efiV := int64RangeValidator{min: 128, max: 4096}
	vResp := &validator.Int64Response{}
	efiV.ValidateInt64(ctx, validator.Int64Request{Path: path.Root("storage_efi_size_mb"), ConfigValue: types.Int64Value(64)}, vResp)
	if !vResp.Diagnostics.HasError() {
		t.Fatalf("expected storage_efi_size_mb=64 to fail validation")
	}

	rootV := int64RangeValidator{min: 4, max: 1 << 30}
	rResp := &validator.Int64Response{}
	rootV.ValidateInt64(ctx, validator.Int64Request{Path: path.Root("storage_root_size_gb"), ConfigValue: types.Int64Value(2)}, rResp)
	if !rResp.Diagnostics.HasError() {
		t.Fatalf("expected storage_root_size_gb=2 to fail validation")
	}

	edV := stringOneOfValidator{allowed: []string{"axonwall", "minimal", "vault", "k3s-storage"}}
	sVResp := &validator.StringResponse{}
	edV.ValidateString(ctx, validator.StringRequest{Path: path.Root("edition"), ConfigValue: types.StringValue("bogus")}, sVResp)
	if !sVResp.Diagnostics.HasError() {
		t.Fatalf("expected edition=bogus to fail validation")
	}
}
