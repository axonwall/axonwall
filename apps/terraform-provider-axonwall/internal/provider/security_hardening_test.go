package provider

import (
	"context"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	dsschema "github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-go/tftypes"
)

func buildCloudInitConfigValue(t *testing.T, s dsschema.Schema, overrides map[string]tftypes.Value) tftypes.Value {
	t.Helper()
	objType := s.Type().TerraformType(context.Background()).(tftypes.Object)
	vals := make(map[string]tftypes.Value, len(objType.AttributeTypes))
	for k, typ := range objType.AttributeTypes {
		vals[k] = tftypes.NewValue(typ, nil)
	}
	for k, v := range overrides {
		vals[k] = v
	}
	return tftypes.NewValue(objType, vals)
}

func validateStringAttr(t *testing.T, s dsschema.Schema, attrName, value string) diag.Diagnostics {
	t.Helper()
	attr, ok := s.Attributes[attrName].(dsschema.StringAttribute)
	if !ok {
		t.Fatalf("expected StringAttribute %q in schema", attrName)
	}
	if len(attr.Validators) == 0 {
		t.Fatalf("expected StringAttribute %q to have at least one validator", attrName)
	}
	var all diag.Diagnostics
	for _, v := range attr.Validators {
		resp := &validator.StringResponse{}
		v.ValidateString(context.Background(), validator.StringRequest{
			Path:        path.Root(attrName),
			ConfigValue: types.StringValue(value),
		}, resp)
		all.Append(resp.Diagnostics...)
	}
	return all
}

func validateStringListAttr(t *testing.T, s dsschema.Schema, attrName string, items []string) diag.Diagnostics {
	t.Helper()
	attr, ok := s.Attributes[attrName].(dsschema.ListAttribute)
	if !ok {
		t.Fatalf("expected ListAttribute %q in schema", attrName)
	}
	if len(attr.Validators) == 0 {
		t.Fatalf("expected ListAttribute %q to have at least one validator", attrName)
	}
	vals := make([]types.String, 0, len(items))
	for _, item := range items {
		vals = append(vals, types.StringValue(item))
	}
	listVal, diags := types.ListValueFrom(context.Background(), types.StringType, vals)
	if diags.HasError() {
		t.Fatalf("ListValueFrom failed: %v", diags)
	}
	var all diag.Diagnostics
	for _, v := range attr.Validators {
		resp := &validator.ListResponse{}
		v.ValidateList(context.Background(), validator.ListRequest{
			Path:        path.Root(attrName),
			ConfigValue: listVal,
		}, resp)
		all.Append(resp.Diagnostics...)
	}
	return all
}

func TestWave2_CloudInitSchemaFormatValidators(t *testing.T) {
	ctx := context.Background()
	ds := NewCloudInitConfigDataSource()
	var sResp datasource.SchemaResponse
	ds.Schema(ctx, datasource.SchemaRequest{}, &sResp)
	if sResp.Diagnostics.HasError() {
		t.Fatalf("Schema failed: %v", sResp.Diagnostics)
	}
	s := sResp.Schema

	// String attribute positive & negative cases.
	stringCases := []struct {
		attr    string
		valid   []string
		invalid []string
	}{
		{
			attr:    "hostname",
			valid:   []string{"", "a", "firewall-01", "edge-01", "fw-single", "BranchFW01"},
			invalid: []string{"-bad", "bad-", "bad_host", "bad.host", "bad host", "bad\nhost", "   ", strings.Repeat("a", 64)},
		},
		{
			attr:    "fqdn",
			valid:   []string{"", "branch-fw-01.corp.internal", "fw01.local", "gw1"},
			invalid: []string{".bad.com", "bad..com", "bad-.com", "-bad.com", "bad host.com", "bad\n.com", strings.Repeat("a.", 130) + "com"},
		},
		{
			attr:    "timezone",
			valid:   []string{"", "UTC", "America/New_York", "America/Chicago", "America/Argentina/Buenos_Aires", "Etc/GMT+5", "Etc/GMT-10"},
			invalid: []string{"../UTC", "/etc/passwd", "America/New York", "UTC\necho", "   "},
		},
		{
			attr:    "admin_username",
			valid:   []string{"", "admin", "root", "ops_admin", "fw-admin1", "_svc"},
			invalid: []string{"-admin", "1admin", "admin.user", "admin:pass", "admin;id", "admin user", "admin\n", strings.Repeat("a", 33)},
		},
		{
			attr:    "admin_password",
			valid:   []string{"", "StrongPass!123"},
			invalid: []string{"line1\nline2", "line1\rline2", "null\x00byte"},
		},
		{
			attr: "admin_password_hash",
			valid: []string{
				"",
				"$6$rounds=656000$saltsalt$hashedpasswordvalue1234567890",
				"$6$testsalt$hashvalue123456",
				"$5$testsalt$hashvalue123456",
				"$y$j9T$testsalt$hashvalue123456",
				"$2b$12$K/SpwjtB.wOHJ/Nc6GVRDuc1h0rM1DfvziFRNPtk27P.c4yDr9njO",
				"$argon2id$v=19$m=65536,t=3,p=4$c2FsdHNhbHQ$aGFzaHZhbHVl",
				"scrypt$0123456789abcdef0123456789abcdef$0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			},
			invalid: []string{
				"plaintext-password",
				"!",
				"*",
				"$1$md5salt$weakhash",
				"$6$onlysalt",
				"$6$salt$bad:colon",
				"$6$salt$bad\nline",
				"   ",
			},
		},
		{
			attr:    "ztp_controller_url",
			valid:   []string{"", "https://ctrl.axonwall.corp", "https://ctrl.corp.internal:2966", "http://127.0.0.1:2966"},
			invalid: []string{"not-a-url", "ftp://ctrl.axonwall.corp", "javascript:alert(1)", "https://user:pass@ctrl.axonwall.corp", "https:///api", "https://ctrl.corp:99999", "https://ctrl.corp\n"},
		},
		{
			attr:    "ztp_enrollment_token",
			valid:   []string{"", "ztp_tok_12345"},
			invalid: []string{"   ", "tok\nnext", "tok\rnext", "tok\x00next"},
		},
		{
			attr:    "storage_encryption_passphrase",
			valid:   []string{"", "luks-recovery-passphrase"},
			invalid: []string{"pass\nnext", "pass\rnext", "pass\x00next"},
		},
	}

	for _, tc := range stringCases {
		for _, v := range tc.valid {
			if diags := validateStringAttr(t, s, tc.attr, v); diags.HasError() {
				t.Errorf("%s expected valid value %q, got errors: %v", tc.attr, v, diags.Errors())
			}
		}
		for _, bad := range tc.invalid {
			if diags := validateStringAttr(t, s, tc.attr, bad); !diags.HasError() {
				t.Errorf("%s expected invalid value %q to fail validation", tc.attr, bad)
			}
		}
	}

	// List attribute positive & negative cases.
	validPubKey := "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl ops@axonwall"
	if diags := validateStringListAttr(t, s, "ssh_authorized_keys", []string{
		validPubKey,
		"ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC7testkeydata1234567890==",
		"ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTY= ops@host",
		"sk-ssh-ed25519@openssh.com AAAAGnNrLXNzaC1lZDI1NTE5QG9wZW5zc2guY29tAAAA",
	}); diags.HasError() {
		t.Fatalf("expected valid SSH keys to pass, got: %v", diags.Errors())
	}
	for _, badKey := range []string{
		"",
		"not-an-ssh-key",
		"ssh-dss AAAAB3NzaC1kc3MAAACBAInvalidDSAKey1234567890",
		`command="/bin/sh" ` + validPubKey,
		"ssh-ed25519 short",
		"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIG...",
		validPubKey + "\nextra-line",
	} {
		if diags := validateStringListAttr(t, s, "ssh_authorized_keys", []string{badKey}); !diags.HasError() {
			t.Errorf("expected invalid SSH key %q to fail validation", badKey)
		}
	}

	if diags := validateStringListAttr(t, s, "starter_packs", []string{"enterprise-ngfw", "edge-branch"}); diags.HasError() {
		t.Fatalf("expected valid starter_packs to pass: %v", diags.Errors())
	}
	for _, badPack := range []string{"", "bad pack", "../escape", "UPPER"} {
		if diags := validateStringListAttr(t, s, "starter_packs", []string{badPack}); !diags.HasError() {
			t.Errorf("expected invalid starter_pack %q to fail validation", badPack)
		}
	}

	for _, diskAttr := range []string{"storage_target_disks", "zfs_extra_disks", "zfs_slog_disks", "zfs_l2arc_disks", "zfs_spare_disks"} {
		if diags := validateStringListAttr(t, s, diskAttr, []string{"/dev/sda", "/dev/nvme0n1", "/dev/disk/by-id/scsi-0QEMU_1"}); diags.HasError() {
			t.Errorf("%s expected valid disks to pass: %v", diskAttr, diags.Errors())
		}
		for _, badDisk := range []string{"", "/etc/passwd", "/dev/../etc/shadow", "sda", "/dev/sda;id", "/dev/sda/"} {
			if diags := validateStringListAttr(t, s, diskAttr, []string{badDisk}); !diags.HasError() {
				t.Errorf("%s expected invalid disk %q to fail validation", diskAttr, badDisk)
			}
		}
	}

	// desired_state_json IP/CIDR/hostname validation.
	validDesiredState := `{
		"version": 1,
		"system": {"hostname": "branch-fw-01", "dnsServers": ["1.1.1.1", "2606:4700:4700::1111"]},
		"interfaces": [
			{"name": "wan", "device": "eth0", "type": "dhcp"},
			{"name": "lan", "device": "eth1", "type": "static", "ipv4Address": "10.80.0.1/24", "ipv4Gateway": "10.80.0.254", "ipv6Address": "fd00:80::1/64", "ipv6Gateway": "fd00:80::fe"}
		],
		"routes": [{"network": "192.168.50.0/24", "gateway": "10.80.0.2"}],
		"gateways": [{"name": "gw1", "interface": "wan", "gatewayIp": "203.0.113.1", "monitorIp": "1.1.1.1"}],
		"rules": [{"action": "pass", "direction": "in", "interface": "lan", "source": "lan_net", "destination": "10.90.0.0/16"}],
		"wireguard": {"enabled": true, "address": "10.99.0.1/24, fd00:99::1/64", "peers": [{"name": "p1", "publicKey": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "allowedIps": ["10.99.0.2/32"]}]},
		"dhcp": {"subnets": [{"interface": "lan", "subnet": "10.80.0.0/24", "poolStart": "10.80.0.100", "poolEnd": "10.80.0.200", "routers": ["10.80.0.1"], "dnsServers": ["10.80.0.1"]}]}
	}`
	if diags := validateStringAttr(t, s, "desired_state_json", validDesiredState); diags.HasError() {
		t.Fatalf("expected valid desired_state_json to pass, got: %v", diags.Errors())
	}

	invalidDesiredStates := []struct {
		name string
		json string
	}{
		{"malformed json", `{bad`},
		{"null", `null`},
		{"array", `[1,2,3]`},
		{"trailing garbage", `{"version":1}{"extra":2}`},
		{"bad hostname", `{"system":{"hostname":"bad_host!"}}`},
		{"bad dns ip", `{"system":{"dnsServers":["not-an-ip"]}}`},
		{"bad ipv4 cidr", `{"interfaces":[{"name":"lan","ipv4Address":"10.0.0.999/24"}]}`},
		{"ipv6 in ipv4 field", `{"interfaces":[{"name":"lan","ipv4Address":"fd00::1/64"}]}`},
		{"bad ipv4 gateway", `{"interfaces":[{"name":"lan","ipv4Gateway":"bad-gw"}]}`},
		{"ipv4 in ipv6 field", `{"interfaces":[{"name":"lan","ipv6Address":"10.0.0.1/24"}]}`},
		{"bad route cidr", `{"routes":[{"network":"10.0.0.1","gateway":"10.0.0.254"}]}`},
		{"bad route gw", `{"routes":[{"network":"10.0.0.0/24","gateway":"not-ip"}]}`},
		{"bad rule endpoint", `{"rules":[{"source":"10.0.0.1; drop","destination":"any"}]}`},
		{"bad wg address", `{"wireguard":{"address":"10.99.0.1/99"}}`},
		{"bad wg peer allowedIps", `{"wireguard":{"peers":[{"allowedIps":["invalid-cidr"]}]}}`},
		{"bad dhcp subnet", `{"dhcp":{"subnets":[{"subnet":"not-a-cidr"}]}}`},
		{"bad dhcp poolStart", `{"dhcp":{"subnets":[{"poolStart":"999.0.0.1"}]}}`},
	}
	for _, tc := range invalidDesiredStates {
		if diags := validateStringAttr(t, s, "desired_state_json", tc.json); !diags.HasError() {
			t.Errorf("desired_state_json case %q unexpectedly passed validation", tc.name)
		}
	}

	// Verify ipOrCIDRValidator directly as well.
	ipV := ipOrCIDRValidator{allowIPv4: true, allowIPv6: true, allowIP: true, allowCIDR: true}
	ipResp := &validator.StringResponse{}
	ipV.ValidateString(ctx, validator.StringRequest{Path: path.Root("ip"), ConfigValue: types.StringValue("10.0.0.1/24")}, ipResp)
	if ipResp.Diagnostics.HasError() {
		t.Fatalf("expected 10.0.0.1/24 to pass ipOrCIDRValidator")
	}
	ipBad := &validator.StringResponse{}
	ipV.ValidateString(ctx, validator.StringRequest{Path: path.Root("ip"), ConfigValue: types.StringValue("300.1.1.1/24")}, ipBad)
	if !ipBad.Diagnostics.HasError() {
		t.Fatalf("expected 300.1.1.1/24 to fail ipOrCIDRValidator")
	}
}

func TestWave2_CloudInitPasswordHashPreferenceAndDedup(t *testing.T) {
	ctx := context.Background()
	ds := NewCloudInitConfigDataSource().(*CloudInitConfigDataSource)
	var sResp datasource.SchemaResponse
	ds.Schema(ctx, datasource.SchemaRequest{}, &sResp)

	pwAttr := sResp.Schema.Attributes["admin_password"].(dsschema.StringAttribute)
	if pwAttr.GetDeprecationMessage() == "" || !strings.Contains(pwAttr.GetDeprecationMessage(), "admin_password_hash") {
		t.Fatalf("expected admin_password schema attribute to deprecate in favor of admin_password_hash, got %q", pwAttr.GetDeprecationMessage())
	}

	hashVal := "$6$rounds=656000$saltsalt$hashedpasswordvalue1234567890"

	// 1. Both admin_password_hash and admin_password provided:
	//    hash wins, warning emitted, plaintext admin_password stripped from YAML.
	rawBoth := buildCloudInitConfigValue(t, sResp.Schema, map[string]tftypes.Value{
		"hostname":             tftypes.NewValue(tftypes.String, "fw-both"),
		"admin_password":       tftypes.NewValue(tftypes.String, "PlaintextLeak123!"),
		"admin_password_hash":  tftypes.NewValue(tftypes.String, hashVal),
		"ztp_enabled":          tftypes.NewValue(tftypes.Bool, true),
		"ztp_controller_url":   tftypes.NewValue(tftypes.String, "https://ctrl.axonwall.corp:2966"),
		"ztp_enrollment_token": tftypes.NewValue(tftypes.String, "ztp-once-only-secret"),
	})
	valResp := datasource.ValidateConfigResponse{}
	ds.ValidateConfig(ctx, datasource.ValidateConfigRequest{Config: tfsdk.Config{Schema: sResp.Schema, Raw: rawBoth}}, &valResp)
	if valResp.Diagnostics.HasError() {
		t.Fatalf("ValidateConfig unexpected error: %v", valResp.Diagnostics)
	}
	if len(valResp.Diagnostics.Warnings()) == 0 {
		t.Fatalf("expected ValidateConfig warning when admin_password is set alongside admin_password_hash")
	}

	readResp := datasource.ReadResponse{State: tfsdk.State{Schema: sResp.Schema}}
	ds.Read(ctx, datasource.ReadRequest{Config: tfsdk.Config{Schema: sResp.Schema, Raw: rawBoth}}, &readResp)
	if readResp.Diagnostics.HasError() {
		t.Fatalf("Read unexpected error: %v", readResp.Diagnostics)
	}
	if len(readResp.Diagnostics.Warnings()) == 0 {
		t.Fatalf("expected Read warning diagnostic preferring admin_password_hash")
	}
	var rendered types.String
	_ = readResp.State.GetAttribute(ctx, path.Root("rendered"), &rendered)
	yamlStr := rendered.ValueString()
	if strings.Contains(yamlStr, "PlaintextLeak123!") || strings.Contains(yamlStr, "admin_password:") {
		t.Fatalf("expected redundant plaintext admin_password to be stripped when admin_password_hash is set:\n%s", yamlStr)
	}
	if !strings.Contains(yamlStr, "admin_password_hash: "+hashVal) || !strings.Contains(yamlStr, "passwd: "+hashVal) {
		t.Fatalf("expected admin_password_hash and users[].passwd in rendered YAML:\n%s", yamlStr)
	}
	if strings.Contains(yamlStr, "ztp_token:") {
		t.Fatalf("expected redundant duplicated ztp_token field to be stripped:\n%s", yamlStr)
	}
	if !strings.Contains(yamlStr, "enrollment_token: ztp-once-only-secret") {
		t.Fatalf("expected canonical axonwall.auth.ztp.enrollment_token in YAML:\n%s", yamlStr)
	}

	// 2. Legacy admin_password only: emits deprecation warning diagnostic while keeping compatibility.
	rawPlain := buildCloudInitConfigValue(t, sResp.Schema, map[string]tftypes.Value{
		"hostname":       tftypes.NewValue(tftypes.String, "fw-plain"),
		"admin_password": tftypes.NewValue(tftypes.String, "LegacyOnlyPass!"),
	})
	plainResp := datasource.ReadResponse{State: tfsdk.State{Schema: sResp.Schema}}
	ds.Read(ctx, datasource.ReadRequest{Config: tfsdk.Config{Schema: sResp.Schema, Raw: rawPlain}}, &plainResp)
	if plainResp.Diagnostics.HasError() {
		t.Fatalf("Read unexpected error: %v", plainResp.Diagnostics)
	}
	if len(plainResp.Diagnostics.Warnings()) == 0 {
		t.Fatalf("expected deprecation warning diagnostic when plaintext admin_password is used")
	}
	_ = plainResp.State.GetAttribute(ctx, path.Root("rendered"), &rendered)
	if !strings.Contains(rendered.ValueString(), "admin_password: LegacyOnlyPass!") {
		t.Fatalf("expected legacy admin_password preserved when admin_password_hash is omitted:\n%s", rendered.ValueString())
	}

	// 3. admin_password_hash only: zero warnings/errors.
	rawHashOnly := buildCloudInitConfigValue(t, sResp.Schema, map[string]tftypes.Value{
		"hostname":            tftypes.NewValue(tftypes.String, "fw-hash"),
		"admin_password_hash": tftypes.NewValue(tftypes.String, hashVal),
	})
	hashResp := datasource.ReadResponse{State: tfsdk.State{Schema: sResp.Schema}}
	ds.Read(ctx, datasource.ReadRequest{Config: tfsdk.Config{Schema: sResp.Schema, Raw: rawHashOnly}}, &hashResp)
	if hashResp.Diagnostics.HasError() || len(hashResp.Diagnostics.Warnings()) > 0 {
		t.Fatalf("expected zero diagnostics for hash-only config, got: %v", hashResp.Diagnostics)
	}

	// 4. scrypt$ hash is kept in axonwall.auth.admin_password_hash without corrupting Linux users[].passwd.
	scryptHash := "scrypt$0123456789abcdef0123456789abcdef$0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	rawScrypt := buildCloudInitConfigValue(t, sResp.Schema, map[string]tftypes.Value{
		"hostname":            tftypes.NewValue(tftypes.String, "fw-scrypt"),
		"admin_password_hash": tftypes.NewValue(tftypes.String, scryptHash),
	})
	scryptResp := datasource.ReadResponse{State: tfsdk.State{Schema: sResp.Schema}}
	ds.Read(ctx, datasource.ReadRequest{Config: tfsdk.Config{Schema: sResp.Schema, Raw: rawScrypt}}, &scryptResp)
	if scryptResp.Diagnostics.HasError() {
		t.Fatalf("Read unexpected error: %v", scryptResp.Diagnostics)
	}
	_ = scryptResp.State.GetAttribute(ctx, path.Root("rendered"), &rendered)
	if !strings.Contains(rendered.ValueString(), "admin_password_hash: "+scryptHash) {
		t.Fatalf("expected scrypt hash in axonwall.auth.admin_password_hash:\n%s", rendered.ValueString())
	}
	if strings.Contains(rendered.ValueString(), "passwd: "+scryptHash) {
		t.Fatalf("did not expect scrypt$ web hash in Linux users[].passwd:\n%s", rendered.ValueString())
	}
}

func TestWave2_BuildHTTPClientBlocksRedirectsAndDowngrades(t *testing.T) {
	var targetHits atomic.Int32
	var seenAuth atomic.Value
	targetSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		targetHits.Add(1)
		seenAuth.Store(r.Header.Get("Authorization"))
		w.WriteHeader(http.StatusOK)
	}))
	defer targetSrv.Close()

	// 1. Same-origin redirect refused.
	var sameOriginHits atomic.Int32
	var sameSrv *httptest.Server
	sameSrv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/final" {
			sameOriginHits.Add(1)
			w.WriteHeader(http.StatusOK)
			return
		}
		http.Redirect(w, r, sameSrv.URL+"/final", http.StatusFound)
	}))
	defer sameSrv.Close()

	client, err := buildHTTPClient("", false, 10)
	if err != nil {
		t.Fatalf("buildHTTPClient failed: %v", err)
	}
	req1, _ := http.NewRequest("GET", sameSrv.URL+"/start", nil)
	req1.Header.Set("Authorization", "Bearer super-secret-token")
	if _, err := client.Do(req1); err == nil || !strings.Contains(err.Error(), "redirect refused") {
		t.Fatalf("expected same-origin redirect to be refused, got: %v", err)
	}
	if sameOriginHits.Load() != 0 {
		t.Fatalf("redirect target /final should never have been requested")
	}

	// 2. Cross-origin HTTP redirect refused without leaking Authorization header.
	crossSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, targetSrv.URL+"/steal", http.StatusTemporaryRedirect)
	}))
	defer crossSrv.Close()

	req2, _ := http.NewRequest("POST", crossSrv.URL+"/apply", strings.NewReader(`{}`))
	req2.Header.Set("Authorization", "Bearer super-secret-token")
	if _, err := client.Do(req2); err == nil || !strings.Contains(err.Error(), "cross-origin redirect") {
		t.Fatalf("expected cross-origin redirect error, got: %v", err)
	}
	if targetHits.Load() != 0 || seenAuth.Load() != nil {
		t.Fatalf("cross-origin redirect target must never be hit")
	}

	// 3. HTTPS -> HTTP downgrade redirect explicitly blocked.
	tlsSrv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, targetSrv.URL+"/downgrade", http.StatusFound)
	}))
	defer tlsSrv.Close()
	leafPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: tlsSrv.Certificate().Raw}))

	tlsClient, err := buildHTTPClient(leafPEM, false, 10)
	if err != nil {
		t.Fatalf("buildHTTPClient with TLS leaf CA failed: %v", err)
	}
	req3, _ := http.NewRequest("GET", tlsSrv.URL+"/state", nil)
	req3.Header.Set("Authorization", "Bearer super-secret-token")
	if _, err := tlsClient.Do(req3); err == nil || !strings.Contains(err.Error(), "downgrade") {
		t.Fatalf("expected HTTPS->HTTP downgrade redirect error, got: %v", err)
	}
	if targetHits.Load() != 0 {
		t.Fatalf("HTTP downgrade target must never be contacted")
	}
}

func buildProviderConfigValue(t *testing.T, p provider.Provider, overrides map[string]tftypes.Value) (tfsdk.Config, provider.SchemaResponse) {
	t.Helper()
	var sResp provider.SchemaResponse
	p.Schema(context.Background(), provider.SchemaRequest{}, &sResp)
	objType := sResp.Schema.Type().TerraformType(context.Background()).(tftypes.Object)
	vals := make(map[string]tftypes.Value, len(objType.AttributeTypes))
	for k, typ := range objType.AttributeTypes {
		vals[k] = tftypes.NewValue(typ, nil)
	}
	for k, v := range overrides {
		vals[k] = v
	}
	return tfsdk.Config{Schema: sResp.Schema, Raw: tftypes.NewValue(objType, vals)}, sResp
}

func TestWave2_ProviderEndpointSecurityPolicy(t *testing.T) {
	ctx := context.Background()
	p := New("test")().(*axonwallProvider)

	// Ensure env vars don't leak between cases.
	clearEnv := func() {
		t.Setenv("AXONWALL_ENDPOINT", "")
		t.Setenv("AXONWALL_ALLOW_INSECURE_HTTP", "")
	}

	// 1. Loopback HTTP allowed without allow_insecure_http and without warnings.
	for _, ep := range []string{
		"http://127.0.0.1:18080/api/v1",
		"http://localhost:3000/api/v1",
		"http://[::1]:3000/api/v1",
	} {
		clearEnv()
		cfg, _ := buildProviderConfigValue(t, p, map[string]tftypes.Value{
			"endpoint": tftypes.NewValue(tftypes.String, ep),
		})
		valResp := &provider.ValidateConfigResponse{}
		p.ValidateConfig(ctx, provider.ValidateConfigRequest{Config: cfg}, valResp)
		if valResp.Diagnostics.HasError() || len(valResp.Diagnostics.Warnings()) > 0 {
			t.Errorf("loopback %s ValidateConfig failed unexpectedly: %v", ep, valResp.Diagnostics)
		}
		cfgResp := &provider.ConfigureResponse{}
		p.Configure(ctx, provider.ConfigureRequest{Config: cfg}, cfgResp)
		if cfgResp.Diagnostics.HasError() || len(cfgResp.Diagnostics.Warnings()) > 0 {
			t.Errorf("loopback %s Configure failed unexpectedly: %v", ep, cfgResp.Diagnostics)
		}
		if cfgResp.ResourceData == nil {
			t.Errorf("expected ResourceData configured for loopback %s", ep)
		}
	}

	// 2. Non-loopback HTTP rejected fail-closed without allow_insecure_http.
	for _, ep := range []string{
		"http://10.80.0.200:3000/api/v1",
		"http://axonwall.corp:3000/api/v1",
		"http://localhost.evil.com:3000/api/v1",
		"http://0.0.0.0:3000/api/v1",
	} {
		clearEnv()
		cfg, _ := buildProviderConfigValue(t, p, map[string]tftypes.Value{
			"endpoint": tftypes.NewValue(tftypes.String, ep),
		})
		valResp := &provider.ValidateConfigResponse{}
		p.ValidateConfig(ctx, provider.ValidateConfigRequest{Config: cfg}, valResp)
		if !valResp.Diagnostics.HasError() {
			t.Errorf("expected ValidateConfig to reject non-loopback HTTP %s", ep)
		}
		cfgResp := &provider.ConfigureResponse{}
		p.Configure(ctx, provider.ConfigureRequest{Config: cfg}, cfgResp)
		if !cfgResp.Diagnostics.HasError() {
			t.Errorf("expected Configure to reject non-loopback HTTP %s", ep)
		}
	}

	// 3. Env var AXONWALL_ENDPOINT non-loopback HTTP rejected fail-closed.
	clearEnv()
	t.Setenv("AXONWALL_ENDPOINT", "http://192.168.1.1:3000/api/v1")
	emptyCfg, _ := buildProviderConfigValue(t, p, nil)
	envRejectResp := &provider.ConfigureResponse{}
	p.Configure(ctx, provider.ConfigureRequest{Config: emptyCfg}, envRejectResp)
	if !envRejectResp.Diagnostics.HasError() {
		t.Fatalf("expected AXONWALL_ENDPOINT non-loopback HTTP to be rejected by default")
	}

	// 4. Explicit allow_insecure_http = true allows non-loopback HTTP with warning.
	clearEnv()
	allowCfg, _ := buildProviderConfigValue(t, p, map[string]tftypes.Value{
		"endpoint":            tftypes.NewValue(tftypes.String, "http://10.80.0.200:3000/api/v1"),
		"allow_insecure_http": tftypes.NewValue(tftypes.Bool, true),
	})
	allowResp := &provider.ConfigureResponse{}
	p.Configure(ctx, provider.ConfigureRequest{Config: allowCfg}, allowResp)
	if allowResp.Diagnostics.HasError() {
		t.Fatalf("expected allow_insecure_http=true to permit non-loopback HTTP, got: %v", allowResp.Diagnostics)
	}
	if len(allowResp.Diagnostics.Warnings()) == 0 {
		t.Fatalf("expected warning diagnostic when allow_insecure_http=true on non-loopback HTTP")
	}

	// 5. Env var AXONWALL_ALLOW_INSECURE_HTTP=true allows non-loopback HTTP with warning.
	clearEnv()
	t.Setenv("AXONWALL_ENDPOINT", "http://10.80.0.200:3000/api/v1")
	t.Setenv("AXONWALL_ALLOW_INSECURE_HTTP", "true")
	envAllowResp := &provider.ConfigureResponse{}
	p.Configure(ctx, provider.ConfigureRequest{Config: emptyCfg}, envAllowResp)
	if envAllowResp.Diagnostics.HasError() || len(envAllowResp.Diagnostics.Warnings()) == 0 {
		t.Fatalf("expected AXONWALL_ALLOW_INSECURE_HTTP=true to allow with warning, got: %v", envAllowResp.Diagnostics)
	}

	// 6. Explicit allow_insecure_http = false overrides AXONWALL_ALLOW_INSECURE_HTTP=true.
	clearEnv()
	t.Setenv("AXONWALL_ALLOW_INSECURE_HTTP", "true")
	overrideCfg, _ := buildProviderConfigValue(t, p, map[string]tftypes.Value{
		"endpoint":            tftypes.NewValue(tftypes.String, "http://10.80.0.200:3000/api/v1"),
		"allow_insecure_http": tftypes.NewValue(tftypes.Bool, false),
	})
	overrideResp := &provider.ConfigureResponse{}
	p.Configure(ctx, provider.ConfigureRequest{Config: overrideCfg}, overrideResp)
	if !overrideResp.Diagnostics.HasError() {
		t.Fatalf("expected explicit allow_insecure_http=false to override env var and reject non-loopback HTTP")
	}

	// 7. Invalid AXONWALL_ALLOW_INSECURE_HTTP value fails closed.
	clearEnv()
	t.Setenv("AXONWALL_ALLOW_INSECURE_HTTP", "definitely")
	badEnvResp := &provider.ConfigureResponse{}
	p.Configure(ctx, provider.ConfigureRequest{Config: emptyCfg}, badEnvResp)
	if !badEnvResp.Diagnostics.HasError() {
		t.Fatalf("expected invalid AXONWALL_ALLOW_INSECURE_HTTP to fail closed")
	}

	// 8. Unsupported scheme or embedded credentials rejected; HTTPS succeeds cleanly.
	for _, badEP := range []string{
		"ftp://10.80.0.200/api/v1",
		"https://admin:secret@10.80.0.200:2966/api/v1",
	} {
		clearEnv()
		badCfg, _ := buildProviderConfigValue(t, p, map[string]tftypes.Value{
			"endpoint": tftypes.NewValue(tftypes.String, badEP),
		})
		badResp := &provider.ConfigureResponse{}
		p.Configure(ctx, provider.ConfigureRequest{Config: badCfg}, badResp)
		if !badResp.Diagnostics.HasError() {
			t.Errorf("expected Configure to reject %q", badEP)
		}
	}

	clearEnv()
	httpsCfg, _ := buildProviderConfigValue(t, p, map[string]tftypes.Value{
		"endpoint": tftypes.NewValue(tftypes.String, "https://10.80.0.200:2966/api/v1/"),
	})
	httpsResp := &provider.ConfigureResponse{}
	p.Configure(ctx, provider.ConfigureRequest{Config: httpsCfg}, httpsResp)
	if httpsResp.Diagnostics.HasError() || len(httpsResp.Diagnostics.Warnings()) > 0 {
		t.Fatalf("expected clean HTTPS config, got: %v", httpsResp.Diagnostics)
	}
	if apiClient, ok := httpsResp.ResourceData.(*AxonwallClient); !ok || apiClient.Endpoint != "https://10.80.0.200:2966/api/v1" {
		t.Fatalf("unexpected ResourceData: %#v", httpsResp.ResourceData)
	}
}

func TestWave2_DesiredStateReadFailsClosedOnCorruptPriorState(t *testing.T) {
	ctx := context.Background()
	res := NewDesiredStateResource().(*DesiredStateResource)
	var sResp resource.SchemaResponse
	res.Schema(ctx, resource.SchemaRequest{}, &sResp)

	serverBody := `{
	  "version": 1,
	  "system": {"hostname": "gw1"},
	  "wireguard": {"privateKey": "TOP_SECRET_WG_KEY_SHOULD_NOT_LEAK"},
	  "mcp": {"keys": [{"token": "SECRET_MCP_TOKEN_SHOULD_NOT_LEAK"}]}
	}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(serverBody))
	}))
	defer srv.Close()
	res.client = &AxonwallClient{Endpoint: srv.URL, Token: "tok", Client: srv.Client()}

	objType := sResp.Schema.Type().TerraformType(ctx).(tftypes.Object)
	for _, corruptPrior := range []string{
		`{corrupt-json`,
		`{"version":1} trailing`,
		`   `,
		``,
		`null`,
		`[]`,
		`123`,
	} {
		rawState := tftypes.NewValue(objType, map[string]tftypes.Value{
			"state_json": tftypes.NewValue(tftypes.String, corruptPrior),
		})
		readResp := resource.ReadResponse{State: tfsdk.State{Schema: sResp.Schema, Raw: rawState}}
		res.Read(ctx, resource.ReadRequest{State: tfsdk.State{Schema: sResp.Schema, Raw: rawState}}, &readResp)
		if !readResp.Diagnostics.HasError() {
			t.Fatalf("expected Read to fail closed for corrupt prior state_json %q", corruptPrior)
		}
		var got types.String
		_ = readResp.State.GetAttribute(ctx, path.Root("state_json"), &got)
		if strings.Contains(got.ValueString(), "TOP_SECRET_WG_KEY_SHOULD_NOT_LEAK") || strings.Contains(got.ValueString(), "SECRET_MCP_TOKEN_SHOULD_NOT_LEAK") {
			t.Fatalf("Read leaked unprojected /state secrets on corrupt prior state_json %q: %s", corruptPrior, got.ValueString())
		}
		if got.ValueString() != corruptPrior {
			t.Fatalf("expected prior state_json %q to remain unmodified on error, got %q", corruptPrior, got.ValueString())
		}
	}

	// Null prior state (e.g., initial unpopulated state) continues to populate cleanly.
	nullState := tftypes.NewValue(objType, map[string]tftypes.Value{
		"state_json": tftypes.NewValue(tftypes.String, nil),
	})
	nullResp := resource.ReadResponse{State: tfsdk.State{Schema: sResp.Schema, Raw: nullState}}
	res.Read(ctx, resource.ReadRequest{State: tfsdk.State{Schema: sResp.Schema, Raw: nullState}}, &nullResp)
	if nullResp.Diagnostics.HasError() {
		t.Fatalf("expected Read with null prior state_json to succeed, got: %v", nullResp.Diagnostics)
	}
}
