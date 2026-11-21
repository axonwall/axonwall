package provider

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-go/tftypes"
)

func TestBugHunt4_ApplyStateChecksSuccessAndPropagatesJobID(t *testing.T) {
	var seenConfirmJobID string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/apply":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"status":"ok","data":{"success":true,"jobId":"ui-server-999","message":"applied"}}`))
		case "/confirm":
			var body map[string]string
			_ = json.NewDecoder(r.Body).Decode(&body)
			seenConfirmJobID = body["jobId"]
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"status":"ok","data":{"success":true}}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	res := &DesiredStateResource{
		client: &AxonwallClient{Endpoint: srv.URL, Token: "tok", Client: srv.Client()},
	}
	if err := res.applyState(context.Background(), `{"version":"1","interfaces":[]}`); err != nil {
		t.Fatalf("applyState failed: %v", err)
	}
	if seenConfirmJobID != "ui-server-999" {
		t.Fatalf("expected confirm to receive server jobId 'ui-server-999', got %q", seenConfirmJobID)
	}

	// Reject /apply 200 OK with data.success == false
	failSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"ok","data":{"success":false,"message":"nftables invalid"}}`))
	}))
	defer failSrv.Close()
	failRes := &DesiredStateResource{
		client: &AxonwallClient{Endpoint: failSrv.URL, Token: "tok", Client: failSrv.Client()},
	}
	if err := failRes.applyState(context.Background(), `{"version":"1"}`); err == nil || !strings.Contains(err.Error(), "nftables invalid") {
		t.Fatalf("expected applyState to fail on data.success=false, got: %v", err)
	}
}

func TestBugHunt4_BuildHTTPClientWithCustomCA(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test-ca"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		IsCA:         true,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatal(err)
	}
	caPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))

	client, err := buildHTTPClient(caPEM, false, 0)
	if err != nil {
		t.Fatalf("buildHTTPClient failed: %v", err)
	}
	if client.Timeout != 150*time.Second {
		t.Fatalf("expected default timeout 150s, got %v", client.Timeout)
	}
}

func TestBugHunt4_CloudInitSingleRootOmitsSlotB(t *testing.T) {
	ds := NewCloudInitConfigDataSource()
	var sResp datasource.SchemaResponse
	ds.Schema(context.Background(), datasource.SchemaRequest{}, &sResp)

	objType := sResp.Schema.Type().TerraformType(context.Background()).(tftypes.Object)
	vals := make(map[string]tftypes.Value, len(objType.AttributeTypes))
	for k, typ := range objType.AttributeTypes {
		vals[k] = tftypes.NewValue(typ, nil)
	}
	vals["hostname"] = tftypes.NewValue(tftypes.String, "fw-single")
	vals["storage_layout_mode"] = tftypes.NewValue(tftypes.String, "single_root")
	raw := tftypes.NewValue(objType, vals)

	req := datasource.ReadRequest{Config: tfsdk.Config{Schema: sResp.Schema, Raw: raw}}
	resp := datasource.ReadResponse{State: tfsdk.State{Schema: sResp.Schema}}
	ds.Read(context.Background(), req, &resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("datasource Read diagnostics: %v", resp.Diagnostics)
	}
	var rendered types.String
	_ = resp.State.GetAttribute(context.Background(), path.Root("rendered"), &rendered)
	if !strings.Contains(rendered.ValueString(), "layout_mode: single_root") {
		t.Fatalf("expected rendered YAML to contain layout_mode: single_root, got:\n%s", rendered.ValueString())
	}
	if strings.Contains(rendered.ValueString(), "slot_b:") {
		t.Fatalf("expected single_root layout without storage_standby_enabled to omit slot_b:\n%s", rendered.ValueString())
	}
}
