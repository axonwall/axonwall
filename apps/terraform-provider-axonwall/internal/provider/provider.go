package provider

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/provider/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// Ensure axonwallProvider satisfies various provider interfaces.
var _ provider.Provider = &axonwallProvider{}

// axonwallProvider defines the provider implementation.
type axonwallProvider struct {
	version string
}

// axonwallProviderModel describes the provider data model.
type axonwallProviderModel struct {
	Endpoint           types.String `tfsdk:"endpoint"`
	Token              types.String `tfsdk:"token"`
	CaCert             types.String `tfsdk:"ca_cert"`
	InsecureSkipVerify types.Bool   `tfsdk:"insecure_skip_verify"`
	TimeoutSeconds     types.Int64  `tfsdk:"timeout_seconds"`
}

func (p *axonwallProvider) Metadata(ctx context.Context, req provider.MetadataRequest, resp *provider.MetadataResponse) {
	resp.TypeName = "axonwall"
	resp.Version = p.version
}

func (p *axonwallProvider) Schema(ctx context.Context, req provider.SchemaRequest, resp *provider.SchemaResponse) {
	resp.Schema = schema.Schema{
		Attributes: map[string]schema.Attribute{
			"endpoint": schema.StringAttribute{
				MarkdownDescription: "Axonwall API Endpoint (e.g. https://192.168.1.1:2966/api/v1)",
				Optional:            true,
			},
			"token": schema.StringAttribute{
				MarkdownDescription: "API Token for Axonwall authentication",
				Optional:            true,
				Sensitive:           true,
			},
			"ca_cert": schema.StringAttribute{
				MarkdownDescription: "PEM CA certificate string or path to CA bundle file for verifying self-signed appliance HTTPS",
				Optional:            true,
			},
			"insecure_skip_verify": schema.BoolAttribute{
				MarkdownDescription: "Skip TLS certificate verification (not recommended for production)",
				Optional:            true,
			},
			"timeout_seconds": schema.Int64Attribute{
				MarkdownDescription: "HTTP request timeout in seconds (default 150s to cover 120s daemon applies)",
				Optional:            true,
			},
		},
	}
}

func buildHTTPClient(caCert string, insecureSkipVerify bool, timeoutSeconds int64) (*http.Client, error) {
	if timeoutSeconds <= 0 {
		timeoutSeconds = 150
	}
	tlsCfg := &tls.Config{
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: insecureSkipVerify,
	}
	if ca := strings.TrimSpace(caCert); ca != "" {
		pemBytes := []byte(ca)
		if !strings.Contains(ca, "-----BEGIN") {
			readBytes, err := os.ReadFile(ca)
			if err != nil {
				return nil, err
			}
			pemBytes = readBytes
		}
		pool, err := x509.SystemCertPool()
		if err != nil || pool == nil {
			pool = x509.NewCertPool()
		}
		if ok := pool.AppendCertsFromPEM(pemBytes); !ok {
			return nil, os.ErrInvalid
		}
		tlsCfg.RootCAs = pool
	}
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.TLSClientConfig = tlsCfg
	return &http.Client{
		Timeout:   time.Duration(timeoutSeconds) * time.Second,
		Transport: tr,
	}, nil
}

func (p *axonwallProvider) Configure(ctx context.Context, req provider.ConfigureRequest, resp *provider.ConfigureResponse) {
	var data axonwallProviderModel

	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)

	if resp.Diagnostics.HasError() {
		return
	}

	endpoint := strings.TrimSpace(data.Endpoint.ValueString())
	if endpoint == "" {
		endpoint = strings.TrimSpace(os.Getenv("AXONWALL_ENDPOINT"))
	}
	if endpoint == "" {
		endpoint = "https://localhost:2966/api/v1"
	}
	endpoint = strings.TrimRight(endpoint, "/")

	token := data.Token.ValueString()
	if token == "" {
		token = os.Getenv("AXONWALL_TOKEN")
	}

	timeoutSec := int64(150)
	if !data.TimeoutSeconds.IsNull() && !data.TimeoutSeconds.IsUnknown() && data.TimeoutSeconds.ValueInt64() > 0 {
		timeoutSec = data.TimeoutSeconds.ValueInt64()
	}
	client, err := buildHTTPClient(data.CaCert.ValueString(), data.InsecureSkipVerify.ValueBool(), timeoutSec)
	if err != nil {
		resp.Diagnostics.AddError("Invalid Axonwall TLS configuration", err.Error())
		return
	}

	apiClient := &AxonwallClient{
		Endpoint: endpoint,
		Token:    token,
		Client:   client,
	}

	resp.DataSourceData = apiClient
	resp.ResourceData = apiClient
}

func (p *axonwallProvider) Resources(ctx context.Context) []func() resource.Resource {
	return []func() resource.Resource{
		NewDesiredStateResource,
	}
}

func (p *axonwallProvider) DataSources(ctx context.Context) []func() datasource.DataSource {
	return []func() datasource.DataSource{
		NewCloudInitConfigDataSource,
	}
}

func New(version string) func() provider.Provider {
	return func() provider.Provider {
		return &axonwallProvider{
			version: version,
		}
	}
}
