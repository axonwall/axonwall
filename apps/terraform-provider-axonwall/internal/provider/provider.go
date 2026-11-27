package provider

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/provider/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// Ensure axonwallProvider satisfies various provider interfaces.
var (
	_ provider.Provider                   = &axonwallProvider{}
	_ provider.ProviderWithValidateConfig = &axonwallProvider{}
)

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
	AllowInsecureHTTP  types.Bool   `tfsdk:"allow_insecure_http"`
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
			"allow_insecure_http": schema.BoolAttribute{
				MarkdownDescription: "Allow plaintext http:// connections to non-loopback endpoints (not recommended; sends API tokens in cleartext). Can also be set via AXONWALL_ALLOW_INSECURE_HTTP=true.",
				Optional:            true,
			},
			"timeout_seconds": schema.Int64Attribute{
				MarkdownDescription: "HTTP request timeout in seconds (default 150s to cover 120s daemon applies)",
				Optional:            true,
			},
		},
	}
}

func isLoopbackHost(host string) bool {
	h := strings.TrimSpace(strings.TrimSuffix(host, "."))
	if h == "" {
		return false
	}
	if strings.EqualFold(h, "localhost") || strings.HasSuffix(strings.ToLower(h), ".localhost") {
		return true
	}
	ip := net.ParseIP(h)
	return ip != nil && ip.IsLoopback()
}

func resolveAllowInsecureHTTP(val types.Bool) (bool, error) {
	if !val.IsNull() && !val.IsUnknown() {
		return val.ValueBool(), nil
	}
	raw := strings.TrimSpace(os.Getenv("AXONWALL_ALLOW_INSECURE_HTTP"))
	if raw == "" {
		return false, nil
	}
	parsed, err := strconv.ParseBool(raw)
	if err != nil {
		return false, fmt.Errorf("invalid AXONWALL_ALLOW_INSECURE_HTTP value %q (expected boolean true/false/1/0)", raw)
	}
	return parsed, nil
}

func parseHTTPURL(raw string) (*url.URL, error) {
	if strings.ContainsAny(raw, "\r\n\x00 \t") {
		return nil, fmt.Errorf("URL cannot contain whitespace or control characters")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("failed to parse URL: %w", err)
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme != "https" && scheme != "http" {
		return nil, fmt.Errorf("URL scheme must be https or http (got %q)", u.Scheme)
	}
	if u.User != nil {
		return nil, fmt.Errorf("URL must not embed userinfo credentials")
	}
	if u.Hostname() == "" {
		return nil, fmt.Errorf("URL must include a non-empty host")
	}
	if portStr := u.Port(); portStr != "" {
		portNum, err := strconv.Atoi(portStr)
		if err != nil || portNum < 1 || portNum > 65535 {
			return nil, fmt.Errorf("URL contains invalid TCP port %q", portStr)
		}
	}
	return u, nil
}

func validateProviderEndpoint(rawEndpoint string, allowInsecureHTTP bool) (string, bool, error) {
	ep := strings.TrimRight(strings.TrimSpace(rawEndpoint), "/")
	if ep == "" {
		return "", false, fmt.Errorf("endpoint cannot be empty")
	}
	u, err := parseHTTPURL(ep)
	if err != nil {
		return "", false, fmt.Errorf("invalid endpoint URL %q: %w", ep, err)
	}
	if strings.EqualFold(u.Scheme, "http") && !isLoopbackHost(u.Hostname()) {
		if !allowInsecureHTTP {
			return "", false, fmt.Errorf(
				"refusing insecure plaintext http:// endpoint %q for non-loopback host %q; use https:// or explicitly set allow_insecure_http = true (or AXONWALL_ALLOW_INSECURE_HTTP=true)",
				ep, u.Hostname(),
			)
		}
		return ep, true, nil
	}
	return ep, false, nil
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
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) > 0 {
				orig := via[0].URL
				if strings.EqualFold(orig.Scheme, "https") && !strings.EqualFold(req.URL.Scheme, "https") {
					return fmt.Errorf("HTTP redirect refused: insecure HTTPS->%s downgrade from %s to %s", strings.ToUpper(req.URL.Scheme), orig.Redacted(), req.URL.Redacted())
				}
				if !strings.EqualFold(orig.Scheme, req.URL.Scheme) || !strings.EqualFold(orig.Host, req.URL.Host) {
					return fmt.Errorf("HTTP redirect refused: cross-origin redirect from %s://%s to %s://%s", orig.Scheme, orig.Host, req.URL.Scheme, req.URL.Host)
				}
			}
			return fmt.Errorf("HTTP redirect refused: redirects are disabled for Axonwall API requests (target: %s)", req.URL.Redacted())
		},
	}, nil
}

func (p *axonwallProvider) ValidateConfig(ctx context.Context, req provider.ValidateConfigRequest, resp *provider.ValidateConfigResponse) {
	var data axonwallProviderModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if data.Endpoint.IsNull() || data.Endpoint.IsUnknown() || data.AllowInsecureHTTP.IsUnknown() {
		return
	}
	rawEndpoint := strings.TrimSpace(data.Endpoint.ValueString())
	if rawEndpoint == "" {
		return
	}
	allowInsecure, err := resolveAllowInsecureHTTP(data.AllowInsecureHTTP)
	if err != nil {
		resp.Diagnostics.AddError("Invalid allow_insecure_http configuration", err.Error())
		return
	}
	if _, warnInsecure, err := validateProviderEndpoint(rawEndpoint, allowInsecure); err != nil {
		resp.Diagnostics.AddAttributeError(path.Root("endpoint"), "Insecure or invalid Axonwall API endpoint", err.Error())
		return
	} else if warnInsecure {
		resp.Diagnostics.AddAttributeWarning(
			path.Root("endpoint"),
			"Insecure non-loopback HTTP endpoint",
			fmt.Sprintf("Using plaintext http:// endpoint %q exposes API tokens and firewall DesiredState on the network; prefer https://.", rawEndpoint),
		)
	}
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

	allowInsecureHTTP, err := resolveAllowInsecureHTTP(data.AllowInsecureHTTP)
	if err != nil {
		resp.Diagnostics.AddError("Invalid allow_insecure_http configuration", err.Error())
		return
	}

	validatedEndpoint, warnInsecureHTTP, err := validateProviderEndpoint(endpoint, allowInsecureHTTP)
	if err != nil {
		resp.Diagnostics.AddAttributeError(path.Root("endpoint"), "Insecure or invalid Axonwall API endpoint", err.Error())
		return
	}
	if warnInsecureHTTP {
		resp.Diagnostics.AddAttributeWarning(
			path.Root("endpoint"),
			"Insecure non-loopback HTTP endpoint",
			fmt.Sprintf("Using plaintext http:// endpoint %q because allow_insecure_http is enabled; API tokens and DesiredState will be transmitted unencrypted.", validatedEndpoint),
		)
	}
	endpoint = validatedEndpoint

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
