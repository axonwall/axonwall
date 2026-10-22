package provider

import (
	"context"
	"net/http"
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
	Endpoint types.String `tfsdk:"endpoint"`
	Token    types.String `tfsdk:"token"`
}

func (p *axonwallProvider) Metadata(ctx context.Context, req provider.MetadataRequest, resp *provider.MetadataResponse) {
	resp.TypeName = "axonwall"
	resp.Version = p.version
}

func (p *axonwallProvider) Schema(ctx context.Context, req provider.SchemaRequest, resp *provider.SchemaResponse) {
	resp.Schema = schema.Schema{
		Attributes: map[string]schema.Attribute{
			"endpoint": schema.StringAttribute{
				MarkdownDescription: "Axonwall API Endpoint (e.g. http://localhost:3000/api/v1)",
				Optional:            true,
			},
			"token": schema.StringAttribute{
				MarkdownDescription: "API Token for Axonwall authentication",
				Optional:            true,
				Sensitive:           true,
			},
		},
	}
}

func (p *axonwallProvider) Configure(ctx context.Context, req provider.ConfigureRequest, resp *provider.ConfigureResponse) {
	var data axonwallProviderModel

	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)

	if resp.Diagnostics.HasError() {
		return
	}

	endpoint := data.Endpoint.ValueString()
	token := data.Token.ValueString()

	if endpoint == "" {
		endpoint = "http://localhost:3000/api/v1"
	}

	client := &http.Client{
		Timeout: 30 * time.Second,
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
