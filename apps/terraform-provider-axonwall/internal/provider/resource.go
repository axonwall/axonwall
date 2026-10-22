package provider

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

type AxonwallClient struct {
	Endpoint string
	Token    string
	Client   *http.Client
}

// DesiredStateResource defines the resource implementation.
type DesiredStateResource struct {
	client *AxonwallClient
}

type DesiredStateResourceModel struct {
	StateJSON types.String `tfsdk:"state_json"`
}

func NewDesiredStateResource() resource.Resource {
	return &DesiredStateResource{}
}

func (r *DesiredStateResource) Metadata(ctx context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_desired_state"
}

func (r *DesiredStateResource) Schema(ctx context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Attributes: map[string]schema.Attribute{
			"state_json": schema.StringAttribute{
				MarkdownDescription: "The full DesiredState JSON payload",
				Required:            true,
			},
		},
	}
}

func (r *DesiredStateResource) Configure(ctx context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}

	client, ok := req.ProviderData.(*AxonwallClient)
	if !ok {
		resp.Diagnostics.AddError(
			"Unexpected Resource Configure Type",
			fmt.Sprintf("Expected *AxonwallClient, got: %T", req.ProviderData),
		)
		return
	}

	r.client = client
}

func (r *DesiredStateResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var data DesiredStateResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	err := r.applyState(data.StateJSON.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Error applying state", err.Error())
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *DesiredStateResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var data DesiredStateResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	if r.client == nil || r.client.Endpoint == "" {
		return
	}

	url := r.client.Endpoint + "/state"
	httpReq, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		resp.Diagnostics.AddError("Failed to create HTTP request to /state", err.Error())
		return
	}
	if r.client.Token != "" {
		httpReq.Header.Set("Authorization", "Bearer "+r.client.Token)
	}

	httpResp, err := r.client.Client.Do(httpReq)
	if err != nil {
		// If daemon is unreachable during drift detection, keep existing state
		return
	}
	defer httpResp.Body.Close()

	if httpResp.StatusCode == http.StatusNotFound {
		resp.State.RemoveResource(ctx)
		return
	}

	if httpResp.StatusCode >= 200 && httpResp.StatusCode < 300 {
		bodyBytes, err := io.ReadAll(io.LimitReader(httpResp.Body, 10<<20))
		if err == nil && len(bodyBytes) > 0 {
			var jsonObj interface{}
			if err := json.Unmarshal(bodyBytes, &jsonObj); err == nil {
				if normBytes, err := json.Marshal(jsonObj); err == nil {
					data.StateJSON = types.StringValue(string(normBytes))
				}
			}
		}
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *DesiredStateResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var data DesiredStateResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	err := r.applyState(data.StateJSON.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Error updating state", err.Error())
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *DesiredStateResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	// Do nothing on delete, or apply an empty state.
}

func (r *DesiredStateResource) applyState(stateJson string) error {
	var parsedState map[string]interface{}
	if err := json.Unmarshal([]byte(stateJson), &parsedState); err != nil {
		return fmt.Errorf("invalid json payload: %w", err)
	}

	payload := map[string]interface{}{
		"jobId":                 "terraform",
		"state":                 parsedState,
		"confirmTimeoutSeconds": 120,
	}
	bodyBytes, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	url := r.client.Endpoint + "/apply"
	httpReq, err := http.NewRequest("POST", url, bytes.NewReader(bodyBytes))
	if err != nil {
		return err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	if r.client.Token != "" {
		httpReq.Header.Set("Authorization", "Bearer "+r.client.Token)
	}

	httpResp, err := r.client.Client.Do(httpReq)
	if err != nil {
		return err
	}
	defer httpResp.Body.Close()

	if httpResp.StatusCode < 200 || httpResp.StatusCode >= 300 {
		respBody, _ := io.ReadAll(io.LimitReader(httpResp.Body, 1<<20))
		return fmt.Errorf("API error %d: %s", httpResp.StatusCode, string(respBody))
	}

	// Confirm the configuration so it does not auto-rollback after the timeout
	confirmUrl := r.client.Endpoint + "/confirm"
	confirmReq, err := http.NewRequest("POST", confirmUrl, bytes.NewReader([]byte(`{"jobId":"terraform"}`)))
	if err != nil {
		return fmt.Errorf("failed to create confirm request: %w", err)
	}
	confirmReq.Header.Set("Content-Type", "application/json")
	if r.client.Token != "" {
		confirmReq.Header.Set("Authorization", "Bearer "+r.client.Token)
	}

	confirmResp, err := r.client.Client.Do(confirmReq)
	if err != nil {
		return fmt.Errorf("failed to send confirm request: %w", err)
	}
	defer confirmResp.Body.Close()

	if confirmResp.StatusCode < 200 || confirmResp.StatusCode >= 300 {
		respBody, _ := io.ReadAll(io.LimitReader(confirmResp.Body, 1<<20))
		return fmt.Errorf("confirm error %d: %s", confirmResp.StatusCode, string(respBody))
	}

	return nil
}
