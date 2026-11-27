package provider

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"reflect"
	"strings"
	"time"

	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
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
				MarkdownDescription: "The declarative DesiredState JSON payload",
				Required:            true,
				Sensitive:           true,
				PlanModifiers: []planmodifier.String{
					semanticJSONPlanModifier{},
				},
			},
		},
	}
}

type semanticJSONPlanModifier struct{}

func (m semanticJSONPlanModifier) Description(ctx context.Context) string {
	return "Suppresses plan diffs when state_json is semantically identical (ignoring whitespace and key ordering)."
}

func (m semanticJSONPlanModifier) MarkdownDescription(ctx context.Context) string {
	return m.Description(ctx)
}

func (m semanticJSONPlanModifier) PlanModifyString(ctx context.Context, req planmodifier.StringRequest, resp *planmodifier.StringResponse) {
	if req.PlanValue.IsNull() || req.PlanValue.IsUnknown() || req.StateValue.IsNull() || req.StateValue.IsUnknown() {
		return
	}
	planObj, err1 := decodeJSONWithNumbers(req.PlanValue.ValueString())
	stateObj, err2 := decodeJSONWithNumbers(req.StateValue.ValueString())
	if err1 == nil && err2 == nil && jsonDeepEqual(planObj, stateObj) {
		resp.PlanValue = req.StateValue
	}
}

func decodeJSONWithNumbers(raw string) (interface{}, error) {
	dec := json.NewDecoder(strings.NewReader(raw))
	dec.UseNumber()
	var v interface{}
	if err := dec.Decode(&v); err != nil {
		return nil, err
	}
	var trailing interface{}
	if err := dec.Decode(&trailing); err != io.EOF {
		if err == nil {
			return nil, fmt.Errorf("unexpected trailing JSON data")
		}
		return nil, err
	}
	return v, nil
}

func jsonDeepEqual(a, b interface{}) bool {
	if na, okA := a.(json.Number); okA {
		if nb, okB := b.(json.Number); okB {
			if na == nb {
				return true
			}
			if ia, errA := na.Int64(); errA == nil {
				if ib, errB := nb.Int64(); errB == nil {
					return ia == ib
				}
			}
			if fa, errA := na.Float64(); errA == nil {
				if fb, errB := nb.Float64(); errB == nil {
					return fa == fb
				}
			}
			return false
		}
		return false
	}
	switch va := a.(type) {
	case map[string]interface{}:
		vb, ok := b.(map[string]interface{})
		if !ok || len(va) != len(vb) {
			return false
		}
		for k, subA := range va {
			subB, exists := vb[k]
			if !exists || !jsonDeepEqual(subA, subB) {
				return false
			}
		}
		return true
	case []interface{}:
		vb, ok := b.([]interface{})
		if !ok || len(va) != len(vb) {
			return false
		}
		for i := range va {
			if !jsonDeepEqual(va[i], vb[i]) {
				return false
			}
		}
		return true
	default:
		return reflect.DeepEqual(a, b)
	}
}

// projectManagedJSON restricts server-returned DesiredState fields to the keys managed
// in prior so server-added default subsystems and unrequested defaults do not trigger
// perpetual drift or copy unrelated appliance secrets into Terraform state.
func projectManagedJSON(prior, server interface{}) interface{} {
	priorMap, pIsMap := prior.(map[string]interface{})
	serverMap, sIsMap := server.(map[string]interface{})
	if pIsMap && sIsMap {
		out := make(map[string]interface{}, len(priorMap))
		for k, pVal := range priorMap {
			if sVal, ok := serverMap[k]; ok {
				out[k] = projectManagedJSON(pVal, sVal)
			}
		}
		return out
	}
	priorArr, pIsArr := prior.([]interface{})
	serverArr, sIsArr := server.([]interface{})
	if pIsArr && sIsArr && len(priorArr) == len(serverArr) {
		out := make([]interface{}, len(priorArr))
		for i := range priorArr {
			out[i] = projectManagedJSON(priorArr[i], serverArr[i])
		}
		return out
	}
	return server
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

	err := r.applyState(ctx, data.StateJSON.ValueString())
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

	url := strings.TrimRight(r.client.Endpoint, "/") + "/state"
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
		resp.Diagnostics.AddError("Failed to read state from Axonwall API", err.Error())
		return
	}
	defer httpResp.Body.Close()

	if httpResp.StatusCode == http.StatusNotFound {
		resp.State.RemoveResource(ctx)
		return
	}

	if httpResp.StatusCode < 200 || httpResp.StatusCode >= 300 {
		respBody, _ := io.ReadAll(io.LimitReader(httpResp.Body, 1<<20))
		resp.Diagnostics.AddError(
			"Axonwall API returned error on state read",
			fmt.Sprintf("HTTP %d: %s", httpResp.StatusCode, string(respBody)),
		)
		return
	}

	bodyBytes, err := io.ReadAll(io.LimitReader(httpResp.Body, 10<<20))
	if err != nil {
		resp.Diagnostics.AddError("Failed to read /state response body", err.Error())
		return
	}
	if len(bytes.TrimSpace(bodyBytes)) > 0 {
		jsonObj, err := decodeJSONWithNumbers(string(bodyBytes))
		if err != nil {
			resp.Diagnostics.AddError("Invalid /state response JSON", err.Error())
			return
		}
		if _, ok := jsonObj.(map[string]interface{}); !ok {
			resp.Diagnostics.AddError("Invalid /state response JSON", "Expected top-level JSON object from /state")
			return
		}
		if !data.StateJSON.IsNull() && !data.StateJSON.IsUnknown() {
			existingObj, existingErr := decodeJSONWithNumbers(data.StateJSON.ValueString())
			if existingErr != nil {
				resp.Diagnostics.AddError(
					"Invalid prior state_json in Terraform state",
					fmt.Sprintf("Failed to parse prior state_json for safe field projection; refusing to fall back to unprojected /state response: %s", existingErr),
				)
				return
			}
			if _, ok := existingObj.(map[string]interface{}); !ok {
				resp.Diagnostics.AddError(
					"Invalid prior state_json in Terraform state",
					"Expected prior state_json to be a JSON object; refusing to fall back to unprojected /state response",
				)
				return
			}
			projected := projectManagedJSON(existingObj, jsonObj)
			if !jsonDeepEqual(projected, existingObj) {
				normBytes, err := json.Marshal(projected)
				if err != nil {
					resp.Diagnostics.AddError("Failed to marshal projected state_json", err.Error())
					return
				}
				data.StateJSON = types.StringValue(string(normBytes))
			}
		} else {
			normBytes, err := json.Marshal(jsonObj)
			if err != nil {
				resp.Diagnostics.AddError("Failed to marshal /state response JSON", err.Error())
				return
			}
			data.StateJSON = types.StringValue(string(normBytes))
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

	err := r.applyState(ctx, data.StateJSON.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Error updating state", err.Error())
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *DesiredStateResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	// Do nothing on delete, or apply an empty state.
}

func (r *DesiredStateResource) applyState(ctx context.Context, stateJson string) error {
	if r.client == nil || r.client.Endpoint == "" {
		return fmt.Errorf("axonwall provider client is not configured")
	}
	var parsedState map[string]interface{}
	if err := json.Unmarshal([]byte(stateJson), &parsedState); err != nil {
		return fmt.Errorf("invalid json payload: %w", err)
	}

	jobID := fmt.Sprintf("terraform-%d", time.Now().UnixNano())
	payload := map[string]interface{}{
		"jobId":                 jobID,
		"state":                 parsedState,
		"confirmTimeoutSeconds": 120,
	}
	bodyBytes, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	baseEndpoint := strings.TrimRight(r.client.Endpoint, "/")
	url := baseEndpoint + "/apply"
	httpReq, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(bodyBytes))
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

	applyRespBody, err := io.ReadAll(io.LimitReader(httpResp.Body, 1<<20))
	if err != nil {
		return fmt.Errorf("failed to read /apply response: %w", err)
	}
	confirmJobID := jobID
	if len(bytes.TrimSpace(applyRespBody)) > 0 {
		var applyEnvelope struct {
			Status string `json:"status"`
			Error  string `json:"error"`
			Data   *struct {
				Success *bool  `json:"success"`
				Message string `json:"message"`
				JobID   string `json:"jobId"`
			} `json:"data"`
		}
		if err := json.Unmarshal(applyRespBody, &applyEnvelope); err != nil {
			return fmt.Errorf("invalid /apply response JSON: %w", err)
		}
		if applyEnvelope.Status != "" && applyEnvelope.Status != "ok" {
			return fmt.Errorf("/apply failed (status=%s): %s", applyEnvelope.Status, applyEnvelope.Error)
		}
		if applyEnvelope.Data != nil {
			if applyEnvelope.Data.Success != nil && !*applyEnvelope.Data.Success {
				return fmt.Errorf("/apply rejected: %s", applyEnvelope.Data.Message)
			}
			if strings.TrimSpace(applyEnvelope.Data.JobID) != "" {
				confirmJobID = strings.TrimSpace(applyEnvelope.Data.JobID)
			}
		}
	}

	// Confirm the configuration so it does not auto-rollback after the timeout
	confirmUrl := baseEndpoint + "/confirm"
	confirmPayload, _ := json.Marshal(map[string]string{"jobId": confirmJobID})
	confirmReq, err := http.NewRequestWithContext(ctx, "POST", confirmUrl, bytes.NewReader(confirmPayload))
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

	confirmRespBody, err := io.ReadAll(io.LimitReader(confirmResp.Body, 1<<20))
	if err != nil {
		return fmt.Errorf("failed to read /confirm response: %w", err)
	}
	if len(bytes.TrimSpace(confirmRespBody)) == 0 {
		return fmt.Errorf("/confirm returned empty response body")
	}
	var confirmEnv struct {
		Status string `json:"status"`
		Error  string `json:"error"`
		Data   *struct {
			Success *bool  `json:"success"`
			Message string `json:"message"`
		} `json:"data"`
	}
	if err := json.Unmarshal(confirmRespBody, &confirmEnv); err != nil {
		return fmt.Errorf("invalid /confirm response JSON: %w", err)
	}
	if confirmEnv.Status != "ok" {
		return fmt.Errorf("/confirm failed (status=%s): %s", confirmEnv.Status, confirmEnv.Error)
	}
	if confirmEnv.Data == nil || confirmEnv.Data.Success == nil || !*confirmEnv.Data.Success {
		msg := ""
		if confirmEnv.Data != nil {
			msg = confirmEnv.Data.Message
		}
		return fmt.Errorf("/confirm rejected: %s", msg)
	}

	return nil
}
