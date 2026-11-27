package provider

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"net"
	"net/url"
	"regexp"
	"slices"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"gopkg.in/yaml.v3"
)

var (
	_ datasource.DataSource                   = &CloudInitConfigDataSource{}
	_ datasource.DataSourceWithValidateConfig = &CloudInitConfigDataSource{}
)

type CloudInitConfigDataSource struct{}

type CloudInitConfigModel struct {
	Hostname                     types.String `tfsdk:"hostname"`
	FQDN                         types.String `tfsdk:"fqdn"`
	Timezone                     types.String `tfsdk:"timezone"`
	Edition                      types.String `tfsdk:"edition"`
	InstallMode                  types.String `tfsdk:"install_mode"`
	AllowWipeExisting            types.Bool   `tfsdk:"allow_wipe_existing"`
	StarterPacks                 types.List   `tfsdk:"starter_packs"`
	AdminUsername                types.String `tfsdk:"admin_username"`
	AdminPassword                types.String `tfsdk:"admin_password"`
	AdminPasswordHash            types.String `tfsdk:"admin_password_hash"`
	SSHAuthorizedKeys            types.List   `tfsdk:"ssh_authorized_keys"`
	ZTPEnabled                   types.Bool   `tfsdk:"ztp_enabled"`
	ZTPControllerURL             types.String `tfsdk:"ztp_controller_url"`
	ZTPEnrollmentToken           types.String `tfsdk:"ztp_enrollment_token"`
	StorageLayoutMode            types.String `tfsdk:"storage_layout_mode"`
	StorageTargetDisks           types.List   `tfsdk:"storage_target_disks"`
	StorageEFISizeMB             types.Int64  `tfsdk:"storage_efi_size_mb"`
	StorageRootSizeGB            types.Int64  `tfsdk:"storage_root_size_gb"`
	StorageRootFstype            types.String `tfsdk:"storage_root_fstype"`
	StorageStandbyEnabled        types.Bool   `tfsdk:"storage_standby_enabled"`
	StorageSwapSizeGB            types.Int64  `tfsdk:"storage_swap_size_gb"`
	StorageSwapZRAM              types.Bool   `tfsdk:"storage_swap_zram"`
	StorageDataSizeGB            types.Int64  `tfsdk:"storage_data_size_gb"`
	StorageDataFstype            types.String `tfsdk:"storage_data_fstype"`
	StorageDataAllocateRemaining types.Bool   `tfsdk:"storage_data_allocate_remaining"`
	StorageSeparateLogPartition  types.Bool   `tfsdk:"storage_separate_log_partition"`
	StorageLogSizeGB             types.Int64  `tfsdk:"storage_log_size_gb"`
	StorageLogFstype             types.String `tfsdk:"storage_log_fstype"`
	StorageEncryptionEnabled     types.Bool   `tfsdk:"storage_encryption_enabled"`
	StorageEncryptionPassphrase  types.String `tfsdk:"storage_encryption_passphrase"`
	StorageTPM2AutoUnlock        types.Bool   `tfsdk:"storage_tpm2_auto_unlock"`
	StorageSystemRAIDEnabled     types.Bool   `tfsdk:"storage_system_raid_enabled"`
	ZFSAllocMode                 types.String `tfsdk:"zfs_alloc_mode"`
	ZFSSizeGB                    types.Int64  `tfsdk:"zfs_size_gb"`
	ZFSRaidTopology              types.String `tfsdk:"zfs_raid_topology"`
	ZFSExtraDisks                types.List   `tfsdk:"zfs_extra_disks"`
	ZFSSlogDisks                 types.List   `tfsdk:"zfs_slog_disks"`
	ZFSL2arcDisks                types.List   `tfsdk:"zfs_l2arc_disks"`
	ZFSSpareDisks                types.List   `tfsdk:"zfs_spare_disks"`
	DesiredStateJSON             types.String `tfsdk:"desired_state_json"`
	Rendered                     types.String `tfsdk:"rendered"`
}

type int64RangeValidator struct {
	min int64
	max int64
}

func (v int64RangeValidator) Description(ctx context.Context) string {
	if v.max == math.MaxInt64 {
		return fmt.Sprintf("value must be >= %d", v.min)
	}
	return fmt.Sprintf("value must be between %d and %d", v.min, v.max)
}

func (v int64RangeValidator) MarkdownDescription(ctx context.Context) string {
	return v.Description(ctx)
}

func (v int64RangeValidator) ValidateInt64(ctx context.Context, req validator.Int64Request, resp *validator.Int64Response) {
	if req.ConfigValue.IsNull() || req.ConfigValue.IsUnknown() {
		return
	}
	val := req.ConfigValue.ValueInt64()
	if val < v.min || val > v.max {
		resp.Diagnostics.AddAttributeError(
			req.Path,
			"Invalid numeric value",
			fmt.Sprintf("%s (got %d).", v.Description(ctx), val),
		)
	}
}

type stringOneOfValidator struct {
	allowed []string
}

func (v stringOneOfValidator) Description(ctx context.Context) string {
	return fmt.Sprintf("value must be one of: %s", strings.Join(v.allowed, ", "))
}

func (v stringOneOfValidator) MarkdownDescription(ctx context.Context) string {
	return v.Description(ctx)
}

func (v stringOneOfValidator) ValidateString(ctx context.Context, req validator.StringRequest, resp *validator.StringResponse) {
	if req.ConfigValue.IsNull() || req.ConfigValue.IsUnknown() {
		return
	}
	val := req.ConfigValue.ValueString()
	if val == "" {
		return
	}
	if !slices.Contains(v.allowed, val) {
		resp.Diagnostics.AddAttributeError(
			req.Path,
			"Invalid attribute value",
			fmt.Sprintf("%s (got %q).", v.Description(ctx), val),
		)
	}
}

var (
	rfc1123HostnameRegex = regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$`)
	rfc1123FQDNRegex     = regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$`)
	ianaTimezoneRegex    = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_+-]{0,63}(/[A-Za-z0-9_+-]{1,64}){0,3}$`)
	linuxUsernameRegex   = regexp.MustCompile(`^[a-zA-Z_][a-zA-Z0-9_-]{0,31}$`)
	starterPackRegex     = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,63}$`)
	openSSHPubKeyRegex   = regexp.MustCompile(`^(ssh-(rsa|ed25519)|ecdsa-sha2-nistp(256|384|521)|sk-(ssh-ed25519|ecdsa-sha2-nistp256)@openssh\.com)\s+[A-Za-z0-9+/]{16,}={0,2}(\s+[^\r\n\x00]*)?$`)
	devDiskPathRegex     = regexp.MustCompile(`^/dev/[a-zA-Z0-9_][a-zA-Z0-9._:-]*(/[a-zA-Z0-9_][a-zA-Z0-9._:-]*)*$`)
	aliasEndpointRegex   = regexp.MustCompile(`^\$[a-zA-Z0-9_-]+$`)

	passwordHashPatterns = []*regexp.Regexp{
		regexp.MustCompile(`^\$6\$(rounds=[0-9]+\$)?[A-Za-z0-9./]{1,64}\$[A-Za-z0-9./]{4,}$`),
		regexp.MustCompile(`^\$5\$(rounds=[0-9]+\$)?[A-Za-z0-9./]{1,64}\$[A-Za-z0-9./]{4,}$`),
		regexp.MustCompile(`^\$y\$[A-Za-z0-9./]{1,32}\$[A-Za-z0-9./]{1,64}\$[A-Za-z0-9./]{4,}$`),
		regexp.MustCompile(`^\$2[aby]\$(0[4-9]|[12][0-9]|3[01])\$[A-Za-z0-9./]{22,}$`),
		regexp.MustCompile(`^\$argon2(id|i|d)\$v=[0-9]+\$m=[0-9]+,t=[0-9]+,p=[0-9]+\$[A-Za-z0-9+/=]+\$[A-Za-z0-9+/=]+$`),
		regexp.MustCompile(`^scrypt\$[0-9a-fA-F]{16,128}\$[0-9a-fA-F]{32,256}$`),
	}
)

type regexStringValidator struct {
	pattern     *regexp.Regexp
	description string
	summary     string
	maxLen      int
	disallow    []string
}

func (v regexStringValidator) Description(ctx context.Context) string {
	return v.description
}

func (v regexStringValidator) MarkdownDescription(ctx context.Context) string {
	return v.description
}

func (v regexStringValidator) ValidateString(ctx context.Context, req validator.StringRequest, resp *validator.StringResponse) {
	if req.ConfigValue.IsNull() || req.ConfigValue.IsUnknown() {
		return
	}
	val := req.ConfigValue.ValueString()
	if val == "" {
		return
	}
	if strings.ContainsAny(val, "\r\n\x00") {
		resp.Diagnostics.AddAttributeError(req.Path, v.summary, "Value must not contain newlines or null bytes.")
		return
	}
	if v.maxLen > 0 && len(val) > v.maxLen {
		resp.Diagnostics.AddAttributeError(req.Path, v.summary, fmt.Sprintf("%s (length %d exceeds max %d).", v.description, len(val), v.maxLen))
		return
	}
	for _, bad := range v.disallow {
		if strings.Contains(val, bad) {
			resp.Diagnostics.AddAttributeError(req.Path, v.summary, fmt.Sprintf("%s (disallowed sequence %q).", v.description, bad))
			return
		}
	}
	if !v.pattern.MatchString(val) {
		resp.Diagnostics.AddAttributeError(req.Path, v.summary, fmt.Sprintf("%s (got %q).", v.description, val))
	}
}

type noControlCharsValidator struct {
	description          string
	rejectWhitespaceOnly bool
}

func (v noControlCharsValidator) Description(ctx context.Context) string {
	return v.description
}

func (v noControlCharsValidator) MarkdownDescription(ctx context.Context) string {
	return v.description
}

func (v noControlCharsValidator) ValidateString(ctx context.Context, req validator.StringRequest, resp *validator.StringResponse) {
	if req.ConfigValue.IsNull() || req.ConfigValue.IsUnknown() {
		return
	}
	val := req.ConfigValue.ValueString()
	if val == "" {
		return
	}
	if strings.ContainsAny(val, "\r\n\x00") {
		resp.Diagnostics.AddAttributeError(req.Path, "Invalid control character", fmt.Sprintf("%s (cannot contain newlines or null bytes).", v.description))
		return
	}
	if v.rejectWhitespaceOnly && strings.TrimSpace(val) == "" {
		resp.Diagnostics.AddAttributeError(req.Path, "Invalid blank value", fmt.Sprintf("%s (cannot be whitespace-only).", v.description))
	}
}

type passwordHashValidator struct{}

func (v passwordHashValidator) Description(ctx context.Context) string {
	return "value must be a supported Linux crypt ($6$, $5$, $y$, $2a$/$2b$/$2y$, $argon2id$) or Axonwall scrypt$ password hash"
}

func (v passwordHashValidator) MarkdownDescription(ctx context.Context) string {
	return v.Description(ctx)
}

func (v passwordHashValidator) ValidateString(ctx context.Context, req validator.StringRequest, resp *validator.StringResponse) {
	if req.ConfigValue.IsNull() || req.ConfigValue.IsUnknown() {
		return
	}
	val := req.ConfigValue.ValueString()
	if val == "" {
		return
	}
	if strings.ContainsAny(val, "\r\n\x00 \t:") {
		resp.Diagnostics.AddAttributeError(req.Path, "Invalid password hash format", "Password hash cannot contain whitespace, colons, newlines, or null bytes.")
		return
	}
	for _, pat := range passwordHashPatterns {
		if pat.MatchString(val) {
			return
		}
	}
	resp.Diagnostics.AddAttributeError(
		req.Path,
		"Invalid password hash format",
		fmt.Sprintf("%s.", v.Description(ctx)),
	)
}

type httpURLValidator struct{}

func (v httpURLValidator) Description(ctx context.Context) string {
	return "value must be a valid http:// or https:// URL with a non-empty host and no embedded credentials"
}

func (v httpURLValidator) MarkdownDescription(ctx context.Context) string {
	return v.Description(ctx)
}

func (v httpURLValidator) ValidateString(ctx context.Context, req validator.StringRequest, resp *validator.StringResponse) {
	if req.ConfigValue.IsNull() || req.ConfigValue.IsUnknown() {
		return
	}
	val := req.ConfigValue.ValueString()
	if val == "" {
		return
	}
	if _, err := parseHTTPURL(val); err != nil {
		resp.Diagnostics.AddAttributeError(req.Path, "Invalid controller URL", err.Error())
	}
}

type listStringsValidator struct {
	elem        validator.String
	rejectEmpty bool
}

func (v listStringsValidator) Description(ctx context.Context) string {
	return v.elem.Description(ctx)
}

func (v listStringsValidator) MarkdownDescription(ctx context.Context) string {
	return v.elem.MarkdownDescription(ctx)
}

func (v listStringsValidator) ValidateList(ctx context.Context, req validator.ListRequest, resp *validator.ListResponse) {
	if req.ConfigValue.IsNull() || req.ConfigValue.IsUnknown() {
		return
	}
	for i, elem := range req.ConfigValue.Elements() {
		strVal, ok := elem.(types.String)
		if !ok || strVal.IsNull() || strVal.IsUnknown() {
			continue
		}
		elemPath := req.Path.AtListIndex(i)
		if v.rejectEmpty && strings.TrimSpace(strVal.ValueString()) == "" {
			resp.Diagnostics.AddAttributeError(elemPath, "Invalid empty list entry", "List elements must not be empty or whitespace-only.")
			continue
		}
		var elemResp validator.StringResponse
		v.elem.ValidateString(ctx, validator.StringRequest{
			Path:        elemPath,
			ConfigValue: strVal,
		}, &elemResp)
		resp.Diagnostics.Append(elemResp.Diagnostics...)
	}
}

type ipOrCIDRValidator struct {
	allowIPv4 bool
	allowIPv6 bool
	allowIP   bool
	allowCIDR bool
}

func (v ipOrCIDRValidator) Description(ctx context.Context) string {
	return "value must be a valid IP address or CIDR"
}

func (v ipOrCIDRValidator) MarkdownDescription(ctx context.Context) string {
	return v.Description(ctx)
}

func (v ipOrCIDRValidator) ValidateString(ctx context.Context, req validator.StringRequest, resp *validator.StringResponse) {
	if req.ConfigValue.IsNull() || req.ConfigValue.IsUnknown() {
		return
	}
	val := req.ConfigValue.ValueString()
	if val == "" {
		return
	}
	if !v.matches(val) {
		resp.Diagnostics.AddAttributeError(req.Path, "Invalid IP/CIDR value", fmt.Sprintf("%s (got %q).", v.Description(ctx), val))
	}
}

func (v ipOrCIDRValidator) matches(val string) bool {
	if strings.ContainsAny(val, "\r\n\x00 \t") {
		return false
	}
	if v.allowIP {
		if ip := net.ParseIP(val); ip != nil {
			if (ip.To4() != nil && v.allowIPv4) || (ip.To4() == nil && v.allowIPv6) {
				return true
			}
		}
	}
	if v.allowCIDR {
		if ip, _, err := net.ParseCIDR(val); err == nil && ip != nil {
			if (ip.To4() != nil && v.allowIPv4) || (ip.To4() == nil && v.allowIPv6) {
				return true
			}
		}
	}
	return false
}

func isValidIPv4(s string) bool {
	return ipOrCIDRValidator{allowIPv4: true, allowIP: true}.matches(s)
}

func isValidIPv6(s string) bool {
	return ipOrCIDRValidator{allowIPv6: true, allowIP: true}.matches(s)
}

func isValidIPv4CIDR(s string) bool {
	return ipOrCIDRValidator{allowIPv4: true, allowCIDR: true}.matches(s)
}

func isValidIPv6CIDR(s string) bool {
	return ipOrCIDRValidator{allowIPv6: true, allowCIDR: true}.matches(s)
}

func isValidIPv4OrCIDR(s string) bool {
	return ipOrCIDRValidator{allowIPv4: true, allowIP: true, allowCIDR: true}.matches(s)
}

func isValidIPv6OrCIDR(s string) bool {
	return ipOrCIDRValidator{allowIPv6: true, allowIP: true, allowCIDR: true}.matches(s)
}

func isValidIPOrCIDR(s string) bool {
	return ipOrCIDRValidator{allowIPv4: true, allowIPv6: true, allowIP: true, allowCIDR: true}.matches(s)
}

func isValidIP(s string) bool {
	return ipOrCIDRValidator{allowIPv4: true, allowIPv6: true, allowIP: true}.matches(s)
}

func isValidCIDR(s string) bool {
	return ipOrCIDRValidator{allowIPv4: true, allowIPv6: true, allowCIDR: true}.matches(s)
}

func isValidFirewallEndpoint(s string) bool {
	if s == "any" || s == "wan_ip" || s == "lan_net" || s == "self" {
		return true
	}
	if aliasEndpointRegex.MatchString(s) {
		return true
	}
	return isValidIPOrCIDR(s)
}

type desiredStateJSONValidator struct{}

func (v desiredStateJSONValidator) Description(ctx context.Context) string {
	return "value must be a valid DesiredState JSON object with well-formed hostnames, IPs, and CIDRs"
}

func (v desiredStateJSONValidator) MarkdownDescription(ctx context.Context) string {
	return v.Description(ctx)
}

func (v desiredStateJSONValidator) ValidateString(ctx context.Context, req validator.StringRequest, resp *validator.StringResponse) {
	if req.ConfigValue.IsNull() || req.ConfigValue.IsUnknown() {
		return
	}
	val := req.ConfigValue.ValueString()
	if val == "" {
		return
	}
	if err := validateDesiredStateJSON(val); err != nil {
		resp.Diagnostics.AddAttributeError(req.Path, "Invalid desired_state_json", err.Error())
	}
}

func validateDesiredStateJSON(raw string) error {
	decoded, err := decodeJSONWithNumbers(raw)
	if err != nil {
		return fmt.Errorf("failed to parse JSON: %w", err)
	}
	obj, ok := decoded.(map[string]interface{})
	if !ok || obj == nil {
		return fmt.Errorf("desired_state_json must be a JSON object")
	}

	if sysMap, ok := obj["system"].(map[string]interface{}); ok {
		if h, ok := sysMap["hostname"].(string); ok && h != "" {
			if !rfc1123HostnameRegex.MatchString(h) {
				return fmt.Errorf("system.hostname %q is not a valid RFC 1123 hostname", h)
			}
		}
		if dnsList, ok := sysMap["dnsServers"].([]interface{}); ok {
			for i, item := range dnsList {
				if s, ok := item.(string); ok && s != "" && !isValidIP(s) {
					return fmt.Errorf("system.dnsServers[%d] %q is not a valid IP address", i, s)
				}
			}
		}
	}

	if ifaces, ok := obj["interfaces"].([]interface{}); ok {
		for i, item := range ifaces {
			m, ok := item.(map[string]interface{})
			if !ok {
				continue
			}
			if s, ok := m["ipv4Address"].(string); ok && s != "" && !isValidIPv4OrCIDR(s) {
				return fmt.Errorf("interfaces[%d].ipv4Address %q is not a valid IPv4 address or CIDR", i, s)
			}
			if s, ok := m["ipv4Gateway"].(string); ok && s != "" && !isValidIPv4(s) {
				return fmt.Errorf("interfaces[%d].ipv4Gateway %q is not a valid IPv4 address", i, s)
			}
			if s, ok := m["ipv6Address"].(string); ok && s != "" && !isValidIPv6OrCIDR(s) {
				return fmt.Errorf("interfaces[%d].ipv6Address %q is not a valid IPv6 address or CIDR", i, s)
			}
			if s, ok := m["ipv6Gateway"].(string); ok && s != "" && !isValidIPv6(s) {
				return fmt.Errorf("interfaces[%d].ipv6Gateway %q is not a valid IPv6 address", i, s)
			}
		}
	}

	if routes, ok := obj["routes"].([]interface{}); ok {
		for i, item := range routes {
			m, ok := item.(map[string]interface{})
			if !ok {
				continue
			}
			if s, ok := m["network"].(string); ok && s != "" && !isValidCIDR(s) {
				return fmt.Errorf("routes[%d].network %q is not a valid CIDR", i, s)
			}
			if s, ok := m["destination"].(string); ok && s != "" && !isValidCIDR(s) {
				return fmt.Errorf("routes[%d].destination %q is not a valid CIDR", i, s)
			}
			if s, ok := m["gateway"].(string); ok && s != "" && !isValidIP(s) {
				return fmt.Errorf("routes[%d].gateway %q is not a valid IP address", i, s)
			}
		}
	}

	if gateways, ok := obj["gateways"].([]interface{}); ok {
		for i, item := range gateways {
			m, ok := item.(map[string]interface{})
			if !ok {
				continue
			}
			if s, ok := m["gatewayIp"].(string); ok && s != "" && !isValidIP(s) {
				return fmt.Errorf("gateways[%d].gatewayIp %q is not a valid IP address", i, s)
			}
			if s, ok := m["monitorIp"].(string); ok && s != "" && !isValidIP(s) {
				return fmt.Errorf("gateways[%d].monitorIp %q is not a valid IP address", i, s)
			}
		}
	}

	if rules, ok := obj["rules"].([]interface{}); ok {
		for i, item := range rules {
			m, ok := item.(map[string]interface{})
			if !ok {
				continue
			}
			if s, ok := m["source"].(string); ok && s != "" && !isValidFirewallEndpoint(s) {
				return fmt.Errorf("rules[%d].source %q is not a valid firewall endpoint (IP, CIDR, keyword, or $alias)", i, s)
			}
			if s, ok := m["destination"].(string); ok && s != "" && !isValidFirewallEndpoint(s) {
				return fmt.Errorf("rules[%d].destination %q is not a valid firewall endpoint (IP, CIDR, keyword, or $alias)", i, s)
			}
		}
	}

	if wg, ok := obj["wireguard"].(map[string]interface{}); ok {
		if addr, ok := wg["address"].(string); ok && addr != "" {
			for _, part := range strings.Split(addr, ",") {
				p := strings.TrimSpace(part)
				if p == "" || !isValidIPOrCIDR(p) {
					return fmt.Errorf("wireguard.address %q contains invalid IP/CIDR %q", addr, p)
				}
			}
		}
		if peers, ok := wg["peers"].([]interface{}); ok {
			for i, item := range peers {
				m, ok := item.(map[string]interface{})
				if !ok {
					continue
				}
				for _, key := range []string{"allowedIps", "allowedIPs"} {
					if list, ok := m[key].([]interface{}); ok {
						for j, rawCIDR := range list {
							if s, ok := rawCIDR.(string); ok && s != "" && !isValidIPOrCIDR(s) {
								return fmt.Errorf("wireguard.peers[%d].%s[%d] %q is not a valid IP/CIDR", i, key, j, s)
							}
						}
					}
				}
			}
		}
	}

	if dhcp, ok := obj["dhcp"].(map[string]interface{}); ok {
		if subnets, ok := dhcp["subnets"].([]interface{}); ok {
			for i, item := range subnets {
				m, ok := item.(map[string]interface{})
				if !ok {
					continue
				}
				if s, ok := m["subnet"].(string); ok && s != "" && !isValidIPv4CIDR(s) {
					return fmt.Errorf("dhcp.subnets[%d].subnet %q is not a valid IPv4 CIDR", i, s)
				}
				for _, field := range []string{"poolStart", "poolEnd"} {
					if s, ok := m[field].(string); ok && s != "" && !isValidIPv4(s) {
						return fmt.Errorf("dhcp.subnets[%d].%s %q is not a valid IPv4 address", i, field, s)
					}
				}
				for _, listField := range []string{"routers", "dnsServers"} {
					if list, ok := m[listField].([]interface{}); ok {
						for j, rawIP := range list {
							if s, ok := rawIP.(string); ok && s != "" && !isValidIPv4(s) {
								return fmt.Errorf("dhcp.subnets[%d].%s[%d] %q is not a valid IPv4 address", i, listField, j, s)
							}
						}
					}
				}
			}
		}
		if subnets6, ok := dhcp["subnets6"].([]interface{}); ok {
			for i, item := range subnets6 {
				m, ok := item.(map[string]interface{})
				if !ok {
					continue
				}
				for _, field := range []string{"subnet", "delegatedPrefix"} {
					if s, ok := m[field].(string); ok && s != "" && !isValidIPv6CIDR(s) {
						return fmt.Errorf("dhcp.subnets6[%d].%s %q is not a valid IPv6 CIDR", i, field, s)
					}
				}
				for _, field := range []string{"poolStart", "poolEnd"} {
					if s, ok := m[field].(string); ok && s != "" && !isValidIPv6(s) {
						return fmt.Errorf("dhcp.subnets6[%d].%s %q is not a valid IPv6 address", i, field, s)
					}
				}
				if list, ok := m["dnsServers"].([]interface{}); ok {
					for j, rawIP := range list {
						if s, ok := rawIP.(string); ok && s != "" && !isValidIPv6(s) {
							return fmt.Errorf("dhcp.subnets6[%d].dnsServers[%d] %q is not a valid IPv6 address", i, j, s)
						}
					}
				}
			}
		}
	}

	return nil
}

func devDiskValidators() []validator.List {
	return []validator.List{
		listStringsValidator{
			rejectEmpty: true,
			elem: regexStringValidator{
				pattern:     devDiskPathRegex,
				maxLen:      256,
				disallow:    []string{".."},
				summary:     "Invalid block device path",
				description: "disk path must be a /dev/... device path without '..' traversal",
			},
		},
	}
}

func NewCloudInitConfigDataSource() datasource.DataSource {
	return &CloudInitConfigDataSource{}
}

func (d *CloudInitConfigDataSource) Metadata(ctx context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_cloudinit_config"
}

func (d *CloudInitConfigDataSource) Schema(ctx context.Context, req datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Renders standard #cloud-config YAML for unattended Axonwall appliance provisioning across bare-metal ISO and cloud VM (QCOW2) deployments.",
		Attributes: map[string]schema.Attribute{
			"hostname": schema.StringAttribute{
				MarkdownDescription: "Appliance system hostname.",
				Optional:            true,
				Validators: []validator.String{
					regexStringValidator{
						pattern:     rfc1123HostnameRegex,
						maxLen:      63,
						summary:     "Invalid hostname",
						description: "hostname must follow RFC 1123 label format (1-63 alphanumeric or hyphen characters, starting and ending with alphanumeric)",
					},
				},
			},
			"fqdn": schema.StringAttribute{
				MarkdownDescription: "Fully qualified domain name.",
				Optional:            true,
				Validators: []validator.String{
					regexStringValidator{
						pattern:     rfc1123FQDNRegex,
						maxLen:      253,
						summary:     "Invalid FQDN",
						description: "fqdn must be a valid RFC 1123 domain name (dot-separated labels, max 253 characters)",
					},
				},
			},
			"timezone": schema.StringAttribute{
				MarkdownDescription: "Timezone identifier (e.g. UTC, America/New_York).",
				Optional:            true,
				Validators: []validator.String{
					regexStringValidator{
						pattern:     ianaTimezoneRegex,
						maxLen:      128,
						disallow:    []string{".."},
						summary:     "Invalid timezone",
						description: "timezone must be a valid IANA timezone identifier (e.g. UTC or America/New_York)",
					},
				},
			},
			"edition": schema.StringAttribute{
				MarkdownDescription: "Appliance edition ('axonwall', 'minimal', 'vault', or 'k3s-storage'). Defaults to 'axonwall'.",
				Optional:            true,
				Validators:          []validator.String{stringOneOfValidator{allowed: []string{"axonwall", "minimal", "vault", "k3s-storage"}}},
			},
			"install_mode": schema.StringAttribute{
				MarkdownDescription: "Bare-metal installer mode ('ab', 'zbm', 'btrfs', or 'rolling'). Derived from storage_layout_mode if omitted.",
				Optional:            true,
				Validators:          []validator.String{stringOneOfValidator{allowed: []string{"ab", "zbm", "btrfs", "rolling"}}},
			},
			"allow_wipe_existing": schema.BoolAttribute{
				MarkdownDescription: "Explicitly authorize axonwall-install --unattended to overwrite a non-empty target disk.",
				Optional:            true,
			},
			"starter_packs": schema.ListAttribute{
				ElementType:         types.StringType,
				MarkdownDescription: "Starter packs to enable during unattended provisioning (e.g. ['enterprise-ngfw', 'edge-branch']).",
				Optional:            true,
				Validators: []validator.List{
					listStringsValidator{
						rejectEmpty: true,
						elem: regexStringValidator{
							pattern:     starterPackRegex,
							maxLen:      64,
							summary:     "Invalid starter pack identifier",
							description: "starter pack name must match [a-z0-9][a-z0-9_-]{0,63}",
						},
					},
				},
			},
			"admin_username": schema.StringAttribute{
				MarkdownDescription: "Local administrator username (defaults to 'admin').",
				Optional:            true,
				Validators: []validator.String{
					regexStringValidator{
						pattern:     linuxUsernameRegex,
						maxLen:      32,
						summary:     "Invalid administrator username",
						description: "admin_username must be a valid Linux username matching ^[a-zA-Z_][a-zA-Z0-9_-]{0,31}$",
					},
				},
			},
			"admin_password": schema.StringAttribute{
				MarkdownDescription: "Deprecated: cleartext administrator password for console/web access. Prefer admin_password_hash.",
				DeprecationMessage:  "Prefer admin_password_hash over plaintext admin_password so cleartext passwords are not stored in Terraform state or #cloud-config user-data.",
				Optional:            true,
				Sensitive:           true,
				Validators: []validator.String{
					noControlCharsValidator{description: "admin_password must be a single-line string without control characters"},
				},
			},
			"admin_password_hash": schema.StringAttribute{
				MarkdownDescription: "Pre-computed password hash (SHA-512 crypt, yescrypt, bcrypt, argon2, or Axonwall scrypt) for administrator account.",
				Optional:            true,
				Sensitive:           true,
				Validators:          []validator.String{passwordHashValidator{}},
			},
			"ssh_authorized_keys": schema.ListAttribute{
				ElementType:         types.StringType,
				MarkdownDescription: "List of SSH public keys authorized for administrator and root access.",
				Optional:            true,
				Validators: []validator.List{
					listStringsValidator{
						rejectEmpty: true,
						elem: regexStringValidator{
							pattern:     openSSHPubKeyRegex,
							maxLen:      16384,
							summary:     "Invalid SSH public key",
							description: "SSH authorized key must be a valid OpenSSH public key (ssh-ed25519, ssh-rsa, ecdsa-sha2-nistp256/384/521, or sk-*@openssh.com) without authorized_keys options",
						},
					},
				},
			},
			"ztp_enabled": schema.BoolAttribute{
				MarkdownDescription: "Enable Zero-Touch Provisioning (ZTP) to central Axonwall Controller.",
				Optional:            true,
			},
			"ztp_controller_url": schema.StringAttribute{
				MarkdownDescription: "Central Controller API URL (e.g. https://ctrl.axonwall.corp).",
				Optional:            true,
				Validators:          []validator.String{httpURLValidator{}},
			},
			"ztp_enrollment_token": schema.StringAttribute{
				MarkdownDescription: "One-time enrollment secret or pre-shared key for ZTP registration.",
				Optional:            true,
				Sensitive:           true,
				Validators: []validator.String{
					noControlCharsValidator{
						description:          "ztp_enrollment_token must be a non-blank single-line token without control characters",
						rejectWhitespaceOnly: true,
					},
				},
			},
			"storage_layout_mode": schema.StringAttribute{
				MarkdownDescription: "Partition layout mode: 'standard_ab', 'compact_ab', 'single_root', or 'custom'. Defaults to 'standard_ab'.",
				Optional:            true,
				Validators:          []validator.String{stringOneOfValidator{allowed: []string{"standard_ab", "compact_ab", "single_root", "custom"}}},
			},
			"storage_target_disks": schema.ListAttribute{
				ElementType:         types.StringType,
				MarkdownDescription: "Target disk devices (e.g. ['/dev/sda', '/dev/sdb']). Defaults to ['/dev/sda'].",
				Optional:            true,
				Validators:          devDiskValidators(),
			},
			"storage_efi_size_mb": schema.Int64Attribute{
				MarkdownDescription: "Size of EFI System Partition in megabytes (128-4096). Defaults to 512.",
				Optional:            true,
				Validators:          []validator.Int64{int64RangeValidator{min: 128, max: 4096}},
			},
			"storage_root_size_gb": schema.Int64Attribute{
				MarkdownDescription: "Size of each root slot in gigabytes (>= 4). Defaults to 16.",
				Optional:            true,
				Validators:          []validator.Int64{int64RangeValidator{min: 4, max: math.MaxInt64}},
			},
			"storage_root_fstype": schema.StringAttribute{
				MarkdownDescription: "Filesystem type for root partition ('ext4', 'xfs', or 'btrfs'). Defaults to 'ext4'.",
				Optional:            true,
				Validators:          []validator.String{stringOneOfValidator{allowed: []string{"ext4", "xfs", "btrfs"}}},
			},
			"storage_standby_enabled": schema.BoolAttribute{
				MarkdownDescription: "Whether Slot B standby root is allocated. Defaults to true.",
				Optional:            true,
			},
			"storage_swap_size_gb": schema.Int64Attribute{
				MarkdownDescription: "Swap partition size in gigabytes (>= 0). Defaults to 2.",
				Optional:            true,
				Validators:          []validator.Int64{int64RangeValidator{min: 0, max: math.MaxInt64}},
			},
			"storage_swap_zram": schema.BoolAttribute{
				MarkdownDescription: "Enable zram swap compression instead of or in addition to disk swap.",
				Optional:            true,
			},
			"storage_data_size_gb": schema.Int64Attribute{
				MarkdownDescription: "Data partition size (/var/lib/axonwall) in gigabytes (>= 2).",
				Optional:            true,
				Validators:          []validator.Int64{int64RangeValidator{min: 2, max: math.MaxInt64}},
			},
			"storage_data_fstype": schema.StringAttribute{
				MarkdownDescription: "Filesystem type for data partition ('ext4', 'xfs', or 'btrfs'). Defaults to 'ext4'.",
				Optional:            true,
				Validators:          []validator.String{stringOneOfValidator{allowed: []string{"ext4", "xfs", "btrfs"}}},
			},
			"storage_data_allocate_remaining": schema.BoolAttribute{
				MarkdownDescription: "Allocate all remaining disk capacity to data partition. Defaults to true.",
				Optional:            true,
			},
			"storage_separate_log_partition": schema.BoolAttribute{
				MarkdownDescription: "Allocate dedicated /var/log partition to prevent log floods from impacting data.",
				Optional:            true,
			},
			"storage_log_size_gb": schema.Int64Attribute{
				MarkdownDescription: "Size of /var/log partition in gigabytes (>= 2). Defaults to 10.",
				Optional:            true,
				Validators:          []validator.Int64{int64RangeValidator{min: 2, max: math.MaxInt64}},
			},
			"storage_log_fstype": schema.StringAttribute{
				MarkdownDescription: "Filesystem type for /var/log ('xfs', 'ext4', or 'btrfs'). Defaults to 'xfs'.",
				Optional:            true,
				Validators:          []validator.String{stringOneOfValidator{allowed: []string{"ext4", "xfs", "btrfs"}}},
			},
			"storage_encryption_enabled": schema.BoolAttribute{
				MarkdownDescription: "Enable LUKS2 volume encryption on persistent data partition.",
				Optional:            true,
			},
			"storage_encryption_passphrase": schema.StringAttribute{
				MarkdownDescription: "Optional manual passphrase for LUKS2 volume unlock.",
				Optional:            true,
				Sensitive:           true,
				Validators: []validator.String{
					noControlCharsValidator{description: "storage_encryption_passphrase must be a single-line string without control characters"},
				},
			},
			"storage_tpm2_auto_unlock": schema.BoolAttribute{
				MarkdownDescription: "Enroll TPM2 chip (PCRs 0,2,7) via systemd-cryptenroll for hardware auto-unlock.",
				Optional:            true,
			},
			"storage_system_raid_enabled": schema.BoolAttribute{
				MarkdownDescription: "Enable RAID-1 mirroring across target disks for system and data.",
				Optional:            true,
			},
			"zfs_alloc_mode": schema.StringAttribute{
				MarkdownDescription: "ZFS tank allocation mode ('remainder', 'split', 'custom', or 'none').",
				Optional:            true,
				Validators:          []validator.String{stringOneOfValidator{allowed: []string{"remainder", "split", "custom", "none"}}},
			},
			"zfs_size_gb": schema.Int64Attribute{
				MarkdownDescription: "Explicit ZFS pool size in gigabytes when zfs_alloc_mode is 'custom' (>= 1).",
				Optional:            true,
				Validators:          []validator.Int64{int64RangeValidator{min: 1, max: math.MaxInt64}},
			},
			"zfs_raid_topology": schema.StringAttribute{
				MarkdownDescription: "ZFS vdev topology ('auto', 'stripe', 'mirror', 'raidz1', 'raidz2', 'raidz3', 'draid1', 'draid2').",
				Optional:            true,
				Validators:          []validator.String{stringOneOfValidator{allowed: []string{"auto", "stripe", "mirror", "raidz1", "raidz2", "raidz3", "draid1", "draid2"}}},
			},
			"zfs_extra_disks": schema.ListAttribute{
				ElementType:         types.StringType,
				MarkdownDescription: "Dedicated ZFS data disks for tank.",
				Optional:            true,
				Validators:          devDiskValidators(),
			},
			"zfs_slog_disks": schema.ListAttribute{
				ElementType:         types.StringType,
				MarkdownDescription: "Dedicated ZFS SLOG (ZIL) disks.",
				Optional:            true,
				Validators:          devDiskValidators(),
			},
			"zfs_l2arc_disks": schema.ListAttribute{
				ElementType:         types.StringType,
				MarkdownDescription: "Dedicated ZFS L2ARC cache disks.",
				Optional:            true,
				Validators:          devDiskValidators(),
			},
			"zfs_spare_disks": schema.ListAttribute{
				ElementType:         types.StringType,
				MarkdownDescription: "Dedicated ZFS hot-spare disks.",
				Optional:            true,
				Validators:          devDiskValidators(),
			},
			"desired_state_json": schema.StringAttribute{
				MarkdownDescription: "Declarative DesiredState JSON payload containing firewall rules, interfaces, wireguard, etc.",
				Optional:            true,
				Sensitive:           true,
				Validators:          []validator.String{desiredStateJSONValidator{}},
			},
			"rendered": schema.StringAttribute{
				MarkdownDescription: "Rendered #cloud-config YAML document.",
				Computed:            true,
				Sensitive:           true,
			},
		},
	}
}

func addCloudInitWarnings(data CloudInitConfigModel, diags *diag.Diagnostics) {
	hasHash := !data.AdminPasswordHash.IsNull() && !data.AdminPasswordHash.IsUnknown() && data.AdminPasswordHash.ValueString() != ""
	hasPlain := !data.AdminPassword.IsNull() && !data.AdminPassword.IsUnknown() && data.AdminPassword.ValueString() != ""
	if hasPlain {
		if hasHash {
			diags.AddAttributeWarning(
				path.Root("admin_password"),
				"Redundant plaintext admin_password ignored",
				"Both admin_password_hash and deprecated plaintext admin_password are set; admin_password_hash takes precedence and plaintext admin_password will be omitted from rendered #cloud-config.",
			)
		} else {
			diags.AddAttributeWarning(
				path.Root("admin_password"),
				"Prefer admin_password_hash over plaintext admin_password",
				"Plaintext admin_password embeds cleartext credentials in Terraform state and #cloud-config user-data; configure admin_password_hash instead.",
			)
		}
	}

	if !data.StorageEncryptionPassphrase.IsNull() && !data.StorageEncryptionPassphrase.IsUnknown() && data.StorageEncryptionPassphrase.ValueString() != "" {
		encEnabled := !data.StorageEncryptionEnabled.IsNull() && !data.StorageEncryptionEnabled.IsUnknown() && data.StorageEncryptionEnabled.ValueBool()
		if !data.StorageEncryptionEnabled.IsUnknown() && !encEnabled {
			diags.AddAttributeWarning(
				path.Root("storage_encryption_passphrase"),
				"LUKS passphrase configured without encryption enabled",
				"storage_encryption_passphrase is ignored unless storage_encryption_enabled is true.",
			)
		}
	}

	if !data.ZTPControllerURL.IsNull() && !data.ZTPControllerURL.IsUnknown() {
		if rawURL := strings.TrimSpace(data.ZTPControllerURL.ValueString()); rawURL != "" {
			if u, err := url.Parse(rawURL); err == nil && strings.EqualFold(u.Scheme, "http") && !isLoopbackHost(u.Hostname()) {
				diags.AddAttributeWarning(
					path.Root("ztp_controller_url"),
					"Plaintext HTTP ZTP controller URL",
					fmt.Sprintf("ztp_controller_url %q uses unencrypted http:// on a non-loopback host; prefer https:// to protect enrollment credentials in transit.", rawURL),
				)
			}
		}
	}
}

func (d *CloudInitConfigDataSource) ValidateConfig(ctx context.Context, req datasource.ValidateConfigRequest, resp *datasource.ValidateConfigResponse) {
	var data CloudInitConfigModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}
	addCloudInitWarnings(data, &resp.Diagnostics)
}

func (d *CloudInitConfigDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var data CloudInitConfigModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}
	addCloudInitWarnings(data, &resp.Diagnostics)

	cloudConfig := make(map[string]interface{})

	if !data.Hostname.IsNull() && data.Hostname.ValueString() != "" {
		cloudConfig["hostname"] = data.Hostname.ValueString()
	}
	if !data.FQDN.IsNull() && data.FQDN.ValueString() != "" {
		cloudConfig["fqdn"] = data.FQDN.ValueString()
	}
	if !data.Timezone.IsNull() && data.Timezone.ValueString() != "" {
		cloudConfig["timezone"] = data.Timezone.ValueString()
	}

	// SSH keys & Admin User
	var sshKeys []string
	if !data.SSHAuthorizedKeys.IsNull() {
		resp.Diagnostics.Append(data.SSHAuthorizedKeys.ElementsAs(ctx, &sshKeys, false)...)
		if resp.Diagnostics.HasError() {
			return
		}
	}

	adminUser := "admin"
	if !data.AdminUsername.IsNull() && data.AdminUsername.ValueString() != "" {
		adminUser = data.AdminUsername.ValueString()
	}

	userEntry := map[string]interface{}{
		"name":  adminUser,
		"gecos": "Axonwall Administrator",
		"sudo":  "ALL=(ALL) NOPASSWD:ALL",
		"shell": "/usr/bin/zsh",
	}
	if len(sshKeys) > 0 {
		userEntry["ssh_authorized_keys"] = sshKeys
	}
	hasPasswordHash := !data.AdminPasswordHash.IsNull() && data.AdminPasswordHash.ValueString() != ""
	if hasPasswordHash && strings.HasPrefix(data.AdminPasswordHash.ValueString(), "$") {
		userEntry["passwd"] = data.AdminPasswordHash.ValueString()
		userEntry["lock_passwd"] = false
	}
	cloudConfig["users"] = []interface{}{userEntry}

	// Axonwall namespace
	axonwallMap := make(map[string]interface{})

	// Auth (prefer admin_password_hash; omit redundant plaintext admin_password when hash is provided)
	authMap := map[string]interface{}{
		"admin_username": adminUser,
	}
	if hasPasswordHash {
		authMap["admin_password_hash"] = data.AdminPasswordHash.ValueString()
	} else if !data.AdminPassword.IsNull() && data.AdminPassword.ValueString() != "" {
		authMap["admin_password"] = data.AdminPassword.ValueString()
	}
	if !data.ZTPEnabled.IsNull() && data.ZTPEnabled.ValueBool() {
		ztpMap := map[string]interface{}{
			"enabled": true,
		}
		if !data.ZTPControllerURL.IsNull() && strings.TrimSpace(data.ZTPControllerURL.ValueString()) != "" {
			ztpURL := strings.TrimSpace(data.ZTPControllerURL.ValueString())
			ztpMap["controller_url"] = ztpURL
			axonwallMap["hub_url"] = ztpURL
		}
		if !data.ZTPEnrollmentToken.IsNull() && strings.TrimSpace(data.ZTPEnrollmentToken.ValueString()) != "" {
			ztpTok := strings.TrimSpace(data.ZTPEnrollmentToken.ValueString())
			ztpMap["enrollment_token"] = ztpTok
		}
		authMap["ztp"] = ztpMap
	}
	axonwallMap["auth"] = authMap

	if !data.Edition.IsNull() && strings.TrimSpace(data.Edition.ValueString()) != "" {
		axonwallMap["edition"] = strings.TrimSpace(data.Edition.ValueString())
	}
	if !data.StarterPacks.IsNull() {
		var starterPacks []string
		resp.Diagnostics.Append(data.StarterPacks.ElementsAs(ctx, &starterPacks, false)...)
		if resp.Diagnostics.HasError() {
			return
		}
		if len(starterPacks) > 0 {
			axonwallMap["starter_packs"] = starterPacks
		}
	}

	// Storage
	layoutMode := "standard_ab"
	if !data.StorageLayoutMode.IsNull() && data.StorageLayoutMode.ValueString() != "" {
		layoutMode = data.StorageLayoutMode.ValueString()
	}

	var targetDisks []string
	if !data.StorageTargetDisks.IsNull() {
		resp.Diagnostics.Append(data.StorageTargetDisks.ElementsAs(ctx, &targetDisks, false)...)
		if resp.Diagnostics.HasError() {
			return
		}
	}
	if len(targetDisks) == 0 {
		targetDisks = []string{"/dev/sda"}
	}

	efiSizeMB := int64(512)
	if !data.StorageEFISizeMB.IsNull() && data.StorageEFISizeMB.ValueInt64() > 0 {
		efiSizeMB = data.StorageEFISizeMB.ValueInt64()
	}

	rootSizeGB := int64(16)
	if !data.StorageRootSizeGB.IsNull() && data.StorageRootSizeGB.ValueInt64() > 0 {
		rootSizeGB = data.StorageRootSizeGB.ValueInt64()
	}

	rootFstype := "ext4"
	if !data.StorageRootFstype.IsNull() && data.StorageRootFstype.ValueString() != "" {
		rootFstype = data.StorageRootFstype.ValueString()
	}

	swapSizeGB := int64(2)
	if !data.StorageSwapSizeGB.IsNull() && data.StorageSwapSizeGB.ValueInt64() >= 0 {
		swapSizeGB = data.StorageSwapSizeGB.ValueInt64()
	}

	swapZram := false
	if !data.StorageSwapZRAM.IsNull() {
		swapZram = data.StorageSwapZRAM.ValueBool()
	}

	dataFstype := "ext4"
	if !data.StorageDataFstype.IsNull() && data.StorageDataFstype.ValueString() != "" {
		dataFstype = data.StorageDataFstype.ValueString()
	}

	dataAllocRemaining := true
	if !data.StorageDataAllocateRemaining.IsNull() {
		dataAllocRemaining = data.StorageDataAllocateRemaining.ValueBool()
	}

	dataMap := map[string]interface{}{
		"allocate_remaining": dataAllocRemaining,
		"filesystem":         dataFstype,
	}
	if !data.StorageDataSizeGB.IsNull() && data.StorageDataSizeGB.ValueInt64() > 0 {
		dataMap["size_gb"] = data.StorageDataSizeGB.ValueInt64()
	}

	logsMap := map[string]interface{}{
		"enabled":    false,
		"size_gb":    10,
		"filesystem": "xfs",
		"mountpoint": "/var/log",
	}
	if !data.StorageSeparateLogPartition.IsNull() && data.StorageSeparateLogPartition.ValueBool() {
		logsMap["enabled"] = true
		if !data.StorageLogSizeGB.IsNull() && data.StorageLogSizeGB.ValueInt64() > 0 {
			logsMap["size_gb"] = data.StorageLogSizeGB.ValueInt64()
		}
		if !data.StorageLogFstype.IsNull() && data.StorageLogFstype.ValueString() != "" {
			logsMap["filesystem"] = data.StorageLogFstype.ValueString()
		}
	}

	standbyEnabled := layoutMode != "single_root"
	if !data.StorageStandbyEnabled.IsNull() && !data.StorageStandbyEnabled.IsUnknown() {
		standbyEnabled = data.StorageStandbyEnabled.ValueBool()
	}

	partitionsMap := map[string]interface{}{
		"efi_size_mb": efiSizeMB,
		"slot_a": map[string]interface{}{
			"size_gb":    rootSizeGB,
			"filesystem": rootFstype,
		},
		"swap": map[string]interface{}{
			"size_gb":      swapSizeGB,
			"zram_enabled": swapZram,
		},
		"data": dataMap,
		"logs": logsMap,
	}
	if standbyEnabled {
		partitionsMap["slot_b"] = map[string]interface{}{
			"size_gb":    rootSizeGB,
			"filesystem": rootFstype,
		}
	}

	encryptionMap := map[string]interface{}{
		"enabled":          false,
		"tpm2_auto_unlock": false,
		"cipher":           "aes-xts-plain64",
		"key_size":         512,
	}
	if !data.StorageEncryptionEnabled.IsNull() && data.StorageEncryptionEnabled.ValueBool() {
		encryptionMap["enabled"] = true
		if !data.StorageTPM2AutoUnlock.IsNull() {
			encryptionMap["tpm2_auto_unlock"] = data.StorageTPM2AutoUnlock.ValueBool()
		}
		if !data.StorageEncryptionPassphrase.IsNull() && data.StorageEncryptionPassphrase.ValueString() != "" {
			encryptionMap["passphrase"] = data.StorageEncryptionPassphrase.ValueString()
		}
	}

	systemRaidEnabled := !data.StorageSystemRAIDEnabled.IsNull() && data.StorageSystemRAIDEnabled.ValueBool()
	systemRaidMap := map[string]interface{}{
		"enabled": systemRaidEnabled,
		"level":   "raid1",
	}

	storageMap := map[string]interface{}{
		"layout_mode":  layoutMode,
		"target_disks": targetDisks,
		"partitions":   partitionsMap,
		"encryption":   encryptionMap,
		"system_raid":  systemRaidMap,
	}

	readStringList := func(listVal types.List) []string {
		if listVal.IsNull() || listVal.IsUnknown() {
			return nil
		}
		var out []string
		resp.Diagnostics.Append(listVal.ElementsAs(ctx, &out, false)...)
		return out
	}
	zfsExtra := readStringList(data.ZFSExtraDisks)
	zfsSlog := readStringList(data.ZFSSlogDisks)
	zfsL2arc := readStringList(data.ZFSL2arcDisks)
	zfsSpare := readStringList(data.ZFSSpareDisks)
	if resp.Diagnostics.HasError() {
		return
	}

	// Emit flat v0.16.2 axonwall-install --unattended keys alongside axonwall.storage.*
	installMode := ""
	if !data.InstallMode.IsNull() && strings.TrimSpace(data.InstallMode.ValueString()) != "" {
		installMode = strings.TrimSpace(data.InstallMode.ValueString())
	} else if layoutMode == "single_root" || !standbyEnabled {
		installMode = "rolling"
	} else {
		installMode = "ab"
	}
	cloudConfig["install_mode"] = installMode
	cloudConfig["target_disk"] = targetDisks[0]
	if systemRaidEnabled || len(targetDisks) > 1 {
		cloudConfig["system_raid_disks"] = targetDisks
	}
	cloudConfig["slot_size_gb"] = rootSizeGB
	if !data.AllowWipeExisting.IsNull() && data.AllowWipeExisting.ValueBool() {
		cloudConfig["allow_wipe_existing"] = true
	}
	if encEnabled, _ := encryptionMap["enabled"].(bool); encEnabled {
		cloudConfig["luks_enabled"] = true
		if tpm2, _ := encryptionMap["tpm2_auto_unlock"].(bool); tpm2 {
			cloudConfig["luks_tpm2"] = true
		}
		if pass, _ := encryptionMap["passphrase"].(string); pass != "" {
			cloudConfig["luks_passphrase"] = pass
		}
	}
	if !data.ZFSAllocMode.IsNull() && strings.TrimSpace(data.ZFSAllocMode.ValueString()) != "" {
		cloudConfig["zfs_alloc_mode"] = strings.TrimSpace(data.ZFSAllocMode.ValueString())
	}
	if !data.ZFSSizeGB.IsNull() && data.ZFSSizeGB.ValueInt64() > 0 {
		cloudConfig["zfs_size_gb"] = data.ZFSSizeGB.ValueInt64()
	}
	if !data.ZFSRaidTopology.IsNull() && strings.TrimSpace(data.ZFSRaidTopology.ValueString()) != "" {
		cloudConfig["zfs_raid_topology"] = strings.TrimSpace(data.ZFSRaidTopology.ValueString())
	}
	if len(zfsExtra) > 0 {
		cloudConfig["zfs_extra_disks"] = zfsExtra
	}
	if len(zfsSlog) > 0 {
		cloudConfig["zfs_slog_disks"] = zfsSlog
	}
	if len(zfsL2arc) > 0 {
		cloudConfig["zfs_l2arc_disks"] = zfsL2arc
	}
	if len(zfsSpare) > 0 {
		cloudConfig["zfs_spare_disks"] = zfsSpare
	}
	if len(zfsExtra) > 0 || (!data.ZFSSizeGB.IsNull() && data.ZFSSizeGB.ValueInt64() > 0) || (!data.ZFSAllocMode.IsNull() && data.ZFSAllocMode.ValueString() != "" && data.ZFSAllocMode.ValueString() != "none") {
		zfsMap := map[string]interface{}{
			"enabled": true,
		}
		if !data.ZFSRaidTopology.IsNull() && strings.TrimSpace(data.ZFSRaidTopology.ValueString()) != "" {
			zfsMap["topology"] = strings.TrimSpace(data.ZFSRaidTopology.ValueString())
		}
		if len(zfsExtra) > 0 {
			zfsMap["extra_disks"] = zfsExtra
		}
		storageMap["zfs"] = zfsMap
	}

	axonwallMap["storage"] = storageMap

	// Desired State injection
	if !data.DesiredStateJSON.IsNull() && data.DesiredStateJSON.ValueString() != "" {
		if err := validateDesiredStateJSON(data.DesiredStateJSON.ValueString()); err != nil {
			resp.Diagnostics.AddError("Invalid desired_state_json", err.Error())
			return
		}
		var desiredStateObj map[string]interface{}
		if err := json.Unmarshal([]byte(data.DesiredStateJSON.ValueString()), &desiredStateObj); err != nil {
			resp.Diagnostics.AddError("Invalid desired_state_json", fmt.Sprintf("Failed to parse JSON: %s", err))
			return
		}
		axonwallMap["desired_state"] = desiredStateObj
	}

	cloudConfig["axonwall"] = axonwallMap

	yamlBytes, err := yaml.Marshal(cloudConfig)
	if err != nil {
		resp.Diagnostics.AddError("Error generating cloud-config YAML", err.Error())
		return
	}

	rendered := fmt.Sprintf("#cloud-config\n%s", string(yamlBytes))
	data.Rendered = types.StringValue(rendered)

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}
