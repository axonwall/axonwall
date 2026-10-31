package provider

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"gopkg.in/yaml.v3"
)

var _ datasource.DataSource = &CloudInitConfigDataSource{}

type CloudInitConfigDataSource struct{}

type CloudInitConfigModel struct {
	Hostname                      types.String `tfsdk:"hostname"`
	FQDN                          types.String `tfsdk:"fqdn"`
	Timezone                      types.String `tfsdk:"timezone"`
	AdminUsername                 types.String `tfsdk:"admin_username"`
	AdminPassword                 types.String `tfsdk:"admin_password"`
	AdminPasswordHash             types.String `tfsdk:"admin_password_hash"`
	SSHAuthorizedKeys             types.List   `tfsdk:"ssh_authorized_keys"`
	ZTPEnabled                    types.Bool   `tfsdk:"ztp_enabled"`
	ZTPControllerURL              types.String `tfsdk:"ztp_controller_url"`
	ZTPEnrollmentToken            types.String `tfsdk:"ztp_enrollment_token"`
	StorageLayoutMode             types.String `tfsdk:"storage_layout_mode"`
	StorageTargetDisks            types.List   `tfsdk:"storage_target_disks"`
	StorageEFISizeMB              types.Int64  `tfsdk:"storage_efi_size_mb"`
	StorageRootSizeGB             types.Int64  `tfsdk:"storage_root_size_gb"`
	StorageRootFstype             types.String `tfsdk:"storage_root_fstype"`
	StorageStandbyEnabled         types.Bool   `tfsdk:"storage_standby_enabled"`
	StorageSwapSizeGB             types.Int64  `tfsdk:"storage_swap_size_gb"`
	StorageSwapZRAM               types.Bool   `tfsdk:"storage_swap_zram"`
	StorageDataSizeGB             types.Int64  `tfsdk:"storage_data_size_gb"`
	StorageDataFstype             types.String `tfsdk:"storage_data_fstype"`
	StorageDataAllocateRemaining  types.Bool   `tfsdk:"storage_data_allocate_remaining"`
	StorageSeparateLogPartition   types.Bool   `tfsdk:"storage_separate_log_partition"`
	StorageLogSizeGB              types.Int64  `tfsdk:"storage_log_size_gb"`
	StorageLogFstype              types.String `tfsdk:"storage_log_fstype"`
	StorageEncryptionEnabled      types.Bool   `tfsdk:"storage_encryption_enabled"`
	StorageEncryptionPassphrase   types.String `tfsdk:"storage_encryption_passphrase"`
	StorageTPM2AutoUnlock         types.Bool   `tfsdk:"storage_tpm2_auto_unlock"`
	StorageSystemRAIDEnabled      types.Bool   `tfsdk:"storage_system_raid_enabled"`
	DesiredStateJSON              types.String `tfsdk:"desired_state_json"`
	Rendered                      types.String `tfsdk:"rendered"`
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
			},
			"fqdn": schema.StringAttribute{
				MarkdownDescription: "Fully qualified domain name.",
				Optional:            true,
			},
			"timezone": schema.StringAttribute{
				MarkdownDescription: "Timezone identifier (e.g. UTC, America/New_York).",
				Optional:            true,
			},
			"admin_username": schema.StringAttribute{
				MarkdownDescription: "Local administrator username (defaults to 'admin').",
				Optional:            true,
			},
			"admin_password": schema.StringAttribute{
				MarkdownDescription: "Cleartext administrator password for console/web access.",
				Optional:            true,
				Sensitive:           true,
			},
			"admin_password_hash": schema.StringAttribute{
				MarkdownDescription: "Pre-computed password hash (SHA-512 crypt) for administrator account.",
				Optional:            true,
				Sensitive:           true,
			},
			"ssh_authorized_keys": schema.ListAttribute{
				ElementType:         types.StringType,
				MarkdownDescription: "List of SSH public keys authorized for administrator and root access.",
				Optional:            true,
			},
			"ztp_enabled": schema.BoolAttribute{
				MarkdownDescription: "Enable Zero-Touch Provisioning (ZTP) to central Axonwall Controller.",
				Optional:            true,
			},
			"ztp_controller_url": schema.StringAttribute{
				MarkdownDescription: "Central Controller API URL (e.g. https://ctrl.axonwall.corp).",
				Optional:            true,
			},
			"ztp_enrollment_token": schema.StringAttribute{
				MarkdownDescription: "One-time enrollment secret or pre-shared key for ZTP registration.",
				Optional:            true,
				Sensitive:           true,
			},
			"storage_layout_mode": schema.StringAttribute{
				MarkdownDescription: "Partition layout mode: 'standard_ab', 'compact_ab', 'single_root', or 'custom'. Defaults to 'standard_ab'.",
				Optional:            true,
			},
			"storage_target_disks": schema.ListAttribute{
				ElementType:         types.StringType,
				MarkdownDescription: "Target disk devices (e.g. ['/dev/sda', '/dev/sdb']). Defaults to ['/dev/sda'].",
				Optional:            true,
			},
			"storage_efi_size_mb": schema.Int64Attribute{
				MarkdownDescription: "Size of EFI System Partition in megabytes. Defaults to 512.",
				Optional:            true,
			},
			"storage_root_size_gb": schema.Int64Attribute{
				MarkdownDescription: "Size of each root slot in gigabytes. Defaults to 16.",
				Optional:            true,
			},
			"storage_root_fstype": schema.StringAttribute{
				MarkdownDescription: "Filesystem type for root partition ('ext4' or 'xfs'). Defaults to 'ext4'.",
				Optional:            true,
			},
			"storage_standby_enabled": schema.BoolAttribute{
				MarkdownDescription: "Whether Slot B standby root is allocated. Defaults to true.",
				Optional:            true,
			},
			"storage_swap_size_gb": schema.Int64Attribute{
				MarkdownDescription: "Swap partition size in gigabytes. Defaults to 2.",
				Optional:            true,
			},
			"storage_swap_zram": schema.BoolAttribute{
				MarkdownDescription: "Enable zram swap compression instead of or in addition to disk swap.",
				Optional:            true,
			},
			"storage_data_size_gb": schema.Int64Attribute{
				MarkdownDescription: "Data partition size (/var/lib/axonwall) in gigabytes.",
				Optional:            true,
			},
			"storage_data_fstype": schema.StringAttribute{
				MarkdownDescription: "Filesystem type for data partition ('ext4' or 'xfs'). Defaults to 'ext4'.",
				Optional:            true,
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
				MarkdownDescription: "Size of /var/log partition in gigabytes. Defaults to 10.",
				Optional:            true,
			},
			"storage_log_fstype": schema.StringAttribute{
				MarkdownDescription: "Filesystem type for /var/log ('xfs' or 'ext4'). Defaults to 'xfs'.",
				Optional:            true,
			},
			"storage_encryption_enabled": schema.BoolAttribute{
				MarkdownDescription: "Enable LUKS2 volume encryption on persistent data partition.",
				Optional:            true,
			},
			"storage_encryption_passphrase": schema.StringAttribute{
				MarkdownDescription: "Optional manual passphrase for LUKS2 volume unlock.",
				Optional:            true,
				Sensitive:           true,
			},
			"storage_tpm2_auto_unlock": schema.BoolAttribute{
				MarkdownDescription: "Enroll TPM2 chip (PCRs 0,2,7) via systemd-cryptenroll for hardware auto-unlock.",
				Optional:            true,
			},
			"storage_system_raid_enabled": schema.BoolAttribute{
				MarkdownDescription: "Enable RAID-1 mirroring across target disks for system and data.",
				Optional:            true,
			},
			"desired_state_json": schema.StringAttribute{
				MarkdownDescription: "Declarative DesiredState JSON payload containing firewall rules, interfaces, wireguard, etc.",
				Optional:            true,
			},
			"rendered": schema.StringAttribute{
				MarkdownDescription: "Rendered #cloud-config YAML document.",
				Computed:            true,
				Sensitive:           true,
			},
		},
	}
}

func (d *CloudInitConfigDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var data CloudInitConfigModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

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
	if !data.AdminPasswordHash.IsNull() && data.AdminPasswordHash.ValueString() != "" {
		userEntry["passwd"] = data.AdminPasswordHash.ValueString()
		userEntry["lock_passwd"] = false
	}
	cloudConfig["users"] = []interface{}{userEntry}

	// Axonwall namespace
	axonwallMap := make(map[string]interface{})

	// Auth
	authMap := map[string]interface{}{
		"admin_username": adminUser,
	}
	if !data.AdminPassword.IsNull() && data.AdminPassword.ValueString() != "" {
		authMap["admin_password"] = data.AdminPassword.ValueString()
	}
	if !data.AdminPasswordHash.IsNull() && data.AdminPasswordHash.ValueString() != "" {
		authMap["admin_password_hash"] = data.AdminPasswordHash.ValueString()
	}
	if !data.ZTPEnabled.IsNull() && data.ZTPEnabled.ValueBool() {
		ztpMap := map[string]interface{}{
			"enabled": true,
		}
		if !data.ZTPControllerURL.IsNull() {
			ztpMap["controller_url"] = data.ZTPControllerURL.ValueString()
		}
		if !data.ZTPEnrollmentToken.IsNull() {
			ztpMap["enrollment_token"] = data.ZTPEnrollmentToken.ValueString()
		}
		authMap["ztp"] = ztpMap
	}
	axonwallMap["auth"] = authMap

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

	standbyEnabled := true
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

	systemRaidMap := map[string]interface{}{
		"enabled": false,
		"level":   "raid1",
	}
	if !data.StorageSystemRAIDEnabled.IsNull() && data.StorageSystemRAIDEnabled.ValueBool() {
		systemRaidMap["enabled"] = true
	}

	storageMap := map[string]interface{}{
		"layout_mode":  layoutMode,
		"target_disks": targetDisks,
		"partitions":   partitionsMap,
		"encryption":   encryptionMap,
		"system_raid":  systemRaidMap,
	}
	axonwallMap["storage"] = storageMap

	// Desired State injection
	if !data.DesiredStateJSON.IsNull() && data.DesiredStateJSON.ValueString() != "" {
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
