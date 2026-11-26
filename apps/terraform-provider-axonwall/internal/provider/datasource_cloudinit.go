package provider

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"slices"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"gopkg.in/yaml.v3"
)

var _ datasource.DataSource = &CloudInitConfigDataSource{}

type CloudInitConfigDataSource struct{}

type CloudInitConfigModel struct {
	Hostname                      types.String `tfsdk:"hostname"`
	FQDN                          types.String `tfsdk:"fqdn"`
	Timezone                      types.String `tfsdk:"timezone"`
	Edition                       types.String `tfsdk:"edition"`
	InstallMode                   types.String `tfsdk:"install_mode"`
	AllowWipeExisting             types.Bool   `tfsdk:"allow_wipe_existing"`
	StarterPacks                  types.List   `tfsdk:"starter_packs"`
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
	ZFSAllocMode                  types.String `tfsdk:"zfs_alloc_mode"`
	ZFSSizeGB                     types.Int64  `tfsdk:"zfs_size_gb"`
	ZFSRaidTopology               types.String `tfsdk:"zfs_raid_topology"`
	ZFSExtraDisks                 types.List   `tfsdk:"zfs_extra_disks"`
	ZFSSlogDisks                  types.List   `tfsdk:"zfs_slog_disks"`
	ZFSL2arcDisks                 types.List   `tfsdk:"zfs_l2arc_disks"`
	ZFSSpareDisks                 types.List   `tfsdk:"zfs_spare_disks"`
	DesiredStateJSON              types.String `tfsdk:"desired_state_json"`
	Rendered                      types.String `tfsdk:"rendered"`
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
				Validators:          []validator.String{stringOneOfValidator{allowed: []string{"standard_ab", "compact_ab", "single_root", "custom"}}},
			},
			"storage_target_disks": schema.ListAttribute{
				ElementType:         types.StringType,
				MarkdownDescription: "Target disk devices (e.g. ['/dev/sda', '/dev/sdb']). Defaults to ['/dev/sda'].",
				Optional:            true,
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
			},
			"zfs_slog_disks": schema.ListAttribute{
				ElementType:         types.StringType,
				MarkdownDescription: "Dedicated ZFS SLOG (ZIL) disks.",
				Optional:            true,
			},
			"zfs_l2arc_disks": schema.ListAttribute{
				ElementType:         types.StringType,
				MarkdownDescription: "Dedicated ZFS L2ARC cache disks.",
				Optional:            true,
			},
			"zfs_spare_disks": schema.ListAttribute{
				ElementType:         types.StringType,
				MarkdownDescription: "Dedicated ZFS hot-spare disks.",
				Optional:            true,
			},
			"desired_state_json": schema.StringAttribute{
				MarkdownDescription: "Declarative DesiredState JSON payload containing firewall rules, interfaces, wireguard, etc.",
				Optional:            true,
				Sensitive:           true,
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
		if !data.ZTPControllerURL.IsNull() && strings.TrimSpace(data.ZTPControllerURL.ValueString()) != "" {
			ztpURL := strings.TrimSpace(data.ZTPControllerURL.ValueString())
			ztpMap["controller_url"] = ztpURL
			axonwallMap["hub_url"] = ztpURL
		}
		if !data.ZTPEnrollmentToken.IsNull() && strings.TrimSpace(data.ZTPEnrollmentToken.ValueString()) != "" {
			ztpTok := strings.TrimSpace(data.ZTPEnrollmentToken.ValueString())
			ztpMap["enrollment_token"] = ztpTok
			axonwallMap["ztp_token"] = ztpTok
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
