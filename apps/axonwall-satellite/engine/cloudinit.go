package engine

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// CloudInitPayload holds raw configuration blobs retrieved from a Cloud-Init datasource
// (NoCloud cidata, ConfigDrive config-2, QEMU fw_cfg, or Cloud IMDS 169.254.169.254).
type CloudInitPayload struct {
	Datasource    string
	UserData      string
	MetaData      string
	NetworkConfig string
}

// CloudInitWriteFile represents a file entry in a #cloud-config write_files section.
type CloudInitWriteFile struct {
	Path        string
	Content     string
	Encoding    string
	Permissions string
}

// MergeCloudInitIntoBootConfig merges parsed Cloud-Init metadata, network-config, and user-data
// into an existing EdgeBootConfig. Values present in Cloud-Init override baked-in UKI defaults.
func MergeCloudInitIntoBootConfig(base *EdgeBootConfig, payload CloudInitPayload, rootDir string) error {
	if base == nil {
		return fmt.Errorf("nil EdgeBootConfig")
	}
	if rootDir == "" {
		rootDir = "/"
	}

	// 1. Parse meta-data (hostname / instance-id)
	if strings.TrimSpace(payload.MetaData) != "" {
		metaID, metaHost := ParseCloudInitMetaData(payload.MetaData)
		if base.SatelliteID == "" {
			if metaHost != "" {
				base.SatelliteID = metaHost
			} else if metaID != "" {
				base.SatelliteID = metaID
			}
		}
	}

	// 2. Parse network-config (Cloud-Init v1 physical subnets or v2 Netplan ethernets)
	if strings.TrimSpace(payload.NetworkConfig) != "" {
		ifaces, routes := ParseCloudInitNetworkConfig(payload.NetworkConfig)
		if len(ifaces) > 0 {
			base.Interfaces = mergeInterfaceSpecs(base.Interfaces, ifaces)
		}
		if len(routes) > 0 {
			base.Routes = append(base.Routes, routes...)
		}
	}

	// 3. Parse user-data (#cloud-config YAML, JSON, or AXONWALL_* env lines)
	if strings.TrimSpace(payload.UserData) != "" {
		if err := ApplyCloudInitUserData(base, payload.UserData, rootDir); err != nil {
			return err
		}
	}

	return nil
}

// ParseCloudInitMetaData extracts instance-id and local-hostname from JSON or YAML meta-data.
func ParseCloudInitMetaData(raw string) (instanceID string, hostname string) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return "", ""
	}

	// Try JSON first (ConfigDrive meta_data.json / OpenStack)
	if strings.HasPrefix(trimmed, "{") {
		var obj map[string]interface{}
		if err := json.Unmarshal([]byte(trimmed), &obj); err == nil {
			for _, k := range []string{"instance-id", "instance_id", "uuid"} {
				if v, ok := obj[k].(string); ok && strings.TrimSpace(v) != "" {
					instanceID = strings.TrimSpace(v)
					break
				}
			}
			for _, k := range []string{"local-hostname", "local_hostname", "hostname", "name"} {
				if v, ok := obj[k].(string); ok && strings.TrimSpace(v) != "" {
					hostname = strings.TrimSpace(v)
					break
				}
			}
			return sanitizeIdentifier(instanceID), sanitizeIdentifier(hostname)
		}
	}

	// Line-based YAML / key-value parsing (NoCloud meta-data)
	for _, line := range strings.Split(trimmed, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}
		k := strings.ToLower(strings.TrimSpace(parts[0]))
		v := unquoteYAML(strings.TrimSpace(parts[1]))
		switch k {
		case "instance-id", "instance_id", "uuid":
			if instanceID == "" {
				instanceID = v
			}
		case "local-hostname", "local_hostname", "hostname":
			if hostname == "" {
				hostname = v
			}
		}
	}

	return sanitizeIdentifier(instanceID), sanitizeIdentifier(hostname)
}

// ApplyCloudInitUserData parses #cloud-config YAML, JSON, or key=value user-data
// and populates EdgeBootConfig as well as writing any provisioned certificates or files.
func ApplyCloudInitUserData(cfg *EdgeBootConfig, raw string, rootDir string) error {
	if rootDir == "" {
		rootDir = "/"
	}
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return nil
	}

	// Support JSON user-data payloads directly
	if strings.HasPrefix(trimmed, "{") {
		return applyCloudInitJSON(cfg, trimmed, rootDir)
	}

	lines := strings.Split(strings.ReplaceAll(raw, "\r\n", "\n"), "\n")

	var (
		inAxonwallSection   bool
		axonwallIndent      int
		inInterfacesList    bool
		inRoutesList        bool
		inWriteFilesList    bool
		currentBlockKey     string
		currentBlockIndent  int
		currentBlockBuilder strings.Builder

		curIface     *EdgeInterfaceSpec
		curRoute     *EdgeRouteSpec
		curWriteFile *CloudInitWriteFile
		writeFiles   []CloudInitWriteFile

		caCertPEM     string
		clientCertPEM string
		clientKeyPEM  string
	)

	flushBlockScalar := func() {
		if currentBlockKey == "" {
			return
		}
		content := currentBlockBuilder.String()
		switch currentBlockKey {
		case "ca_cert", "cacert":
			caCertPEM = content
		case "client_cert", "satellite_cert", "cert":
			clientCertPEM = content
		case "client_key", "satellite_key", "key":
			clientKeyPEM = content
		case "write_file_content":
			if curWriteFile != nil {
				curWriteFile.Content = content
			}
		}
		currentBlockKey = ""
		currentBlockBuilder.Reset()
	}

	flushPendingItems := func() {
		if curIface != nil && curIface.Device != "" {
			if curIface.MTU <= 0 {
				curIface.MTU = 1500
			}
			curIface.Enabled = true
			cfg.Interfaces = mergeInterfaceSpecs(cfg.Interfaces, []EdgeInterfaceSpec{*curIface})
			curIface = nil
		}
		if curRoute != nil && curRoute.Destination != "" && curRoute.Gateway != "" {
			cfg.Routes = append(cfg.Routes, *curRoute)
			curRoute = nil
		}
		if curWriteFile != nil && curWriteFile.Path != "" {
			writeFiles = append(writeFiles, *curWriteFile)
			curWriteFile = nil
		}
	}

	for _, rawLine := range lines {
		trimmedLine := strings.TrimSpace(rawLine)
		indent := countLeadingSpaces(rawLine)

		// Handle multiline YAML block scalar (| or >)
		if currentBlockKey != "" {
			if trimmedLine == "" {
				currentBlockBuilder.WriteString("\n")
				continue
			}
			if indent > currentBlockIndent {
				stripLen := currentBlockIndent + 2
				if stripLen > len(rawLine) {
					stripLen = indent
				}
				currentBlockBuilder.WriteString(rawLine[stripLen:] + "\n")
				continue
			}
			flushBlockScalar()
		}

		if trimmedLine == "" || strings.HasPrefix(trimmedLine, "#") {
			continue
		}

		// Check if we exited `axonwall:` section
		if inAxonwallSection && indent <= axonwallIndent && !strings.HasPrefix(trimmedLine, "-") {
			flushPendingItems()
			inAxonwallSection = false
			inInterfacesList = false
			inRoutesList = false
		}

		// Top-level or section transitions
		if !strings.HasPrefix(trimmedLine, "-") && strings.HasSuffix(trimmedLine, ":") {
			sectionName := strings.ToLower(strings.TrimSuffix(trimmedLine, ":"))
			flushPendingItems()
			switch sectionName {
			case "axonwall":
				inAxonwallSection = true
				axonwallIndent = indent
				inInterfacesList = false
				inRoutesList = false
				inWriteFilesList = false
				continue
			case "interfaces":
				inInterfacesList = true
				inRoutesList = false
				inWriteFilesList = false
				continue
			case "routes":
				inRoutesList = true
				inInterfacesList = false
				inWriteFilesList = false
				continue
			case "write_files":
				inWriteFilesList = true
				inInterfacesList = false
				inRoutesList = false
				continue
			}
		}

		// Handle list items under interfaces:, routes:, or write_files:
		if inInterfacesList {
			if strings.HasPrefix(trimmedLine, "-") {
				flushPendingItems()
				curIface = &EdgeInterfaceSpec{MTU: 1500, Enabled: true}
				rest := strings.TrimSpace(strings.TrimPrefix(trimmedLine, "-"))
				if rest != "" {
					applyInterfaceKV(curIface, rest)
				}
				continue
			} else if curIface != nil && strings.Contains(trimmedLine, ":") {
				applyInterfaceKV(curIface, trimmedLine)
				continue
			}
		}

		if inRoutesList {
			if strings.HasPrefix(trimmedLine, "-") {
				flushPendingItems()
				curRoute = &EdgeRouteSpec{}
				rest := strings.TrimSpace(strings.TrimPrefix(trimmedLine, "-"))
				if rest != "" {
					applyRouteKV(curRoute, rest)
				}
				continue
			} else if curRoute != nil && strings.Contains(trimmedLine, ":") {
				applyRouteKV(curRoute, trimmedLine)
				continue
			}
		}

		if inWriteFilesList {
			if strings.HasPrefix(trimmedLine, "-") {
				flushPendingItems()
				curWriteFile = &CloudInitWriteFile{Permissions: "0600"}
				rest := strings.TrimSpace(strings.TrimPrefix(trimmedLine, "-"))
				if rest != "" {
					if isBlock := applyWriteFileKV(curWriteFile, rest); isBlock {
						currentBlockKey = "write_file_content"
						currentBlockIndent = indent + 2
					}
				}
				continue
			} else if curWriteFile != nil && strings.Contains(trimmedLine, ":") {
				if isBlock := applyWriteFileKV(curWriteFile, trimmedLine); isBlock {
					currentBlockKey = "write_file_content"
					currentBlockIndent = indent
				}
				continue
			}
		}

		// Handle key=value or key: value pairs
		var key, val string
		if strings.Contains(trimmedLine, ":") && (!strings.Contains(trimmedLine, "=") || strings.Index(trimmedLine, ":") < strings.Index(trimmedLine, "=")) {
			parts := strings.SplitN(trimmedLine, ":", 2)
			key = strings.ToLower(strings.TrimSpace(parts[0]))
			val = strings.TrimSpace(parts[1])
		} else if strings.Contains(trimmedLine, "=") {
			parts := strings.SplitN(trimmedLine, "=", 2)
			key = strings.ToLower(strings.TrimSpace(parts[0]))
			val = strings.TrimSpace(parts[1])
		} else {
			continue
		}

		if val == "|" || val == "|-" || val == ">" || val == ">-" {
			currentBlockKey = strings.TrimPrefix(strings.TrimPrefix(key, "axonwall."), "axonwall_")
			currentBlockIndent = indent
			continue
		}

		val = unquoteYAML(val)
		applyScalarConfigKV(cfg, key, val)
	}

	flushBlockScalar()
	flushPendingItems()

	// Write any inline certificates to /etc/axonwall/certs
	certsDir := filepath.Join(rootDir, "etc", "axonwall", "certs")
	if caCertPEM != "" {
		_ = os.MkdirAll(certsDir, 0700)
		_ = os.WriteFile(filepath.Join(certsDir, "ca.crt"), []byte(strings.TrimSpace(caCertPEM)+"\n"), 0600)
	}
	if clientCertPEM != "" {
		_ = os.MkdirAll(certsDir, 0700)
		_ = os.WriteFile(filepath.Join(certsDir, "satellite.crt"), []byte(strings.TrimSpace(clientCertPEM)+"\n"), 0600)
	}
	if clientKeyPEM != "" {
		_ = os.MkdirAll(certsDir, 0700)
		_ = os.WriteFile(filepath.Join(certsDir, "satellite.key"), []byte(strings.TrimSpace(clientKeyPEM)+"\n"), 0600)
	}

	// Process write_files entries
	for _, wf := range writeFiles {
		if err := writeCloudInitFile(cfg, wf, rootDir); err != nil {
			slog.Warn("Skipped cloud-init write_files entry", "path", wf.Path, "error", err)
		}
	}

	return nil
}

// ParseCloudInitNetworkConfig parses Cloud-Init Networking Config v1 (config: physical)
// and v2 (Netplan ethernets:) into EdgeInterfaceSpec and EdgeRouteSpec slices.
func ParseCloudInitNetworkConfig(raw string) ([]EdgeInterfaceSpec, []EdgeRouteSpec) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return nil, nil
	}

	// Detect JSON format (OpenStack network_data.json)
	if strings.HasPrefix(trimmed, "{") {
		return parseNetworkConfigJSON(trimmed)
	}

	var (
		ifaces []EdgeInterfaceSpec
		routes []EdgeRouteSpec
	)

	lines := strings.Split(strings.ReplaceAll(trimmed, "\r\n", "\n"), "\n")

	// Detect whether this is v2 (ethernets:) or v1 (config:)
	isV2 := false
	for _, l := range lines {
		tl := strings.TrimSpace(l)
		if tl == "ethernets:" || strings.HasPrefix(tl, "ethernets:") {
			isV2 = true
			break
		}
	}

	if isV2 {
		var (
			inEthernets   bool
			ethIndent     int
			curDev        string
			devIndent     int
			curSpec       *EdgeInterfaceSpec
			inAddresses   bool
			FirstStaticIP string
		)
		flushDev := func() {
			if curSpec != nil && curSpec.Device != "" {
				if curSpec.Address == "" && FirstStaticIP != "" {
					curSpec.Address = FirstStaticIP
				}
				if curSpec.Address != "" {
					if curSpec.Name == "" {
						curSpec.Name = inferInterfaceRole(len(ifaces), curSpec.Gateway != "")
					}
					curSpec.Enabled = true
					if curSpec.MTU <= 0 {
						curSpec.MTU = 1500
					}
					ifaces = append(ifaces, *curSpec)
				}
			}
			curSpec = nil
			FirstStaticIP = ""
			inAddresses = false
		}

		for _, rawLine := range lines {
			tl := strings.TrimSpace(rawLine)
			if tl == "" || strings.HasPrefix(tl, "#") {
				continue
			}
			indent := countLeadingSpaces(rawLine)

			if tl == "ethernets:" {
				inEthernets = true
				ethIndent = indent
				continue
			}
			if !inEthernets {
				continue
			}
			if indent <= ethIndent {
				flushDev()
				inEthernets = false
				continue
			}

			// New device key under ethernets: (e.g. "  eth0:")
			if strings.HasSuffix(tl, ":") && !strings.HasPrefix(tl, "-") && (curSpec == nil || indent <= devIndent) {
				flushDev()
				curDev = strings.TrimSuffix(tl, ":")
				devIndent = indent
				curSpec = &EdgeInterfaceSpec{
					Device:  curDev,
					MTU:     1500,
					Enabled: true,
				}
				continue
			}

			if curSpec == nil {
				continue
			}

			if tl == "addresses:" {
				inAddresses = true
				continue
			}
			if inAddresses {
				if strings.HasPrefix(tl, "-") {
					addrVal := unquoteYAML(strings.TrimSpace(strings.TrimPrefix(tl, "-")))
					if _, _, err := net.ParseCIDR(addrVal); err == nil && FirstStaticIP == "" {
						FirstStaticIP = addrVal
					}
					continue
				}
				inAddresses = false
			}

			if strings.Contains(tl, ":") {
				parts := strings.SplitN(tl, ":", 2)
				k := strings.ToLower(strings.TrimSpace(parts[0]))
				v := unquoteYAML(strings.TrimSpace(parts[1]))
				switch k {
				case "dhcp4":
					if v == "true" || v == "yes" || v == "1" {
						curSpec.Address = "dhcp"
					}
				case "addresses":
					// Inline array e.g. addresses: [10.0.0.1/24]
					v = strings.Trim(v, "[]")
					for _, item := range strings.Split(v, ",") {
						item = unquoteYAML(strings.TrimSpace(item))
						if _, _, err := net.ParseCIDR(item); err == nil && FirstStaticIP == "" {
							FirstStaticIP = item
						}
					}
				case "gateway4", "via":
					if net.ParseIP(v) != nil {
						curSpec.Gateway = v
					}
				case "mtu":
					if mtu, err := strconv.Atoi(v); err == nil && mtu >= 576 && mtu <= 9216 {
						curSpec.MTU = mtu
					}
				}
			}
		}
		flushDev()
		return ifaces, routes
	}

	// Cloud-Init v1 networking config (`version: 1`, `config:` list of `type: physical` and `subnets:`)
	var (
		curSpec   *EdgeInterfaceSpec
		inSubnets bool
		curAddr   string
		curMask   string
		curGW     string
		curType   string
	)
	flushSubnet := func() {
		if curSpec == nil {
			return
		}
		if strings.EqualFold(curType, "dhcp") || strings.EqualFold(curType, "dhcp4") {
			curSpec.Address = "dhcp"
		} else if curAddr != "" {
			if strings.Contains(curAddr, "/") {
				curSpec.Address = curAddr
			} else if curMask != "" {
				if cidr := ipAndMaskToCIDR(curAddr, curMask); cidr != "" {
					curSpec.Address = cidr
				}
			} else {
				curSpec.Address = curAddr + "/24"
			}
		}
		if curGW != "" && net.ParseIP(curGW) != nil {
			curSpec.Gateway = curGW
		}
		curAddr, curMask, curGW, curType = "", "", "", ""
	}
	flushV1Spec := func() {
		flushSubnet()
		if curSpec != nil && curSpec.Device != "" && curSpec.Address != "" {
			if curSpec.Name == "" {
				curSpec.Name = inferInterfaceRole(len(ifaces), curSpec.Gateway != "")
			}
			ifaces = append(ifaces, *curSpec)
		}
		curSpec = nil
		inSubnets = false
	}

	for _, rawLine := range lines {
		tl := strings.TrimSpace(rawLine)
		if tl == "" || strings.HasPrefix(tl, "#") {
			continue
		}
		if tl == "subnets:" {
			inSubnets = true
			continue
		}
		if strings.HasPrefix(tl, "- type:") {
			typeVal := unquoteYAML(strings.TrimSpace(strings.TrimPrefix(tl, "- type:")))
			if inSubnets && (typeVal == "dhcp" || typeVal == "dhcp4" || typeVal == "static") {
				flushSubnet()
				curType = typeVal
				continue
			}
			flushV1Spec()
			if typeVal == "physical" {
				curSpec = &EdgeInterfaceSpec{MTU: 1500, Enabled: true}
			}
			continue
		}
		if curSpec == nil {
			continue
		}
		if strings.Contains(tl, ":") {
			parts := strings.SplitN(strings.TrimSpace(strings.TrimPrefix(tl, "-")), ":", 2)
			if len(parts) != 2 {
				continue
			}
			k := strings.ToLower(strings.TrimSpace(parts[0]))
			v := unquoteYAML(strings.TrimSpace(parts[1]))
			if inSubnets {
				switch k {
				case "type":
					curType = v
				case "address", "ip_address":
					curAddr = v
				case "netmask":
					curMask = v
				case "gateway":
					curGW = v
				}
			} else {
				switch k {
				case "name":
					curSpec.Device = v
				case "mtu":
					if mtu, err := strconv.Atoi(v); err == nil && mtu >= 576 && mtu <= 9216 {
						curSpec.MTU = mtu
					}
				}
			}
		}
	}
	flushV1Spec()

	return ifaces, routes
}

// DiscoverLocalCloudInit probes local seed datasources (QEMU fw_cfg and NoCloud/ConfigDrive
// block devices /dev/vd*, /dev/sr*, /dev/sd*, /dev/nvme*) without requiring network access.
func DiscoverLocalCloudInit() (CloudInitPayload, bool) {
	// 1. Check QEMU fw_cfg sysfs (/sys/firmware/qemu_fw_cfg/by_name/...)
	fwCfgCandidates := []string{
		"/sys/firmware/qemu_fw_cfg/by_name/opt/org.axonwall/user-data/raw",
		"/sys/firmware/qemu_fw_cfg/by_name/opt/cloud-init/user-data/raw",
		"/sys/firmware/qemu_fw_cfg/by_name/opt/com.coreos/config/raw",
	}
	for _, p := range fwCfgCandidates {
		if data, err := os.ReadFile(p); err == nil && len(bytes.TrimSpace(data)) > 0 {
			meta := readFirstExistingFile("/sys/firmware/qemu_fw_cfg/by_name",
				"opt/org.axonwall/meta-data/raw",
				"opt/cloud-init/meta-data/raw",
			)
			netCfg := readFirstExistingFile("/sys/firmware/qemu_fw_cfg/by_name",
				"opt/org.axonwall/network-config/raw",
				"opt/cloud-init/network-config/raw",
			)
			return CloudInitPayload{
				Datasource:    "qemu-fw-cfg",
				UserData:      string(data),
				MetaData:      meta,
				NetworkConfig: netCfg,
			}, true
		}
	}

	// 2. Scan block devices in /sys/class/block for NoCloud (cidata) or ConfigDrive (config-2)
	entries, err := os.ReadDir("/sys/class/block")
	if err != nil {
		return CloudInitPayload{}, false
	}

	mntDir := "/run/cloud-init-seed"
	_ = os.MkdirAll(mntDir, 0700)
	defer os.Remove(mntDir)

	for _, entry := range entries {
		name := entry.Name()
		if strings.HasPrefix(name, "loop") || strings.HasPrefix(name, "ram") || strings.HasPrefix(name, "dm-") {
			continue
		}
		devPath := filepath.Join("/dev", name)
		ensureBlockDeviceNode(name, devPath)

		for _, fstype := range []string{"iso9660", "vfat"} {
			if err := syscall.Mount(devPath, mntDir, fstype, syscall.MS_RDONLY|syscall.MS_NOSUID|syscall.MS_NODEV|syscall.MS_NOEXEC, ""); err != nil {
				continue
			}

			payload, found := readMountedCloudInitSeed(mntDir, fmt.Sprintf("block:%s(%s)", devPath, fstype))
			_ = syscall.Unmount(mntDir, 0)
			if found {
				return payload, true
			}
		}
	}

	return CloudInitPayload{}, false
}

// FetchIMDSCloudInit probes cloud hypervisor HTTP metadata services (OpenStack, AWS IMDSv2/v1,
// GCP, and Azure) at baseURL (default "http://169.254.169.254").
func FetchIMDSCloudInit(ctx context.Context, baseURL string) (CloudInitPayload, bool) {
	if baseURL == "" {
		baseURL = "http://169.254.169.254"
	}
	baseURL = strings.TrimRight(baseURL, "/")

	client := &http.Client{Timeout: 1500 * time.Millisecond}

	// 1. OpenStack / ConfigDrive HTTP / Hetzner / DigitalOcean (/openstack/latest/...)
	if userData, ok := httpGetString(ctx, client, baseURL+"/openstack/latest/user_data", nil); ok && strings.TrimSpace(userData) != "" {
		metaData, _ := httpGetString(ctx, client, baseURL+"/openstack/latest/meta_data.json", nil)
		netData, _ := httpGetString(ctx, client, baseURL+"/openstack/latest/network_data.json", nil)
		return CloudInitPayload{
			Datasource:    "imds-openstack",
			UserData:      userData,
			MetaData:      metaData,
			NetworkConfig: netData,
		}, true
	}

	// 2. AWS EC2 / Generic IMDSv2 (with automatic fallback to IMDSv1)
	var awsHeaders map[string]string
	if tokenReq, err := http.NewRequestWithContext(ctx, http.MethodPut, baseURL+"/latest/api/token", nil); err == nil {
		tokenReq.Header.Set("X-aws-ec2-metadata-token-ttl-seconds", "60")
		if resp, err := client.Do(tokenReq); err == nil {
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK && len(bytes.TrimSpace(body)) > 0 {
				awsHeaders = map[string]string{
					"X-aws-ec2-metadata-token": strings.TrimSpace(string(body)),
				}
			}
		}
	}
	if userData, ok := httpGetString(ctx, client, baseURL+"/latest/user-data", awsHeaders); ok && strings.TrimSpace(userData) != "" {
		instID, _ := httpGetString(ctx, client, baseURL+"/latest/meta-data/instance-id", awsHeaders)
		localHost, _ := httpGetString(ctx, client, baseURL+"/latest/meta-data/local-hostname", awsHeaders)
		metaCombined := fmt.Sprintf("instance-id: %s\nlocal-hostname: %s\n", strings.TrimSpace(instID), strings.TrimSpace(localHost))
		return CloudInitPayload{
			Datasource: "imds-ec2",
			UserData:   userData,
			MetaData:   metaCombined,
		}, true
	}

	// 3. Google Cloud Platform (GCP) Metadata Server
	gcpHeaders := map[string]string{"Metadata-Flavor": "Google"}
	if userData, ok := httpGetString(ctx, client, baseURL+"/computeMetadata/v1/instance/attributes/user-data", gcpHeaders); ok && strings.TrimSpace(userData) != "" {
		instName, _ := httpGetString(ctx, client, baseURL+"/computeMetadata/v1/instance/name", gcpHeaders)
		return CloudInitPayload{
			Datasource: "imds-gcp",
			UserData:   userData,
			MetaData:   fmt.Sprintf("local-hostname: %s\n", strings.TrimSpace(instName)),
		}, true
	}

	// 4. Microsoft Azure IMDS
	azureHeaders := map[string]string{"Metadata": "true"}
	if b64UserData, ok := httpGetString(ctx, client, baseURL+"/metadata/instance/compute/userData?api-version=2021-01-01&format=text", azureHeaders); ok && strings.TrimSpace(b64UserData) != "" {
		if decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(b64UserData)); err == nil && len(decoded) > 0 {
			vmName, _ := httpGetString(ctx, client, baseURL+"/metadata/instance/compute/name?api-version=2021-01-01&format=text", azureHeaders)
			return CloudInitPayload{
				Datasource: "imds-azure",
				UserData:   string(decoded),
				MetaData:   fmt.Sprintf("local-hostname: %s\n", strings.TrimSpace(vmName)),
			}, true
		}
	}

	return CloudInitPayload{}, false
}

// DiscoverPrimaryNIC finds the first non-loopback network interface in /sys/class/net
// (e.g. "eth0", "enp1s0", "ens3") for zero-touch DHCPv4 + IMDS bootstrap when no
// explicit interface list was supplied on the kernel command line or local cidata drive.
func DiscoverPrimaryNIC(sysClassNetDir string) string {
	if sysClassNetDir == "" {
		sysClassNetDir = "/sys/class/net"
	}
	entries, err := os.ReadDir(sysClassNetDir)
	if err != nil {
		return ""
	}
	// Prefer eth0 first if present
	for _, e := range entries {
		if e.Name() == "eth0" {
			return "eth0"
		}
	}
	for _, e := range entries {
		name := e.Name()
		if name == "lo" || strings.HasPrefix(name, "wg") || strings.HasPrefix(name, "tailscale") ||
			strings.HasPrefix(name, "veth") || strings.HasPrefix(name, "br") || strings.HasPrefix(name, "bond") ||
			strings.HasPrefix(name, "sit") || strings.HasPrefix(name, "tun") {
			continue
		}
		return name
	}
	return ""
}

// Helper functions

func readMountedCloudInitSeed(mntDir, sourceLabel string) (CloudInitPayload, bool) {
	// Check NoCloud layout (/user-data, /meta-data, /network-config)
	userData := readFirstExistingFile(mntDir, "user-data", "USER-DATA", "USER_DATA", "user_data")
	metaData := readFirstExistingFile(mntDir, "meta-data", "META-DATA", "META_DATA", "meta_data")
	netConfig := readFirstExistingFile(mntDir, "network-config", "NETWORK-CONFIG", "NETWORK_CONFIG", "network_config")

	if userData != "" || metaData != "" || netConfig != "" {
		return CloudInitPayload{
			Datasource:    "nocloud:" + sourceLabel,
			UserData:      userData,
			MetaData:      metaData,
			NetworkConfig: netConfig,
		}, true
	}

	// Check ConfigDrive v2 layout (/openstack/latest/...)
	osDir := filepath.Join(mntDir, "openstack", "latest")
	osUser := readFirstExistingFile(osDir, "user_data", "USER_DATA")
	osMeta := readFirstExistingFile(osDir, "meta_data.json", "META_DATA.JSON")
	osNet := readFirstExistingFile(osDir, "network_data.json", "NETWORK_DATA.JSON")

	if osUser != "" || osMeta != "" || osNet != "" {
		return CloudInitPayload{
			Datasource:    "configdrive:" + sourceLabel,
			UserData:      osUser,
			MetaData:      osMeta,
			NetworkConfig: osNet,
		}, true
	}

	return CloudInitPayload{}, false
}

func readFirstExistingFile(dir string, names ...string) string {
	for _, name := range names {
		p := filepath.Join(dir, name)
		if data, err := os.ReadFile(p); err == nil && len(bytes.TrimSpace(data)) > 0 {
			return string(data)
		}
	}
	return ""
}

func ensureBlockDeviceNode(devName, devPath string) {
	if _, err := os.Stat(devPath); err == nil {
		return
	}
	devNumBytes, err := os.ReadFile(filepath.Join("/sys/class/block", devName, "dev"))
	if err != nil {
		return
	}
	parts := strings.SplitN(strings.TrimSpace(string(devNumBytes)), ":", 2)
	if len(parts) != 2 {
		return
	}
	maj, err1 := strconv.Atoi(parts[0])
	min, err2 := strconv.Atoi(parts[1])
	if err1 != nil || err2 != nil {
		return
	}
	dev := int((maj << 8) | (min & 0xff) | ((min & 0xfff00) << 12))
	_ = syscall.Mknod(devPath, syscall.S_IFBLK|0600, dev)
}

func httpGetString(ctx context.Context, client *http.Client, reqURL string, headers map[string]string) (string, bool) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return "", false
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", false
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", false
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 256*1024))
	if err != nil {
		return "", false
	}
	return string(body), true
}

func applyScalarConfigKV(cfg *EdgeBootConfig, rawKey, val string) {
	if val == "" {
		return
	}
	key := strings.ToLower(strings.TrimSpace(rawKey))
	key = strings.TrimPrefix(key, "export ")
	key = strings.TrimPrefix(key, "axonwall.")
	key = strings.TrimPrefix(key, "axonwall_")

	switch key {
	case "hub", "hub_url", "huburl", "core", "core_url":
		cfg.HubURL = val
	case "id", "satellite_id", "satelliteid", "hostname", "fqdn":
		if key == "hostname" || key == "fqdn" {
			cfg.Hostname = sanitizeIdentifier(val)
			if cfg.SatelliteID == "" {
				cfg.SatelliteID = sanitizeIdentifier(val)
			}
		} else {
			cfg.SatelliteID = sanitizeIdentifier(val)
		}
	case "token", "ztp_token", "ztptoken":
		cfg.ZtpToken = val
	case "sku", "sku_profile", "skuprofile":
		cfg.SkuProfile = val
	case "slot", "uki_slot", "ukislot":
		cfg.UkiSlot = val
	case "watchdog", "watchdog_sec", "watchdogsec":
		if sec, err := strconv.Atoi(val); err == nil && sec > 0 {
			cfg.WatchdogSec = sec
		}
	case "insecure_bootstrap", "insecurebootstrap":
		cfg.InsecureBootstrap = (val == "1" || strings.EqualFold(val, "true") || strings.EqualFold(val, "yes"))
	case "wan", "lan", "mgmt":
		if spec, ok := parseInterfaceBootArg(key, val); ok {
			cfg.Interfaces = mergeInterfaceSpecs(cfg.Interfaces, []EdgeInterfaceSpec{spec})
		}
	}
}

func applyInterfaceKV(spec *EdgeInterfaceSpec, line string) {
	parts := strings.SplitN(line, ":", 2)
	if len(parts) != 2 {
		return
	}
	k := strings.ToLower(strings.TrimSpace(parts[0]))
	v := unquoteYAML(strings.TrimSpace(parts[1]))
	switch k {
	case "name", "role":
		spec.Name = v
	case "device", "dev", "interface", "ifname":
		spec.Device = v
	case "address", "ip", "cidr":
		spec.Address = v
	case "gateway", "gw":
		spec.Gateway = v
	case "ipv6_mode", "ipv6mode":
		spec.IPv6Mode = v
	case "ipv6_address", "ipv6address", "ip6":
		spec.IPv6Address = v
	case "mtu":
		if mtu, err := strconv.Atoi(v); err == nil && mtu >= 576 && mtu <= 9216 {
			spec.MTU = mtu
		}
	}
}

func applyRouteKV(rt *EdgeRouteSpec, line string) {
	parts := strings.SplitN(line, ":", 2)
	if len(parts) != 2 {
		return
	}
	k := strings.ToLower(strings.TrimSpace(parts[0]))
	v := unquoteYAML(strings.TrimSpace(parts[1]))
	switch k {
	case "destination", "to", "dst":
		rt.Destination = v
	case "gateway", "via", "gw":
		rt.Gateway = v
	case "device", "dev":
		rt.Device = v
	}
}

func applyWriteFileKV(wf *CloudInitWriteFile, line string) bool {
	parts := strings.SplitN(line, ":", 2)
	if len(parts) != 2 {
		return false
	}
	k := strings.ToLower(strings.TrimSpace(parts[0]))
	v := strings.TrimSpace(parts[1])
	if k == "content" && (v == "|" || v == "|-" || v == ">" || v == ">-") {
		return true
	}
	v = unquoteYAML(v)
	switch k {
	case "path":
		wf.Path = v
	case "content":
		wf.Content = v
	case "encoding":
		wf.Encoding = strings.ToLower(v)
	case "permissions", "perm":
		wf.Permissions = v
	}
	return false
}

func writeCloudInitFile(cfg *EdgeBootConfig, wf CloudInitWriteFile, rootDir string) error {
	cleanRel := filepath.Clean("/" + strings.TrimSpace(wf.Path))
	// Restrict cloud-init write_files to safe configuration paths in RAM
	allowedPrefixes := []string{
		"/etc/axonwall/",
		"/etc/wireguard/",
		"/etc/nftables.conf",
		"/etc/resolv.conf",
		"/etc/hosts",
	}
	allowed := false
	for _, prefix := range allowedPrefixes {
		if cleanRel == prefix || strings.HasPrefix(cleanRel, prefix) {
			allowed = true
			break
		}
	}
	if !allowed {
		return fmt.Errorf("path %q outside allowed /etc/axonwall scope", cleanRel)
	}

	rawBytes := []byte(wf.Content)
	switch wf.Encoding {
	case "b64", "base64":
		decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(wf.Content))
		if err != nil {
			return err
		}
		rawBytes = decoded
	case "gz+b64", "gzip+base64":
		decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(wf.Content))
		if err != nil {
			return err
		}
		zr, err := gzip.NewReader(bytes.NewReader(decoded))
		if err != nil {
			return err
		}
		uncompressed, err := io.ReadAll(io.LimitReader(zr, 512*1024))
		_ = zr.Close()
		if err != nil {
			return err
		}
		rawBytes = uncompressed
	}

	perm := os.FileMode(0600)
	if wf.Permissions != "" {
		if parsed, err := strconv.ParseUint(wf.Permissions, 8, 32); err == nil {
			perm = os.FileMode(parsed) & 0777
		}
	}

	destPath := filepath.Join(rootDir, strings.TrimPrefix(cleanRel, "/"))
	if err := os.MkdirAll(filepath.Dir(destPath), 0700); err != nil {
		return err
	}
	if err := os.WriteFile(destPath, rawBytes, perm); err != nil {
		return err
	}

	// If the written file is an Axonwall environment file, also parse its key=value lines
	if strings.HasSuffix(cleanRel, ".env") || strings.HasSuffix(cleanRel, ".conf") {
		for _, line := range strings.Split(string(rawBytes), "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") || !strings.Contains(line, "=") {
				continue
			}
			parts := strings.SplitN(line, "=", 2)
			applyScalarConfigKV(cfg, parts[0], unquoteYAML(strings.TrimSpace(parts[1])))
		}
	}

	return nil
}

func applyCloudInitJSON(cfg *EdgeBootConfig, rawJSON, rootDir string) error {
	var doc map[string]interface{}
	if err := json.Unmarshal([]byte(rawJSON), &doc); err != nil {
		return err
	}
	if ax, ok := doc["axonwall"].(map[string]interface{}); ok {
		for k, v := range ax {
			if s, ok := v.(string); ok {
				applyScalarConfigKV(cfg, k, s)
			} else if b, ok := v.(bool); ok {
				applyScalarConfigKV(cfg, k, strconv.FormatBool(b))
			}
		}
	}
	for k, v := range doc {
		if s, ok := v.(string); ok {
			applyScalarConfigKV(cfg, k, s)
		}
	}
	return nil
}

func parseNetworkConfigJSON(rawJSON string) ([]EdgeInterfaceSpec, []EdgeRouteSpec) {
	var doc struct {
		Services []struct {
			Type    string `json:"type"`
			Address string `json:"address"`
		} `json:"services"`
		Networks []struct {
			Type      string `json:"type"`
			NetworkID string `json:"network_id"`
			Link      string `json:"link"`
			IPAddress string `json:"ip_address"`
			Netmask   string `json:"netmask"`
			Routes    []struct {
				Network string `json:"network"`
				Netmask string `json:"netmask"`
				Gateway string `json:"gateway"`
			} `json:"routes"`
		} `json:"networks"`
	}
	if err := json.Unmarshal([]byte(rawJSON), &doc); err != nil {
		return nil, nil
	}

	var (
		ifaces []EdgeInterfaceSpec
		routes []EdgeRouteSpec
	)
	for i, n := range doc.Networks {
		dev := n.Link
		if dev == "" {
			dev = fmt.Sprintf("eth%d", i)
		}
		spec := EdgeInterfaceSpec{
			Device:  dev,
			MTU:     1500,
			Enabled: true,
		}
		if strings.Contains(n.Type, "dhcp") {
			spec.Address = "dhcp"
		} else if n.IPAddress != "" {
			spec.Address = ipAndMaskToCIDR(n.IPAddress, n.Netmask)
		}
		for _, r := range n.Routes {
			if (r.Network == "0.0.0.0" || r.Network == "::") && net.ParseIP(r.Gateway) != nil {
				spec.Gateway = r.Gateway
			} else if r.Network != "" && net.ParseIP(r.Gateway) != nil {
				dst := ipAndMaskToCIDR(r.Network, r.Netmask)
				if dst != "" {
					routes = append(routes, EdgeRouteSpec{
						Destination: dst,
						Gateway:     r.Gateway,
						Device:      dev,
					})
				}
			}
		}
		if spec.Address != "" {
			spec.Name = inferInterfaceRole(len(ifaces), spec.Gateway != "")
			ifaces = append(ifaces, spec)
		}
	}
	return ifaces, routes
}

func mergeInterfaceSpecs(existing, incoming []EdgeInterfaceSpec) []EdgeInterfaceSpec {
	out := make([]EdgeInterfaceSpec, len(existing))
	copy(out, existing)
	for _, inc := range incoming {
		replaced := false
		for i := range out {
			if (inc.Device != "" && out[i].Device == inc.Device) || (inc.Name != "" && out[i].Name == inc.Name) {
				out[i] = inc
				replaced = true
				break
			}
		}
		if !replaced {
			out = append(out, inc)
		}
	}
	return out
}

func inferInterfaceRole(index int, hasDefaultGateway bool) string {
	if index == 0 || hasDefaultGateway {
		return "wan"
	}
	if index == 1 {
		return "lan"
	}
	return "mgmt"
}

func ipAndMaskToCIDR(ipStr, maskStr string) string {
	ip := net.ParseIP(strings.TrimSpace(ipStr))
	if ip == nil {
		return ""
	}
	if maskStr == "" {
		if ip.To4() != nil {
			return ip.String() + "/24"
		}
		return ip.String() + "/64"
	}
	maskIP := net.ParseIP(strings.TrimSpace(maskStr))
	if maskIP == nil {
		return ""
	}
	if v4Mask := maskIP.To4(); v4Mask != nil {
		ones, bits := net.IPv4Mask(v4Mask[0], v4Mask[1], v4Mask[2], v4Mask[3]).Size()
		if bits > 0 {
			return fmt.Sprintf("%s/%d", ip.String(), ones)
		}
	}
	return ip.String() + "/24"
}

func countLeadingSpaces(s string) int {
	n := 0
	for _, ch := range s {
		if ch == ' ' {
			n++
		} else if ch == '\t' {
			n += 2
		} else {
			break
		}
	}
	return n
}

func unquoteYAML(s string) string {
	s = strings.TrimSpace(s)
	if len(s) >= 2 {
		if (s[0] == '"' && s[len(s)-1] == '"') || (s[0] == '\'' && s[len(s)-1] == '\'') {
			return s[1 : len(s)-1]
		}
	}
	return s
}

func sanitizeIdentifier(s string) string {
	s = strings.TrimSpace(s)
	var b strings.Builder
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_' || r == '.' {
			b.WriteRune(r)
		}
	}
	return b.String()
}
