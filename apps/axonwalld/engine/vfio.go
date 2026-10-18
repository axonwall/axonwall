package engine

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
)

type PciDeviceInventory struct {
	BDF            string `json:"bdf"`
	VendorID       string `json:"vendorId"`
	DeviceID       string `json:"deviceId"`
	DeviceClass    string `json:"deviceClass"`
	DeviceName     string `json:"deviceName"`
	IommuGroup     int    `json:"iommuGroup"`
	CurrentDriver  string `json:"currentDriver"`
	IsVfioBound    bool   `json:"isVfioBound"`
	SriovSupported bool   `json:"sriovSupported"`
	SriovTotalVfs  int    `json:"sriovTotalVfs"`
	SriovNumVfs    int    `json:"sriovNumVfs"`
}

type VFIOManager struct {
	mu sync.RWMutex
}

func NewVFIOManager() *VFIOManager {
	return &VFIOManager{}
}

var bdfRegex = regexp.MustCompile(`^[0-9a-fA-F]{4}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}\.[0-7]$`)

func readSysfsTrim(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

// DiscoverPciDevices scans sysfs for all PCI devices and their IOMMU group assignments
func (m *VFIOManager) DiscoverPciDevices() ([]PciDeviceInventory, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	pciRoot := "/sys/bus/pci/devices"
	entries, err := os.ReadDir(pciRoot)
	if err != nil {
		// Fallback for mock/test environments
		return []PciDeviceInventory{}, nil
	}

	// Try reading lspci map if available for human-readable device names
	lspciMap := make(map[string]string)
	if out, err := exec.Command("lspci", "-D").CombinedOutput(); err == nil {
		for _, line := range strings.Split(string(out), "\n") {
			parts := strings.SplitN(line, " ", 2)
			if len(parts) == 2 {
				lspciMap[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
			}
		}
	}

	var devices []PciDeviceInventory
	for _, entry := range entries {
		bdf := entry.Name()
		if !bdfRegex.MatchString(bdf) {
			continue
		}

		devDir := filepath.Join(pciRoot, bdf)

		vendor := strings.TrimPrefix(readSysfsTrim(filepath.Join(devDir, "vendor")), "0x")
		device := strings.TrimPrefix(readSysfsTrim(filepath.Join(devDir, "device")), "0x")
		class := strings.TrimPrefix(readSysfsTrim(filepath.Join(devDir, "class")), "0x")

		// IOMMU group
		iommuGroup := -1
		if iommuLink, err := os.Readlink(filepath.Join(devDir, "iommu_group")); err == nil {
			groupStr := filepath.Base(iommuLink)
			if g, err := strconv.Atoi(groupStr); err == nil {
				iommuGroup = g
			}
		}

		// Current driver
		currentDriver := "none"
		if driverLink, err := os.Readlink(filepath.Join(devDir, "driver")); err == nil {
			currentDriver = filepath.Base(driverLink)
		}

		// SR-IOV info
		sriovSupported := false
		sriovTotalVfs := 0
		sriovNumVfs := 0
		if totalStr := readSysfsTrim(filepath.Join(devDir, "sriov_totalvfs")); totalStr != "" {
			if tv, err := strconv.Atoi(totalStr); err == nil && tv > 0 {
				sriovSupported = true
				sriovTotalVfs = tv
				if numStr := readSysfsTrim(filepath.Join(devDir, "sriov_numvfs")); numStr != "" {
					if nv, err := strconv.Atoi(numStr); err == nil {
						sriovNumVfs = nv
					}
				}
			}
		}

		devName := lspciMap[bdf]
		if devName == "" {
			devName = fmt.Sprintf("PCI Device [%s:%s] Class %s", vendor, device, class)
		}

		devices = append(devices, PciDeviceInventory{
			BDF:            bdf,
			VendorID:       vendor,
			DeviceID:       device,
			DeviceClass:    class,
			DeviceName:     devName,
			IommuGroup:     iommuGroup,
			CurrentDriver:  currentDriver,
			IsVfioBound:    currentDriver == "vfio-pci",
			SriovSupported: sriovSupported,
			SriovTotalVfs:  sriovTotalVfs,
			SriovNumVfs:    sriovNumVfs,
		})
	}

	return devices, nil
}

// BindVfio overrides the driver and binds the specified BDF to vfio-pci
func (m *VFIOManager) BindVfio(bdf string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if !bdfRegex.MatchString(bdf) {
		return fmt.Errorf("invalid PCI BDF format: %s", bdf)
	}

	devDir := filepath.Join("/sys/bus/pci/devices", bdf)
	if _, err := os.Stat(devDir); os.IsNotExist(err) {
		return fmt.Errorf("pci device %s does not exist", bdf)
	}

	// 1. Ensure vfio-pci module is loaded
	_ = exec.Command("modprobe", "vfio-pci").Run()

	// 2. Unbind existing driver if present
	driverLink := filepath.Join(devDir, "driver")
	if _, err := os.Readlink(driverLink); err == nil {
		unbindPath := filepath.Join(driverLink, "unbind")
		_ = os.WriteFile(unbindPath, []byte(bdf), 0200)
	}

	// 3. Set driver_override to vfio-pci
	overridePath := filepath.Join(devDir, "driver_override")
	if err := os.WriteFile(overridePath, []byte("vfio-pci"), 0644); err != nil {
		return fmt.Errorf("failed to write driver_override for %s: %v", bdf, err)
	}

	// 4. Bind to vfio-pci
	bindPath := "/sys/bus/pci/drivers/vfio-pci/bind"
	if err := os.WriteFile(bindPath, []byte(bdf), 0200); err != nil {
		// If already bound or handled, check if driver is now vfio-pci
		if dl, lErr := os.Readlink(driverLink); lErr == nil && filepath.Base(dl) == "vfio-pci" {
			return nil
		}
		return fmt.Errorf("failed to bind %s to vfio-pci: %v", bdf, err)
	}

	return nil
}

// UnbindVfio releases the device from vfio-pci and triggers a rescan
func (m *VFIOManager) UnbindVfio(bdf string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if !bdfRegex.MatchString(bdf) {
		return fmt.Errorf("invalid PCI BDF format: %s", bdf)
	}

	devDir := filepath.Join("/sys/bus/pci/devices", bdf)
	unbindPath := "/sys/bus/pci/drivers/vfio-pci/unbind"
	_ = os.WriteFile(unbindPath, []byte(bdf), 0200)

	overridePath := filepath.Join(devDir, "driver_override")
	_ = os.WriteFile(overridePath, []byte("\n"), 0644)

	rescanPath := "/sys/bus/pci/rescan"
	_ = os.WriteFile(rescanPath, []byte("1"), 0200)

	return nil
}

// ConfigureSriov changes the number of Virtual Functions allocated to the physical device
func (m *VFIOManager) ConfigureSriov(bdf string, numVfs int) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if !bdfRegex.MatchString(bdf) {
		return fmt.Errorf("invalid PCI BDF format: %s", bdf)
	}

	devDir := filepath.Join("/sys/bus/pci/devices", bdf)
	sriovPath := filepath.Join(devDir, "sriov_numvfs")
	if _, err := os.Stat(sriovPath); os.IsNotExist(err) {
		return fmt.Errorf("device %s does not support SR-IOV (sriov_numvfs missing)", bdf)
	}

	totalStr := readSysfsTrim(filepath.Join(devDir, "sriov_totalvfs"))
	if totalStr != "" {
		if tv, err := strconv.Atoi(totalStr); err == nil && numVfs > tv {
			return fmt.Errorf("requested %d VFs exceeds maximum supported (%d)", numVfs, tv)
		}
	}

	// Writing 0 first is required by many drivers before allocating new VFs
	_ = os.WriteFile(sriovPath, []byte("0"), 0644)

	if numVfs > 0 {
		val := strconv.Itoa(numVfs)
		if err := os.WriteFile(sriovPath, []byte(val), 0644); err != nil {
			return fmt.Errorf("failed to set %d VFs on %s: %v", numVfs, bdf, err)
		}
	}

	return nil
}
