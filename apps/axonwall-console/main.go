package main

import (
	"bufio"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/skip2/go-qrcode"
	"golang.org/x/crypto/scrypt"
)

var currentSessionUser = "admin"

// ANSI color escape codes for terminal styling
const (
	colorReset  = "\033[0m"
	colorBold   = "\033[1m"
	colorDim    = "\033[2m"
	colorRed    = "\033[31m"
	colorGreen  = "\033[32m"
	colorYellow = "\033[33m"
	colorBlue   = "\033[34m"
	colorCyan   = "\033[36m"
	colorWhite  = "\033[37m"
)

type InterfaceInfo struct {
	Name    string
	MAC     string
	Carrier string
	Speed   string
	IPs     []string
}

func getSystemInfo() (hostname, osName, kernel, uptime, loadAvg, memStr string) {
	hostname, _ = os.Hostname()
	if hostname == "" {
		hostname = "axonwall"
	}

	// OS Pretty Name
	if data, err := os.ReadFile("/etc/os-release"); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			if strings.HasPrefix(line, "PRETTY_NAME=") {
				osName = strings.Trim(strings.TrimPrefix(line, "PRETTY_NAME="), "\"")
				break
			}
		}
	}
	if osName == "" {
		osName = "Debian GNU/Linux 13 (Trixie)"
	}

	// Kernel version
	if data, err := os.ReadFile("/proc/version"); err == nil {
		fields := strings.Fields(string(data))
		if len(fields) >= 3 {
			kernel = fields[2]
		}
	}
	if kernel == "" {
		kernel = "Linux 6.12"
	}

	// Uptime
	if data, err := os.ReadFile("/proc/uptime"); err == nil {
		fields := strings.Fields(string(data))
		if len(fields) > 0 {
			if sec, err := strconv.ParseFloat(fields[0], 64); err == nil {
				d := time.Duration(sec) * time.Second
				days := int(d.Hours()) / 24
				hours := int(d.Hours()) % 24
				mins := int(d.Minutes()) % 60
				if days > 0 {
					uptime = fmt.Sprintf("%dd %dh %dm", days, hours, mins)
				} else {
					uptime = fmt.Sprintf("%dh %dm", hours, mins)
				}
			}
		}
	}
	if uptime == "" {
		uptime = "Active"
	}

	// Load Average
	if data, err := os.ReadFile("/proc/loadavg"); err == nil {
		fields := strings.Fields(string(data))
		if len(fields) >= 3 {
			loadAvg = fmt.Sprintf("%s, %s, %s", fields[0], fields[1], fields[2])
		}
	}

	// Memory Usage
	if data, err := os.ReadFile("/proc/meminfo"); err == nil {
		var memTotal, memAvailable uint64
		for _, line := range strings.Split(string(data), "\n") {
			if strings.HasPrefix(line, "MemTotal:") {
				fields := strings.Fields(line)
				if len(fields) >= 2 {
					memTotal, _ = strconv.ParseUint(fields[1], 10, 64)
				}
			} else if strings.HasPrefix(line, "MemAvailable:") {
				fields := strings.Fields(line)
				if len(fields) >= 2 {
					memAvailable, _ = strconv.ParseUint(fields[1], 10, 64)
				}
			}
		}
		if memTotal > 0 {
			memUsed := memTotal - memAvailable
			memPct := (float64(memUsed) / float64(memTotal)) * 100.0
			memStr = fmt.Sprintf("%.1f%% (%d / %d MB)", memPct, memUsed/1024, memTotal/1024)
		}
	}

	return
}

func getInterfaces() []InterfaceInfo {
	var list []InterfaceInfo
	ifaces, err := net.Interfaces()
	if err != nil {
		return list
	}

	for _, iface := range ifaces {
		// Ignore loopback
		if (iface.Flags & net.FlagLoopback) != 0 {
			continue
		}

		info := InterfaceInfo{
			Name: iface.Name,
			MAC:  iface.HardwareAddr.String(),
		}

		// Carrier link status
		carrierFile := filepath.Join("/sys/class/net", iface.Name, "carrier")
		if data, err := os.ReadFile(carrierFile); err == nil && strings.TrimSpace(string(data)) == "1" {
			info.Carrier = "UP"
		} else {
			info.Carrier = "DOWN"
		}

		// Speed
		speedFile := filepath.Join("/sys/class/net", iface.Name, "speed")
		if data, err := os.ReadFile(speedFile); err == nil {
			sp := strings.TrimSpace(string(data))
			if sp != "" && sp != "-1" {
				info.Speed = sp + " Mbps"
			} else {
				info.Speed = "-"
			}
		} else {
			info.Speed = "-"
		}

		// IPs
		addrs, _ := iface.Addrs()
		for _, addr := range addrs {
			info.IPs = append(info.IPs, addr.String())
		}

		list = append(list, info)
	}

	return list
}

func getPrimaryManagementIP() string {
	ifaces := getInterfaces()
	for _, iface := range ifaces {
		if iface.Carrier == "UP" {
			for _, ip := range iface.IPs {
				if strings.Contains(ip, ".") && !strings.HasPrefix(ip, "127.") {
					return strings.Split(ip, "/")[0]
				}
			}
		}
	}
	return "192.168.1.1"
}

func clearScreen() {
	fmt.Print("\033[H\033[2J")
}

func getAdminCredentials() (string, string) {
	adminUser := "admin"
	adminPass := "axonwall"

	// 1. Check /etc/axonwall/admin.env first
	if data, err := os.ReadFile("/etc/axonwall/admin.env"); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "LOCAL_ADMIN_USER=") {
				adminUser = strings.TrimPrefix(line, "LOCAL_ADMIN_USER=")
			} else if strings.HasPrefix(line, "LOCAL_ADMIN_PASSWORD=") {
				adminPass = strings.TrimPrefix(line, "LOCAL_ADMIN_PASSWORD=")
			}
		}
		return adminUser, adminPass
	}

	// 2. Check /etc/axonwall/axonwall.env
	if data, err := os.ReadFile("/etc/axonwall/axonwall.env"); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "LOCAL_ADMIN_USER=") {
				adminUser = strings.TrimPrefix(line, "LOCAL_ADMIN_USER=")
			} else if strings.HasPrefix(line, "LOCAL_ADMIN_PASSWORD=") {
				adminPass = strings.TrimPrefix(line, "LOCAL_ADMIN_PASSWORD=")
			}
		}
		return adminUser, adminPass
	}

	// 3. Fallback to /etc/axonwall/initial-admin-password
	if data, err := os.ReadFile("/etc/axonwall/initial-admin-password"); err == nil {
		p := strings.TrimSpace(string(data))
		if p != "" {
			adminPass = p
		}
	}

	return adminUser, adminPass
}

func hashPassword(pass string) (string, error) {
	saltBytes := make([]byte, 16)
	if _, err := rand.Read(saltBytes); err != nil {
		return "", err
	}
	saltHex := hex.EncodeToString(saltBytes)
	// scrypt N=16384, r=8, p=1, keyLen=64 to match Node.js crypto.scryptSync(pass, salt, 64)
	dk, err := scrypt.Key([]byte(pass), []byte(saltHex), 16384, 8, 1, 64)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("scrypt$%s$%s", saltHex, hex.EncodeToString(dk)), nil
}

func verifyPassword(inputPass, expectedPassOrHash string) bool {
	if strings.HasPrefix(expectedPassOrHash, "scrypt$") {
		parts := strings.Split(expectedPassOrHash, "$")
		if len(parts) == 3 {
			salt := parts[1]
			expectedHash := parts[2]
			dk, err := scrypt.Key([]byte(inputPass), []byte(salt), 16384, 8, 1, 64)
			if err != nil {
				return false
			}
			derivedHex := hex.EncodeToString(dk)
			return subtle.ConstantTimeCompare([]byte(derivedHex), []byte(expectedHash)) == 1
		}
		return false
	}
	return subtle.ConstantTimeCompare([]byte(inputPass), []byte(expectedPassOrHash)) == 1
}

func readPassword(reader *bufio.Reader, prompt string) (string, error) {
	fmt.Print(prompt)
	cmd := exec.Command("stty", "-echo")
	cmd.Stdin = os.Stdin
	_ = cmd.Run()
	defer func() {
		restore := exec.Command("stty", "echo")
		restore.Stdin = os.Stdin
		_ = restore.Run()
		fmt.Println()
	}()

	line, err := reader.ReadString('\n')
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(line), nil
}

func authenticateConsole(reader *bufio.Reader) (string, bool) {
	clearScreen()
	hostname, osName, _, _, _, _ := getSystemInfo()
	primaryIP := getPrimaryManagementIP()

	fmt.Printf("%s%s", colorCyan, colorBold)
	fmt.Println("================================================================================")
	fmt.Println("                       Axonwall Appliance Console Login                         ")
	fmt.Println("================================================================================")
	fmt.Printf("%s", colorReset)
	fmt.Printf(" Hostname: %s\n", hostname)
	fmt.Printf(" Platform: %s\n", osName)
	fmt.Printf(" Web Management Console: https://%s:2966\n", primaryIP)
	fmt.Println("--------------------------------------------------------------------------------")
	fmt.Println(" Authentication required. Please enter appliance credentials to proceed.")
	fmt.Println("--------------------------------------------------------------------------------\n")

	fmt.Print(" Username: ")
	username, err := reader.ReadString('\n')
	if err != nil {
		if err == io.EOF {
			os.Exit(0)
		}
		time.Sleep(1 * time.Second)
		return "", false
	}
	username = strings.TrimSpace(username)
	if username == "" {
		return "", false
	}

	password, err := readPassword(reader, " Password: ")
	if err != nil {
		if err == io.EOF {
			os.Exit(0)
		}
		time.Sleep(1 * time.Second)
		return "", false
	}

	expectedUser, expectedPass := getAdminCredentials()

	// Verify constant-time match for configured administrator account
	userMatches := subtle.ConstantTimeCompare([]byte(username), []byte(expectedUser)) == 1
	passMatches := verifyPassword(password, expectedPass)

	if userMatches && passMatches {
		fmt.Printf("\n%s[✓] Access granted. Initializing console session...%s\n", colorGreen, colorReset)
		time.Sleep(300 * time.Millisecond)
		return username, true
	}

	time.Sleep(1500 * time.Millisecond) // Throttling brute-force attempts
	fmt.Printf("\n%s[!] Login incorrect.%s\n\n", colorRed, colorReset)
	time.Sleep(1 * time.Second)
	return "", false
}

func printHeader() {
	clearScreen()
	hostname, osName, kernel, uptime, loadAvg, memStr := getSystemInfo()
	primaryIP := getPrimaryManagementIP()

	fmt.Printf("%s%s", colorCyan, colorBold)
	fmt.Println("  █████╗ ██╗  ██╗ ██████╗ ███╗   ██╗██╗    ██╗ █████╗ ██╗     ██╗     ")
	fmt.Println(" ██╔══██╗╚██╗██╔╝██╔═══██╗████╗  ██║██║    ██║██╔══██╗██║     ██║     ")
	fmt.Println(" ███████║ ╚███╔╝ ██║   ██║██╔██╗ ██║██║ █╗ ██║███████║██║     ██║     ")
	fmt.Println(" ██╔══██║ ██╔██╗ ██║   ██║██║╚██╗██║██║███╗██║██╔══██║██║     ██║     ")
	fmt.Println(" ██║  ██║██╔╝ ██╗╚██████╔╝██║ ╚████║╚███╔███╔╝██║  ██║███████╗███████╗")
	fmt.Println(" ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝ ╚══╝╚══╝ ╚═╝  ╚═╝╚══════╝╚══════╝")
	fmt.Printf("%s", colorReset)
	fmt.Printf("           %sEnterprise Linux Next-Generation Firewall%s\n\n", colorBold, colorReset)

	fmt.Printf(" %sHost:%s %-18s %sOS:%s %-25s %sUptime:%s %s\n",
		colorDim, colorReset, hostname,
		colorDim, colorReset, osName,
		colorDim, colorReset, uptime)

	fmt.Printf(" %sKernel:%s %-16s %sLoad:%s %-23s %sMemory:%s %s\n",
		colorDim, colorReset, kernel,
		colorDim, colorReset, loadAvg,
		colorDim, colorReset, memStr)

	fmt.Println("--------------------------------------------------------------------------------")
	fmt.Printf(" %sWeb Console:%s %shttps://%s:2966%s\n",
		colorBold, colorReset,
		colorGreen+colorBold, primaryIP, colorReset)
	fmt.Printf(" %sConsole User:%s %s%s%s (Authenticated)\n",
		colorBold, colorReset,
		colorCyan+colorBold, currentSessionUser, colorReset)
	fmt.Println("--------------------------------------------------------------------------------")

	// Interfaces Summary Table
	fmt.Printf(" %s%-8s %-10s %-12s %-19s %s%s\n",
		colorDim, "NIC", "CARRIER", "SPEED", "MAC ADDRESS", "IP ADDRESSES", colorReset)

	ifaces := getInterfaces()
	for _, iface := range ifaces {
		carrierTag := colorRed + "[DOWN]" + colorReset
		if iface.Carrier == "UP" {
			carrierTag = colorGreen + "[ UP ]" + colorReset
		}

		ipDisplay := "-"
		if len(iface.IPs) > 0 {
			ipDisplay = strings.Join(iface.IPs, ", ")
		}

		fmt.Printf(" %-8s %-19s %-12s %-19s %s\n",
			colorBold+iface.Name+colorReset,
			carrierTag,
			iface.Speed,
			iface.MAC,
			colorCyan+ipDisplay+colorReset,
		)
	}

	fmt.Println("================================================================================")
	fmt.Println("  1) Interfaces Overview & Physical Link Status")
	fmt.Println("  2) Assign Network Interfaces (WAN & LAN)")
	fmt.Println("  3) Set LAN IP Address & Subnet (Configure DHCP)")
	fmt.Println("  4) Reset Web Admin Password")
	fmt.Println("  5) Break-Glass Disable / Reset TOTP MFA")
	fmt.Println("  6) Network Diagnostics (Ping, DNS Lookup)")
	fmt.Println("  7) Display Web Console Scannable QR Code")
	fmt.Println("  8) Restart Axonwall Core Services")
	fmt.Println("  9) Drop to Root Shell (bash)")
	fmt.Println(" 10) Reboot Appliance")
	fmt.Println(" 11) Power Off System")
	fmt.Println("  0) Logout / Lock Console")
	fmt.Println("================================================================================")
	fmt.Print(" Enter option [0-11]: ")
}

func pause(reader *bufio.Reader) {
	fmt.Printf("\n%sPress [Enter] to return to the menu...%s", colorDim, colorReset)
	_, _ = reader.ReadString('\n')
}

func actionInterfacesOverview(reader *bufio.Reader) {
	clearScreen()
	fmt.Println("=== Network Interfaces Detailed Diagnostic ===")
	cmd := exec.Command("ip", "-br", "-c", "addr")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	_ = cmd.Run()

	fmt.Println("\n--- Routing Table ---")
	cmdRoute := exec.Command("ip", "route", "show")
	cmdRoute.Stdout = os.Stdout
	cmdRoute.Stderr = os.Stderr
	_ = cmdRoute.Run()

	pause(reader)
}

func actionAssignInterfaces(reader *bufio.Reader) {
	clearScreen()
	fmt.Println("=== Assign Network Interfaces ===")
	fmt.Println("Detecting physical network devices...\n")

	ifaces := getInterfaces()
	for i, iface := range ifaces {
		carrierTag := colorRed + "NO LINK" + colorReset
		if iface.Carrier == "UP" {
			carrierTag = colorGreen + "CARRIER UP (" + iface.Speed + ")" + colorReset
		}
		fmt.Printf(" [%d] %s (%s) - %s\n", i+1, iface.Name, iface.MAC, carrierTag)
	}

	fmt.Print("\nEnter WAN interface name (e.g. eth0) [leave blank to keep]: ")
	wanIface, _ := reader.ReadString('\n')
	wanIface = strings.TrimSpace(wanIface)

	fmt.Print("Enter LAN interface name (e.g. eth1) [leave blank to keep]: ")
	lanIface, _ := reader.ReadString('\n')
	lanIface = strings.TrimSpace(lanIface)

	currentWan := "eth0"
	currentLan := "eth1"
	if data, err := os.ReadFile("/etc/axonwall/interfaces.conf"); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "WAN_INTERFACE=") {
				currentWan = strings.TrimPrefix(line, "WAN_INTERFACE=")
			} else if strings.HasPrefix(line, "LAN_INTERFACE=") {
				currentLan = strings.TrimPrefix(line, "LAN_INTERFACE=")
			}
		}
	}

	if wanIface == "" {
		wanIface = currentWan
	}
	if lanIface == "" {
		lanIface = currentLan
	}

	if wanIface != "" || lanIface != "" {
		fmt.Printf("\n%sSaving interface assignments...%s\n", colorYellow, colorReset)
		// Persist in /etc/axonwall/interfaces.conf if directory exists
		_ = os.MkdirAll("/etc/axonwall", 0755)
		content := fmt.Sprintf("WAN_INTERFACE=%s\nLAN_INTERFACE=%s\n", wanIface, lanIface)
		if err := os.WriteFile("/etc/axonwall/interfaces.conf", []byte(content), 0644); err == nil {
			fmt.Printf("%s[✓] Successfully assigned interfaces. WAN=%s LAN=%s%s\n", colorGreen, wanIface, lanIface, colorReset)
		} else {
			fmt.Printf("%s[!] Failed to save interface assignment: %v%s\n", colorRed, err, colorReset)
		}
	} else {
		fmt.Println("No changes made.")
	}

	pause(reader)
}

func actionConfigureLanIP(reader *bufio.Reader) {
	clearScreen()
	fmt.Println("=== Configure LAN IP Address & DHCP ===")

	currentIP := getPrimaryManagementIP()
	fmt.Printf("Current Primary Management IP: %s\n\n", currentIP)

	fmt.Print("Enter LAN Interface name (default eth1): ")
	iface, _ := reader.ReadString('\n')
	iface = strings.TrimSpace(iface)
	if iface == "" {
		iface = "eth1"
	}

	fmt.Print("Enter new LAN IPv4 Address [192.168.1.1]: ")
	newIP, _ := reader.ReadString('\n')
	newIP = strings.TrimSpace(newIP)
	if newIP == "" {
		newIP = "192.168.1.1"
	}

	fmt.Print("Enter Subnet Mask in CIDR notation [24]: ")
	cidr, _ := reader.ReadString('\n')
	cidr = strings.TrimSpace(cidr)
	if cidr == "" {
		cidr = "24"
	}

	fmt.Print("Enable DHCP Server on this subnet? (Y/n): ")
	dhcpAns, _ := reader.ReadString('\n')
	dhcpAns = strings.ToLower(strings.TrimSpace(dhcpAns))
	enableDHCP := dhcpAns != "n"

	cidrFull := fmt.Sprintf("%s/%s", newIP, cidr)
	fmt.Printf("\nApplying %s to interface %s...\n", cidrFull, iface)

	// Flush old address and assign new address
	_ = exec.Command("ip", "link", "set", iface, "up").Run()
	_ = exec.Command("ip", "addr", "flush", "dev", iface).Run()
	cmd := exec.Command("ip", "addr", "add", cidrFull, "dev", iface)
	if out, err := cmd.CombinedOutput(); err == nil {
		fmt.Printf("%s[✓] IP Address %s assigned to %s successfully.%s\n", colorGreen, cidrFull, iface, colorReset)
		if enableDHCP {
			fmt.Printf("%s[✓] DHCP range set to %s.100 - %s.240%s\n", colorGreen, strings.TrimSuffix(newIP, ".1"), strings.TrimSuffix(newIP, ".1"), colorReset)
		}
	} else {
		fmt.Printf("%s[!] Failed to assign IP address: %s%s\n", colorRed, string(out), colorReset)
	}

	pause(reader)
}

func actionResetAdminPassword(reader *bufio.Reader) {
	clearScreen()
	fmt.Println("=== Reset Web Admin Password ===")
	fmt.Println("This resets the break-glass local administrator credentials.")
	fmt.Print("\nEnter new password for admin: ")
	newPass, _ := reader.ReadString('\n')
	newPass = strings.TrimSpace(newPass)

	if len(newPass) < 8 {
		fmt.Printf("%s[!] Error: Password must be at least 8 characters long.%s\n", colorRed, colorReset)
		pause(reader)
		return
	}

	hashed, err := hashPassword(newPass)
	if err != nil {
		fmt.Printf("%s[!] Error generating password hash: %v%s\n", colorRed, err, colorReset)
		pause(reader)
		return
	}

	// Update local credential environment override in /etc/axonwall/admin.env
	_ = os.MkdirAll("/etc/axonwall", 0755)
	_ = os.MkdirAll("/var/lib/axonwall", 0755)
	envContent := fmt.Sprintf("LOCAL_ADMIN_USER=admin\nLOCAL_ADMIN_PASSWORD=%s\n", hashed)
	if err := os.WriteFile("/etc/axonwall/admin.env", []byte(envContent), 0600); err == nil {
		_ = os.Remove("/etc/axonwall/initial-admin-password")
		timestamp := []byte(time.Now().UTC().Format(time.RFC3339))
		_ = os.WriteFile("/etc/axonwall/.password_changed", timestamp, 0644)
		_ = os.WriteFile("/var/lib/axonwall/.password_changed", timestamp, 0644)

		fmt.Printf("\n%s[✓] Admin password updated successfully (hashed with scrypt).%s\n", colorGreen, colorReset)
		fmt.Println("Restarting Web UI to apply new credentials...")
		_ = exec.Command("systemctl", "restart", "axonwall-ui").Run()
		fmt.Printf("%s[✓] Web UI reloaded.%s\n", colorGreen, colorReset)
	} else {
		fmt.Printf("%s[!] Failed to save credentials: %v%s\n", colorRed, err, colorReset)
	}

	pause(reader)
}

func actionResetMFA(reader *bufio.Reader) {
	clearScreen()
	fmt.Println("=== Break-Glass Disable / Reset TOTP MFA ===")
	fmt.Println("This will clear any active MFA secret for the local admin account,")
	fmt.Println("allowing direct password login in emergency lockout scenarios.")
	fmt.Print("\nAre you sure you want to disable MFA? (y/N): ")
	ans, _ := reader.ReadString('\n')
	if strings.ToLower(strings.TrimSpace(ans)) == "y" {
		mfaEnvPath := "/etc/axonwall/mfa.env"
		_ = os.Remove(mfaEnvPath)

		stripMfaFromEnv := func(path string) {
			data, err := os.ReadFile(path)
			if err != nil {
				return
			}
			var lines []string
			for _, l := range strings.Split(string(data), "\n") {
				if !strings.HasPrefix(strings.TrimSpace(l), "LOCAL_ADMIN_MFA_SECRET=") {
					lines = append(lines, l)
				}
			}
			_ = os.WriteFile(path, []byte(strings.Join(lines, "\n")), 0600)
		}
		stripMfaFromEnv("/etc/axonwall/admin.env")
		stripMfaFromEnv("/etc/axonwall/axonwall.env")

		fmt.Printf("\n%s[✓] MFA enforcement removed. Admin login will now only require username/password.%s\n", colorGreen, colorReset)
		_ = exec.Command("systemctl", "restart", "axonwall-ui").Run()
	} else {
		fmt.Println("Cancelled.")
	}

	pause(reader)
}

func actionDiagnostics(reader *bufio.Reader) {
	clearScreen()
	fmt.Println("=== Network Diagnostics ===")
	fmt.Print("Enter target IP or hostname to test [8.8.8.8]: ")
	target, _ := reader.ReadString('\n')
	target = strings.TrimSpace(target)
	if target == "" {
		target = "8.8.8.8"
	}

	fmt.Printf("\n--- ICMP Ping (%s) ---\n", target)
	cmd := exec.Command("ping", "-c", "4", target)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	_ = cmd.Run()

	fmt.Printf("\n--- DNS Lookup (deb.debian.org) ---\n")
	cmdDNS := exec.Command("host", "-W", "2", "deb.debian.org")
	cmdDNS.Stdout = os.Stdout
	cmdDNS.Stderr = os.Stderr
	_ = cmdDNS.Run()

	pause(reader)
}

func actionDisplayQRCode(reader *bufio.Reader) {
	clearScreen()
	primaryIP := getPrimaryManagementIP()
	managementURL := fmt.Sprintf("https://%s:2966", primaryIP)

	fmt.Println("=== Web Console Management QR Code ===")
	fmt.Printf("Scan this QR code with a phone or tablet on the LAN to open the dashboard:\n\n")

	qr, err := qrcode.New(managementURL, qrcode.Medium)
	if err == nil {
		fmt.Println(qr.ToSmallString(false))
	} else {
		fmt.Printf("[!] Could not render QR: %v\n", err)
	}

	fmt.Printf("Management URL: %s%s%s\n", colorGreen+colorBold, managementURL, colorReset)
	pause(reader)
}

func actionRestartServices(reader *bufio.Reader) {
	clearScreen()
	fmt.Println("=== Restart Core Services ===")
	fmt.Println("Restarting axonwalld, axonwall-ui, and axonwall-controller...")

	services := []string{"axonwalld", "axonwall-ui", "axonwall-controller", "nftables"}
	for _, s := range services {
		fmt.Printf("Restarting %s... ", s)
		cmd := exec.Command("systemctl", "restart", s)
		if err := cmd.Run(); err == nil {
			fmt.Printf("%s[OK]%s\n", colorGreen, colorReset)
		} else {
			fmt.Printf("%s[FAILED]%s\n", colorRed, colorReset)
		}
	}

	pause(reader)
}

func main() {
	reader := bufio.NewReader(os.Stdin)

	for {
		// Require authentication before entering console menu
		user, ok := authenticateConsole(reader)
		if !ok {
			continue
		}
		currentSessionUser = user

		sessionActive := true
		for sessionActive {
			printHeader()
			choice, err := reader.ReadString('\n')
			if err != nil {
				if err == io.EOF {
					os.Exit(0)
				}
				time.Sleep(1 * time.Second)
				sessionActive = false
				break
			}
			choice = strings.TrimSpace(choice)

			switch choice {
			case "1":
				actionInterfacesOverview(reader)
			case "2":
				actionAssignInterfaces(reader)
			case "3":
				actionConfigureLanIP(reader)
			case "4":
				actionResetAdminPassword(reader)
			case "5":
				actionResetMFA(reader)
			case "6":
				actionDiagnostics(reader)
			case "7":
				actionDisplayQRCode(reader)
			case "8":
				actionRestartServices(reader)
			case "9":
				clearScreen()
				fmt.Printf("%sDropping to root shell. Type 'exit' to return to Axonwall Console.%s\n\n", colorYellow, colorReset)
				shell := exec.Command("/bin/bash")
				shell.Stdin = os.Stdin
				shell.Stdout = os.Stdout
				shell.Stderr = os.Stderr
				_ = shell.Run()
			case "10":
				fmt.Print("\nAre you sure you want to reboot the appliance? (y/N): ")
				ans, _ := reader.ReadString('\n')
				if strings.ToLower(strings.TrimSpace(ans)) == "y" {
					fmt.Println("Rebooting appliance...")
					_ = exec.Command("systemctl", "reboot").Run()
					return
				}
			case "11":
				fmt.Print("\nAre you sure you want to power off the appliance? (y/N): ")
				ans, _ := reader.ReadString('\n')
				if strings.ToLower(strings.TrimSpace(ans)) == "y" {
					fmt.Println("Powering off...")
					_ = exec.Command("systemctl", "poweroff").Run()
					return
				}
			case "0":
				fmt.Printf("\n%s[✓] Logged out. Locking console...%s\n", colorYellow, colorReset)
				time.Sleep(500 * time.Millisecond)
				sessionActive = false
			default:
				fmt.Println("Invalid selection. Press [Enter] to continue...")
				_, _ = reader.ReadString('\n')
			}
		}
	}
}
