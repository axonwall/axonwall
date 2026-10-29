package engine

import (
	"encoding/binary"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"
)

var nlSeq atomic.Uint32

// EdgeNetworkEngine configures network interfaces, IP addresses, and kernel routes
// directly via Linux Netlink sockets (NETLINK_ROUTE) and sysfs/ioctl without requiring
// external userland binaries (/sbin/ip or /sbin/ifconfig).
type EdgeNetworkEngine struct {
	SysClassNetDir string
}

func NewEdgeNetworkEngine() *EdgeNetworkEngine {
	return &EdgeNetworkEngine{
		SysClassNetDir: "/sys/class/net",
	}
}

// ValidateInterfaceSpec checks that an EdgeInterfaceSpec is free of injection or malformed values.
func ValidateInterfaceSpec(spec EdgeInterfaceSpec) error {
	dev := strings.TrimSpace(spec.Device)
	if dev == "" || !validRadioRegex.MatchString(dev) || strings.HasPrefix(dev, "-") || strings.Contains(dev, "..") {
		return fmt.Errorf("invalid interface device name: %q", spec.Device)
	}
	if spec.MTU != 0 && (spec.MTU < 576 || spec.MTU > 9216) {
		return fmt.Errorf("invalid MTU %d for %s (must be 576..9216)", spec.MTU, dev)
	}
	addr := strings.TrimSpace(spec.Address)
	if addr != "" && !strings.EqualFold(addr, "dhcp") {
		if _, _, err := net.ParseCIDR(addr); err != nil {
			return fmt.Errorf("invalid CIDR address %q for %s: %w", addr, dev, err)
		}
	}
	gw := strings.TrimSpace(spec.Gateway)
	if gw != "" {
		if net.ParseIP(gw) == nil {
			return fmt.Errorf("invalid gateway IP %q for %s", gw, dev)
		}
	}
	return nil
}

// ValidateRouteSpec checks that an EdgeRouteSpec has a valid destination CIDR (or "default") and gateway IP.
func ValidateRouteSpec(route EdgeRouteSpec) error {
	dst := strings.TrimSpace(route.Destination)
	if dst == "" {
		return fmt.Errorf("route destination cannot be empty")
	}
	if !strings.EqualFold(dst, "default") {
		if _, _, err := net.ParseCIDR(dst); err != nil {
			return fmt.Errorf("invalid route destination CIDR %q: %w", dst, err)
		}
	}
	gw := strings.TrimSpace(route.Gateway)
	if gw == "" || net.ParseIP(gw) == nil {
		return fmt.Errorf("invalid route gateway IP %q", route.Gateway)
	}
	dev := strings.TrimSpace(route.Device)
	if dev != "" && (!validRadioRegex.MatchString(dev) || strings.HasPrefix(dev, "-") || strings.Contains(dev, "..")) {
		return fmt.Errorf("invalid route device %q", route.Device)
	}
	return nil
}

// BringUpLoopback configures the kernel loopback interface (lo -> 127.0.0.1/8 UP) via native Netlink/ioctl.
func (e *EdgeNetworkEngine) BringUpLoopback() error {
	loSpec := EdgeInterfaceSpec{
		Name:    "loopback",
		Device:  "lo",
		Address: "127.0.0.1/8",
		Enabled: true,
	}
	return e.ConfigureInterface(loSpec)
}

// SetLinkUp toggles an interface's administrative IFF_UP flag via ioctl SIOCSIFFLAGS.
func (e *EdgeNetworkEngine) SetLinkUp(dev string, up bool) error {
	dev = strings.TrimSpace(dev)
	if dev == "" || !validRadioRegex.MatchString(dev) {
		return fmt.Errorf("invalid interface name %q", dev)
	}
	return setInterfaceFlags(dev, up)
}

// ConfigureInterface applies link state, MTU, CIDR address, and optional default gateway to a network device.
func (e *EdgeNetworkEngine) ConfigureInterface(spec EdgeInterfaceSpec) error {
	if err := ValidateInterfaceSpec(spec); err != nil {
		return err
	}

	dev := strings.TrimSpace(spec.Device)

	// 1. Set MTU via /sys/class/net/<dev>/mtu if specified
	if spec.MTU > 0 {
		mtuPath := filepath.Join(e.SysClassNetDir, dev, "mtu")
		_ = os.WriteFile(mtuPath, []byte(strconv.Itoa(spec.MTU)+"\n"), 0644)
	}

	// 2. Set link UP or DOWN via ioctl SIOCSIFFLAGS
	if err := setInterfaceFlags(dev, spec.Enabled); err != nil {
		slog.Debug("Native ioctl link state note", "device", dev, "enabled", spec.Enabled, "note", err)
	}

	if !spec.Enabled {
		return nil
	}

	// 2b. Apply per-interface IPv6 mode (e.g. "disabled", "auto", "delegated", "static")
	if strings.TrimSpace(spec.IPv6Mode) != "" {
		_ = ApplyInterfaceIPv6Mode("/proc/sys", dev, spec.IPv6Mode)
	}

	// 3. Assign CIDR address via native Netlink RTM_NEWADDR (or pure-Go DHCPv4 DORA handshake)
	addr := strings.TrimSpace(spec.Address)
	gw := strings.TrimSpace(spec.Gateway)
	if strings.EqualFold(addr, "dhcp") {
		lease, dhcpErr := AcquireDHCPv4Lease(dev, 4*time.Second)
		if dhcpErr != nil {
			return fmt.Errorf("DHCPv4 lease acquisition failed on %s: %w", dev, dhcpErr)
		}
		addr = lease.CIDR
		if gw == "" && lease.Gateway != "" {
			gw = lease.Gateway
		}
	}

	if addr != "" {
		if err := addInterfaceAddressNetlink(dev, addr); err != nil {
			// Fallback to /sbin/ip if available
			if ipBin, lookErr := exec.LookPath("ip"); lookErr == nil {
				_ = exec.Command(ipBin, "addr", "replace", addr, "dev", dev).Run()
			} else {
				return fmt.Errorf("netlink address assignment failed on %s (%s): %w", dev, addr, err)
			}
		}
	}

	// 3b. Assign static/ULA IPv6 address if configured and IPv6 is not disabled on the interface
	v6Addr := strings.TrimSpace(spec.IPv6Address)
	if v6Addr != "" && !strings.EqualFold(strings.TrimSpace(spec.IPv6Mode), "disabled") {
		_ = addInterfaceAddressNetlink(dev, v6Addr)
	}

	// 4. Configure default route if Gateway is specified
	if gw != "" {
		route := EdgeRouteSpec{
			Destination: "default",
			Gateway:     gw,
			Device:      dev,
		}
		if err := e.AddRoute(route); err != nil {
			return err
		}
	}

	slog.Info("Configured edge network interface", "name", spec.Name, "device", dev, "address", addr, "gateway", gw)
	return nil
}

// AddRoute installs or replaces a static or default route in the kernel via native Netlink RTM_NEWROUTE.
func (e *EdgeNetworkEngine) AddRoute(route EdgeRouteSpec) error {
	if err := ValidateRouteSpec(route); err != nil {
		return err
	}

	if err := addRouteNetlink(route); err != nil {
		if ipBin, lookErr := exec.LookPath("ip"); lookErr == nil {
			args := []string{"route", "replace", route.Destination, "via", route.Gateway}
			if route.Device != "" {
				args = append(args, "dev", route.Device)
			}
			if out, cmdErr := exec.Command(ipBin, args...).CombinedOutput(); cmdErr != nil {
				return fmt.Errorf("failed to add route %s via %s: %v (%s)", route.Destination, route.Gateway, cmdErr, string(out))
			}
			return nil
		}
		return fmt.Errorf("netlink route add failed (%s via %s): %w", route.Destination, route.Gateway, err)
	}

	slog.Info("Installed edge kernel route", "destination", route.Destination, "gateway", route.Gateway, "device", route.Device)
	return nil
}

// ifreqFlags represents the C struct ifreq for SIOCGIFFLAGS / SIOCSIFFLAGS.
type ifreqFlags struct {
	Name  [syscall.IFNAMSIZ]byte
	Flags uint16
	Pad   [22]byte
}

func setInterfaceFlags(dev string, up bool) error {
	if len(dev) >= syscall.IFNAMSIZ {
		return fmt.Errorf("device name too long: %s", dev)
	}
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM|syscall.SOCK_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer syscall.Close(fd)

	var ifr ifreqFlags
	copy(ifr.Name[:], dev)

	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), uintptr(syscall.SIOCGIFFLAGS), uintptr(unsafe.Pointer(&ifr)))
	if errno != 0 {
		return errno
	}

	if up {
		ifr.Flags |= uint16(syscall.IFF_UP | syscall.IFF_RUNNING)
	} else {
		ifr.Flags &^= uint16(syscall.IFF_UP)
	}

	_, _, errno = syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), uintptr(syscall.SIOCSIFFLAGS), uintptr(unsafe.Pointer(&ifr)))
	if errno != 0 {
		return errno
	}
	return nil
}

func addRouteAttr(buf []byte, attrType uint16, payload []byte) []byte {
	rtaLen := uint16(4 + len(payload))
	alignedLen := (int(rtaLen) + 3) & ^3
	attr := make([]byte, alignedLen)
	binary.NativeEndian.PutUint16(attr[0:2], rtaLen)
	binary.NativeEndian.PutUint16(attr[2:4], attrType)
	copy(attr[4:], payload)
	return append(buf, attr...)
}

func addInterfaceAddressNetlink(dev, cidr string) error {
	iface, err := net.InterfaceByName(dev)
	if err != nil {
		return err
	}
	ip, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return err
	}
	ones, _ := ipNet.Mask.Size()

	family := uint8(syscall.AF_INET)
	ipBytes := ip.To4()
	if ipBytes == nil {
		family = uint8(syscall.AF_INET6)
		ipBytes = ip.To16()
	}

	// Header (16 bytes) + ifaddrmsg (8 bytes)
	msg := make([]byte, 24)
	msg[16] = family
	msg[17] = uint8(ones)
	msg[18] = 0 // flags
	msg[19] = uint8(syscall.RT_SCOPE_UNIVERSE)
	binary.NativeEndian.PutUint32(msg[20:24], uint32(iface.Index))

	msg = addRouteAttr(msg, syscall.IFA_LOCAL, ipBytes)
	msg = addRouteAttr(msg, syscall.IFA_ADDRESS, ipBytes)

	binary.NativeEndian.PutUint32(msg[0:4], uint32(len(msg)))
	binary.NativeEndian.PutUint16(msg[4:6], uint16(syscall.RTM_NEWADDR))
	binary.NativeEndian.PutUint16(msg[6:8], uint16(syscall.NLM_F_REQUEST|syscall.NLM_F_CREATE|syscall.NLM_F_REPLACE|syscall.NLM_F_ACK))
	binary.NativeEndian.PutUint32(msg[8:12], nlSeq.Add(1))
	binary.NativeEndian.PutUint32(msg[12:16], uint32(os.Getpid()))

	return sendNetlinkRouteMessage(msg)
}

func addRouteNetlink(route EdgeRouteSpec) error {
	gwIP := net.ParseIP(strings.TrimSpace(route.Gateway))
	if gwIP == nil {
		return fmt.Errorf("invalid gateway IP: %s", route.Gateway)
	}

	family := uint8(syscall.AF_INET)
	gwBytes := gwIP.To4()
	if gwBytes == nil {
		family = uint8(syscall.AF_INET6)
		gwBytes = gwIP.To16()
	}

	var dstBytes []byte
	dstPrefixLen := uint8(0)
	dst := strings.TrimSpace(route.Destination)
	if !strings.EqualFold(dst, "default") {
		_, ipNet, err := net.ParseCIDR(dst)
		if err != nil {
			return err
		}
		ones, _ := ipNet.Mask.Size()
		dstPrefixLen = uint8(ones)
		if family == uint8(syscall.AF_INET) {
			dstBytes = ipNet.IP.To4()
		} else {
			dstBytes = ipNet.IP.To16()
		}
	}

	// nlmsghdr (16 bytes) + rtmsg (12 bytes)
	msg := make([]byte, 28)
	msg[16] = family
	msg[17] = dstPrefixLen
	msg[18] = 0 // src_len
	msg[19] = 0 // tos
	msg[20] = syscall.RT_TABLE_MAIN
	msg[21] = syscall.RTPROT_STATIC
	msg[22] = syscall.RT_SCOPE_UNIVERSE
	msg[23] = syscall.RTN_UNICAST

	if len(dstBytes) > 0 {
		msg = addRouteAttr(msg, syscall.RTA_DST, dstBytes)
	}
	msg = addRouteAttr(msg, syscall.RTA_GATEWAY, gwBytes)

	if route.Device != "" {
		if iface, err := net.InterfaceByName(strings.TrimSpace(route.Device)); err == nil {
			oif := make([]byte, 4)
			binary.NativeEndian.PutUint32(oif, uint32(iface.Index))
			msg = addRouteAttr(msg, syscall.RTA_OIF, oif)
		}
	}

	binary.NativeEndian.PutUint32(msg[0:4], uint32(len(msg)))
	binary.NativeEndian.PutUint16(msg[4:6], uint16(syscall.RTM_NEWROUTE))
	binary.NativeEndian.PutUint16(msg[6:8], uint16(syscall.NLM_F_REQUEST|syscall.NLM_F_CREATE|syscall.NLM_F_REPLACE|syscall.NLM_F_ACK))
	binary.NativeEndian.PutUint32(msg[8:12], nlSeq.Add(1))
	binary.NativeEndian.PutUint32(msg[12:16], uint32(os.Getpid()))

	return sendNetlinkRouteMessage(msg)
}

func sendNetlinkRouteMessage(msg []byte) error {
	fd, err := syscall.Socket(syscall.AF_NETLINK, syscall.SOCK_RAW|syscall.SOCK_CLOEXEC, syscall.NETLINK_ROUTE)
	if err != nil {
		return err
	}
	defer syscall.Close(fd)

	sa := &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK}
	if err := syscall.Bind(fd, sa); err != nil {
		return err
	}
	if err := syscall.Sendto(fd, msg, 0, sa); err != nil {
		return err
	}

	reply := make([]byte, 4096)
	n, _, err := syscall.Recvfrom(fd, reply, 0)
	if err != nil {
		return err
	}
	if n >= 20 {
		msgType := binary.NativeEndian.Uint16(reply[4:6])
		if msgType == syscall.NLMSG_ERROR {
			errCode := int32(binary.NativeEndian.Uint32(reply[16:20]))
			if errCode != 0 {
				return syscall.Errno(-errCode)
			}
		}
	}
	return nil
}
