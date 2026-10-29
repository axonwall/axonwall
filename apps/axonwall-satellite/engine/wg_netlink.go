package engine

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"net"
	"strconv"
	"strings"
	"syscall"
)

// Generic Netlink & WireGuard kernel ABI constants (from <linux/genetlink.h> and <linux/wireguard.h>)
const (
	genlIDCtrl        = 0x10
	ctrlCmdGetFamily  = 3
	ctrlAttrFamilyID  = 1
	ctrlAttrFamilyName = 2

	wgGenlName    = "wireguard"
	wgGenlVersion = 1
	wgKeyLen      = 32

	wgCmdGetDevice = 0
	wgCmdSetDevice = 1

	wgDeviceFReplacePeers = 1 << 0

	wgDeviceAIfindex    = 1
	wgDeviceAIfname     = 2
	wgDeviceAPrivateKey = 3
	wgDeviceAPublicKey  = 4
	wgDeviceAFlags      = 5
	wgDeviceAListenPort = 6
	wgDeviceAFwmark     = 7
	wgDeviceAPeers      = 8

	wgPeerFReplaceAllowedIPs = 1 << 1

	wgPeerAPublicKey           = 1
	wgPeerAPresharedKey        = 2
	wgPeerAFlags               = 3
	wgPeerAEndpoint            = 4
	wgPeerAPersistentKeepalive = 5
	wgPeerAAllowedIPs          = 9

	wgAllowedIPAFamily   = 1
	wgAllowedIPAIPAddr   = 2
	wgAllowedIPACIDRMask = 3

	// RTNL link creation attributes (from <linux/if_link.h>)
	iflaIfname   = 3
	iflaLinkinfo = 18
	iflaInfoKind = 1
)

// DecodeWireGuardKey decodes a 44-character base64 WireGuard key into its 32-byte raw representation.
func DecodeWireGuardKey(b64 string) ([wgKeyLen]byte, error) {
	var key [wgKeyLen]byte
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(b64))
	if err != nil {
		return key, fmt.Errorf("invalid base64 WireGuard key: %w", err)
	}
	if len(raw) != wgKeyLen {
		return key, fmt.Errorf("invalid WireGuard key length: got %d bytes, want %d", len(raw), wgKeyLen)
	}
	copy(key[:], raw)
	return key, nil
}

// BuildWireGuardSetDeviceAttrs serializes the WG_CMD_SET_DEVICE netlink attributes for unit testing
// and kernel Generic Netlink submission.
func BuildWireGuardSetDeviceAttrs(cfg WireGuardConfig) ([]byte, error) {
	privKey, err := DecodeWireGuardKey(cfg.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("privateKey: %w", err)
	}

	listenPort := uint16(cfg.ListenPort)
	if listenPort == 0 {
		listenPort = 51820
	}

	var attrs bytes.Buffer
	attrs.Write(nlAttrStr(wgDeviceAIfname, cfg.InterfaceName))
	attrs.Write(nlAttrU32LE(wgDeviceAFlags, wgDeviceFReplacePeers))
	attrs.Write(nlAttr(wgDeviceAPrivateKey, privKey[:]))
	attrs.Write(nlAttrU16LE(wgDeviceAListenPort, listenPort))

	if len(cfg.Peers) > 0 {
		var peersBuf bytes.Buffer
		for idx, p := range cfg.Peers {
			pubKey, err := DecodeWireGuardKey(p.PublicKey)
			if err != nil {
				return nil, fmt.Errorf("peer[%d] publicKey: %w", idx, err)
			}

			var peerAttrs [][]byte
			peerAttrs = append(peerAttrs,
				nlAttr(wgPeerAPublicKey, pubKey[:]),
				nlAttrU32LE(wgPeerAFlags, wgPeerFReplaceAllowedIPs),
			)

			keepAlive := p.KeepAliveSec
			if keepAlive <= 0 {
				keepAlive = 25
			}
			peerAttrs = append(peerAttrs, nlAttrU16LE(wgPeerAPersistentKeepalive, uint16(keepAlive)))

			if strings.TrimSpace(p.Endpoint) != "" {
				epBytes, err := encodeSockaddrEndpoint(strings.TrimSpace(p.Endpoint))
				if err != nil {
					return nil, fmt.Errorf("peer[%d] endpoint %q: %w", idx, p.Endpoint, err)
				}
				peerAttrs = append(peerAttrs, nlAttr(wgPeerAEndpoint, epBytes))
			}

			if strings.TrimSpace(p.AllowedIPs) != "" {
				var allowedBuf bytes.Buffer
				for i, cidrStr := range strings.Split(p.AllowedIPs, ",") {
					cidrStr = strings.TrimSpace(cidrStr)
					if cidrStr == "" {
						continue
					}
					if !strings.Contains(cidrStr, "/") {
						if ip := net.ParseIP(cidrStr); ip != nil && ip.To4() != nil {
							cidrStr += "/32"
						} else {
							cidrStr += "/128"
						}
					}
					_, ipNet, err := net.ParseCIDR(cidrStr)
					if err != nil || ipNet == nil {
						return nil, fmt.Errorf("peer[%d] allowedIps %q: %w", idx, cidrStr, err)
					}
					ones, _ := ipNet.Mask.Size()
					var fam uint16 = syscall.AF_INET
					ipBytes := ipNet.IP.To4()
					if ipBytes == nil {
						fam = syscall.AF_INET6
						ipBytes = ipNet.IP.To16()
					}
					allowedBuf.Write(nlAttrNested(uint16(i),
						nlAttrU16LE(wgAllowedIPAFamily, fam),
						nlAttr(wgAllowedIPAIPAddr, ipBytes),
						nlAttr(wgAllowedIPACIDRMask, []byte{uint8(ones)}),
					))
				}
				peerAttrs = append(peerAttrs, nlAttr(wgPeerAAllowedIPs|nlaFNested, allowedBuf.Bytes()))
			}

			peersBuf.Write(nlAttrNested(uint16(idx), peerAttrs...))
		}
		attrs.Write(nlAttr(wgDeviceAPeers|nlaFNested, peersBuf.Bytes()))
	}

	return attrs.Bytes(), nil
}

func nlAttrU16LE(typ uint16, v uint16) []byte {
	var b [2]byte
	binary.NativeEndian.PutUint16(b[:], v)
	return nlAttr(typ, b[:])
}

func nlAttrU32LE(typ uint16, v uint32) []byte {
	var b [4]byte
	binary.NativeEndian.PutUint32(b[:], v)
	return nlAttr(typ, b[:])
}

func encodeSockaddrEndpoint(ep string) ([]byte, error) {
	host, portStr, err := net.SplitHostPort(ep)
	if err != nil {
		return nil, err
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 1 || port > 65535 {
		return nil, fmt.Errorf("invalid endpoint port %q", portStr)
	}
	ip := net.ParseIP(host)
	if ip == nil {
		ips, lookupErr := net.LookupIP(host)
		if lookupErr != nil || len(ips) == 0 {
			return nil, fmt.Errorf("unresolvable endpoint host %q", host)
		}
		ip = ips[0]
	}

	if ip4 := ip.To4(); ip4 != nil {
		// struct sockaddr_in (16 bytes): family(2), port(2 BE), addr(4), zero(8)
		buf := make([]byte, 16)
		binary.NativeEndian.PutUint16(buf[0:2], syscall.AF_INET)
		binary.BigEndian.PutUint16(buf[2:4], uint16(port))
		copy(buf[4:8], ip4)
		return buf, nil
	}

	// struct sockaddr_in6 (28 bytes): family(2), port(2 BE), flowinfo(4), addr(16), scope_id(4)
	buf := make([]byte, 28)
	binary.NativeEndian.PutUint16(buf[0:2], syscall.AF_INET6)
	binary.BigEndian.PutUint16(buf[2:4], uint16(port))
	copy(buf[8:24], ip.To16())
	return buf, nil
}

// ConfigureWireGuardNetlink creates the WireGuard link via RTNETLINK (IFLA_INFO_KIND="wireguard"),
// configures private key, listen port, and peers via Generic Netlink (WG_CMD_SET_DEVICE),
// and assigns the tunnel IP + brings the interface UP via EdgeNetworkEngine.
func ConfigureWireGuardNetlink(cfg WireGuardConfig) error {
	setAttrs, err := BuildWireGuardSetDeviceAttrs(cfg)
	if err != nil {
		return err
	}

	// 1. Ensure WireGuard interface exists in the kernel via RTM_NEWLINK
	if err := ensureWireGuardLinkNetlink(cfg.InterfaceName); err != nil {
		return fmt.Errorf("RTM_NEWLINK wireguard create failed: %w", err)
	}

	// 2. Program WireGuard device via NETLINK_GENERIC ("wireguard" family)
	famID, err := resolveGenlFamilyID(wgGenlName)
	if err != nil {
		return fmt.Errorf("failed to resolve generic netlink family %q: %w", wgGenlName, err)
	}

	if err := sendGenlMsg(famID, wgCmdSetDevice, wgGenlVersion, setAttrs); err != nil {
		return fmt.Errorf("WG_CMD_SET_DEVICE failed: %w", err)
	}

	// 3. Assign tunnel CIDR and bring interface UP via native RTNETLINK
	netEng := NewEdgeNetworkEngine()
	if err := netEng.ConfigureInterface(EdgeInterfaceSpec{
		Name:    "wg-mesh",
		Device:  cfg.InterfaceName,
		Address: cfg.TunnelIP,
		MTU:     1420,
		Enabled: true,
	}); err != nil {
		return fmt.Errorf("failed to configure WireGuard tunnel IP %s on %s: %w", cfg.TunnelIP, cfg.InterfaceName, err)
	}

	return nil
}

// ensureWireGuardLinkNetlink creates a WireGuard virtual network device via RTM_NEWLINK if it does not already exist.
func ensureWireGuardLinkNetlink(ifname string) error {
	if _, err := net.InterfaceByName(ifname); err == nil {
		return nil // Already exists
	}

	fd, err := syscall.Socket(syscall.AF_NETLINK, syscall.SOCK_RAW|syscall.SOCK_CLOEXEC, syscall.NETLINK_ROUTE)
	if err != nil {
		return err
	}
	defer syscall.Close(fd)

	if err := syscall.Bind(fd, &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK}); err != nil {
		return err
	}

	ifnameAttr := nlAttrStr(iflaIfname, ifname)
	linkInfoAttr := nlAttrNested(iflaLinkinfo, nlAttrStr(iflaInfoKind, "wireguard"))

	// nlmsghdr (16) + ifinfomsg (16) + attrs
	totalLen := syscall.NLMSG_HDRLEN + 16 + len(ifnameAttr) + len(linkInfoAttr)
	msg := make([]byte, totalLen)
	binary.NativeEndian.PutUint32(msg[0:4], uint32(totalLen))
	binary.NativeEndian.PutUint16(msg[4:6], syscall.RTM_NEWLINK)
	binary.NativeEndian.PutUint16(msg[6:8], syscall.NLM_F_REQUEST|syscall.NLM_F_ACK|syscall.NLM_F_CREATE|syscall.NLM_F_EXCL)
	binary.NativeEndian.PutUint32(msg[8:12], 1)

	offset := syscall.NLMSG_HDRLEN + 16
	copy(msg[offset:], ifnameAttr)
	offset += len(ifnameAttr)
	copy(msg[offset:], linkInfoAttr)

	if err := syscall.Sendto(fd, msg, 0, &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK}); err != nil {
		return err
	}

	return readNetlinkAck(fd)
}

func resolveGenlFamilyID(familyName string) (uint16, error) {
	fd, err := syscall.Socket(syscall.AF_NETLINK, syscall.SOCK_RAW|syscall.SOCK_CLOEXEC, syscall.NETLINK_GENERIC)
	if err != nil {
		return 0, err
	}
	defer syscall.Close(fd)

	if err := syscall.Bind(fd, &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK}); err != nil {
		return 0, err
	}

	attr := nlAttrStr(ctrlAttrFamilyName, familyName)
	// nlmsghdr (16) + genlmsghdr (4: cmd, version, reserved) + attr
	totalLen := syscall.NLMSG_HDRLEN + 4 + len(attr)
	msg := make([]byte, totalLen)
	binary.NativeEndian.PutUint32(msg[0:4], uint32(totalLen))
	binary.NativeEndian.PutUint16(msg[4:6], genlIDCtrl)
	binary.NativeEndian.PutUint16(msg[6:8], syscall.NLM_F_REQUEST|syscall.NLM_F_ACK)
	binary.NativeEndian.PutUint32(msg[8:12], 1)
	msg[16] = ctrlCmdGetFamily
	msg[17] = 1
	copy(msg[20:], attr)

	if err := syscall.Sendto(fd, msg, 0, &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK}); err != nil {
		return 0, err
	}

	buf := make([]byte, 4096)
	n, _, err := syscall.Recvfrom(fd, buf, 0)
	if err != nil {
		return 0, err
	}

	msgs, err := syscall.ParseNetlinkMessage(buf[:n])
	if err != nil {
		return 0, err
	}

	for _, m := range msgs {
		if m.Header.Type == syscall.NLMSG_ERROR && len(m.Data) >= 4 {
			errno := int32(binary.NativeEndian.Uint32(m.Data[0:4]))
			if errno < 0 {
				return 0, syscall.Errno(-errno)
			}
			continue
		}
		if len(m.Data) <= 4 {
			continue
		}
		// Parse genl attributes starting at m.Data[4:]
		pos := 4
		for pos+4 <= len(m.Data) {
			aLen := int(binary.NativeEndian.Uint16(m.Data[pos : pos+2]))
			aTyp := binary.NativeEndian.Uint16(m.Data[pos+2 : pos+4])
			if aLen < 4 || pos+aLen > len(m.Data) {
				break
			}
			if aTyp == ctrlAttrFamilyID && aLen >= 6 {
				return binary.NativeEndian.Uint16(m.Data[pos+4 : pos+6]), nil
			}
			pos += (aLen + 3) & ^3
		}
	}
	return 0, fmt.Errorf("wireguard generic netlink family ID not found in response")
}

func sendGenlMsg(familyID uint16, cmd, version uint8, attrs []byte) error {
	fd, err := syscall.Socket(syscall.AF_NETLINK, syscall.SOCK_RAW|syscall.SOCK_CLOEXEC, syscall.NETLINK_GENERIC)
	if err != nil {
		return err
	}
	defer syscall.Close(fd)

	if err := syscall.Bind(fd, &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK}); err != nil {
		return err
	}

	totalLen := syscall.NLMSG_HDRLEN + 4 + len(attrs)
	msg := make([]byte, totalLen)
	binary.NativeEndian.PutUint32(msg[0:4], uint32(totalLen))
	binary.NativeEndian.PutUint16(msg[4:6], familyID)
	binary.NativeEndian.PutUint16(msg[6:8], syscall.NLM_F_REQUEST|syscall.NLM_F_ACK)
	binary.NativeEndian.PutUint32(msg[8:12], 2)
	msg[16] = cmd
	msg[17] = version
	copy(msg[20:], attrs)

	if err := syscall.Sendto(fd, msg, 0, &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK}); err != nil {
		return err
	}

	return readNetlinkAck(fd)
}

func readNetlinkAck(fd int) error {
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
