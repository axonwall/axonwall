package engine

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
)

// DHCPv6 message types (RFC 8415)
const (
	dhcpv6MsgSolicit   = 1
	dhcpv6MsgAdvertise = 2
	dhcpv6MsgRequest   = 3
	dhcpv6MsgRenew     = 5
	dhcpv6MsgRebind    = 6
	dhcpv6MsgReply     = 7

	dhcpv6OptClientID    = 1
	dhcpv6OptServerID    = 2
	dhcpv6OptIANA        = 3
	dhcpv6OptIAAddr      = 5
	dhcpv6OptORO         = 6
	dhcpv6OptElapsedTime = 8
	dhcpv6OptDNSServers  = 23
	dhcpv6OptIAPD        = 25
	dhcpv6OptIAPrefix    = 26
)

// DHCPv6Lease represents a WAN IPv6 address (IA_NA) and/or Delegated Prefix (IA_PD)
// acquired via RFC 8415 DHCPv6.
type DHCPv6Lease struct {
	WANAddress        string   `json:"wanAddress,omitempty"`        // e.g. "2001:db8:1::1234/128"
	DelegatedPrefix   string   `json:"delegatedPrefix,omitempty"`   // e.g. "2001:db8:abcd::/56"
	PreferredLifetime uint32   `json:"preferredLifetime,omitempty"` // seconds
	ValidLifetime     uint32   `json:"validLifetime,omitempty"`     // seconds
	ServerDUID        []byte   `json:"serverDuid,omitempty"`
	DNSServers        []string `json:"dnsServers,omitempty"`
}

// ApplyInterfaceIPv6Mode configures kernel per-interface IPv6 sysctls according to mode:
//   - "disabled": disable_ipv6=1, accept_ra=0, autoconf=0 (complete kernel IPv6 stack shutoff on interface)
//   - "auto":     disable_ipv6=0, accept_ra=2 (accept RA even when forwarding=1), autoconf=1
//   - "static" | "delegated" | "ula-only": disable_ipv6=0, accept_ra=0, autoconf=0
func ApplyInterfaceIPv6Mode(procSysRoot, dev, mode string) error {
	if procSysRoot == "" {
		procSysRoot = "/proc/sys"
	}
	if !validRadioRegex.MatchString(dev) || strings.HasPrefix(dev, "-") || strings.Contains(dev, "..") {
		return fmt.Errorf("invalid interface name %q", dev)
	}

	confDir := filepath.Join(procSysRoot, "net", "ipv6", "conf", dev)
	_ = os.MkdirAll(confDir, 0755)

	normMode := strings.ToLower(strings.TrimSpace(mode))
	var disableV6, acceptRA, autoconf string

	switch normMode {
	case "disabled", "off", "none":
		disableV6 = "1"
		acceptRA = "0"
		autoconf = "0"
	case "auto", "slaac", "dhcpv6", "dhcp":
		disableV6 = "0"
		acceptRA = "2" // accept Router Advertisements even with net.ipv6.conf.all.forwarding=1
		autoconf = "1"
	default:
		// "static", "delegated", "ula-only"
		disableV6 = "0"
		acceptRA = "0"
		autoconf = "0"
	}

	if err := os.WriteFile(filepath.Join(confDir, "disable_ipv6"), []byte(disableV6+"\n"), 0644); err != nil {
		return err
	}
	_ = os.WriteFile(filepath.Join(confDir, "accept_ra"), []byte(acceptRA+"\n"), 0644)
	_ = os.WriteFile(filepath.Join(confDir, "autoconf"), []byte(autoconf+"\n"), 0644)
	return nil
}

// DeriveDeterministicULA generates a stable RFC 4193 /48 Unique Local Address prefix
// (fdXX:XXXX:XXXX::/48) from a seed (such as SatelliteID or host machine-id) so internal
// DNS, NAS, and k3s endpoints survive ISP prefix renumbering.
func DeriveDeterministicULA(seed string) string {
	sum := sha256.Sum256([]byte("axonwall-ula:" + strings.TrimSpace(seed)))
	return fmt.Sprintf("fd%02x:%02x%02x:%02x%02x::/48", sum[0], sum[1], sum[2], sum[3], sum[4])
}

// CarveSubnet64 carves a /64 subnet + hostID (e.g. ::1/64) out of a /48 or /56 IPv6 prefix.
func CarveSubnet64(prefixCIDR string, subnetID uint16, hostID uint16) (string, error) {
	ip, ipNet, err := net.ParseCIDR(strings.TrimSpace(prefixCIDR))
	if err != nil {
		return "", err
	}
	v6 := ip.To16()
	if v6 == nil || ip.To4() != nil {
		return "", fmt.Errorf("not an IPv6 prefix: %q", prefixCIDR)
	}
	ones, _ := ipNet.Mask.Size()
	if ones > 64 {
		return "", fmt.Errorf("prefix %q is narrower than /64", prefixCIDR)
	}

	out := make(net.IP, 16)
	copy(out, v6.Mask(ipNet.Mask))

	if ones <= 48 {
		binary.BigEndian.PutUint16(out[6:8], subnetID)
	} else {
		// e.g. /56 -> modify byte 7
		out[7] = (out[7] & ipNet.Mask[7]) | byte(subnetID&0xff)
	}

	if hostID > 0 {
		binary.BigEndian.PutUint16(out[14:16], hostID)
	}
	return fmt.Sprintf("%s/64", out.String()), nil
}

// BuildDUIDLL constructs a deterministic RFC 8415 DUID-LL (Type 3, Hardware Type 1 Ethernet)
// from a 6-byte MAC address so the active and standby HA Edge VMs share the exact same DHCPv6 identity.
func BuildDUIDLL(mac net.HardwareAddr) []byte {
	duid := make([]byte, 4+len(mac))
	binary.BigEndian.PutUint16(duid[0:2], 3) // DUID-LL
	binary.BigEndian.PutUint16(duid[2:4], 1) // HTYPE Ethernet (1)
	copy(duid[4:], mac)
	return duid
}

// BuildDHCPv6Packet builds an RFC 8415 DHCPv6 Solicit (1) or Request (3) UDP payload
// requesting IA_NA (WAN address) and IA_PD (Prefix Delegation with hintPrefixLen, e.g. 56).
func BuildDHCPv6Packet(msgType byte, txID [3]byte, clientDUID []byte, serverDUID []byte, hintPrefixLen byte) []byte {
	if hintPrefixLen == 0 {
		hintPrefixLen = 56
	}
	var buf []byte
	buf = append(buf, msgType, txID[0], txID[1], txID[2])

	// 1. Client Identifier Option (1)
	buf = appendDHCPv6Opt(buf, dhcpv6OptClientID, clientDUID)

	// 2. Server Identifier Option (2) if Request/Renew
	if len(serverDUID) > 0 {
		buf = appendDHCPv6Opt(buf, dhcpv6OptServerID, serverDUID)
	}

	// 3. Elapsed Time Option (8): 0 ms
	buf = appendDHCPv6Opt(buf, dhcpv6OptElapsedTime, []byte{0, 0})

	// 4. IA_NA Option (3): IAID=1, T1=0, T2=0
	iana := make([]byte, 12)
	binary.BigEndian.PutUint32(iana[0:4], 1)
	buf = appendDHCPv6Opt(buf, dhcpv6OptIANA, iana)

	// 5. IA_PD Option (25): IAID=2, T1=0, T2=0 + embedded IAPREFIX Option (26) hint
	iaprefix := make([]byte, 25)
	// Preferred=0, Valid=0, prefix-length=hintPrefixLen, IPv6 prefix=::
	iaprefix[8] = hintPrefixLen
	iapd := make([]byte, 12)
	binary.BigEndian.PutUint32(iapd[0:4], 2)
	iapd = appendDHCPv6Opt(iapd, dhcpv6OptIAPrefix, iaprefix)
	buf = appendDHCPv6Opt(buf, dhcpv6OptIAPD, iapd)

	// 6. Option Request Option (6): request DNS Recursive Name Server (23)
	oro := make([]byte, 2)
	binary.BigEndian.PutUint16(oro[0:2], dhcpv6OptDNSServers)
	buf = appendDHCPv6Opt(buf, dhcpv6OptORO, oro)

	return buf
}

// ParseDHCPv6Packet parses an RFC 8415 DHCPv6 Advertise (2) or Reply (7) packet.
func ParseDHCPv6Packet(pkt []byte, expectedTxID [3]byte) (msgType byte, lease DHCPv6Lease, err error) {
	if len(pkt) < 4 {
		return 0, lease, fmt.Errorf("short DHCPv6 packet (%d bytes)", len(pkt))
	}
	msgType = pkt[0]
	if pkt[1] != expectedTxID[0] || pkt[2] != expectedTxID[1] || pkt[3] != expectedTxID[2] {
		return 0, lease, fmt.Errorf("DHCPv6 transaction ID mismatch")
	}

	opts := pkt[4:]
	for len(opts) >= 4 {
		optCode := binary.BigEndian.Uint16(opts[0:2])
		optLen := int(binary.BigEndian.Uint16(opts[2:4]))
		opts = opts[4:]
		if len(opts) < optLen {
			break
		}
		optData := opts[:optLen]
		opts = opts[optLen:]

		switch optCode {
		case dhcpv6OptServerID:
			lease.ServerDUID = append([]byte(nil), optData...)

		case dhcpv6OptIANA:
			if len(optData) >= 12 {
				sub := optData[12:]
				for len(sub) >= 4 {
					sc := binary.BigEndian.Uint16(sub[0:2])
					sl := int(binary.BigEndian.Uint16(sub[2:4]))
					sub = sub[4:]
					if len(sub) < sl {
						break
					}
					sd := sub[:sl]
					sub = sub[sl:]
					if sc == dhcpv6OptIAAddr && len(sd) >= 24 {
						ip := net.IP(sd[0:16])
						lease.WANAddress = ip.String() + "/128"
					}
				}
			}

		case dhcpv6OptIAPD:
			if len(optData) >= 12 {
				sub := optData[12:]
				for len(sub) >= 4 {
					sc := binary.BigEndian.Uint16(sub[0:2])
					sl := int(binary.BigEndian.Uint16(sub[2:4]))
					sub = sub[4:]
					if len(sub) < sl {
						break
					}
					sd := sub[:sl]
					sub = sub[sl:]
					if sc == dhcpv6OptIAPrefix && len(sd) >= 25 {
						prefLife := binary.BigEndian.Uint32(sd[0:4])
						validLife := binary.BigEndian.Uint32(sd[4:8])
						pLen := sd[8]
						prefixIP := net.IP(sd[9:25])
						lease.DelegatedPrefix = fmt.Sprintf("%s/%d", prefixIP.String(), pLen)
						lease.PreferredLifetime = prefLife
						lease.ValidLifetime = validLife
					}
				}
			}

		case dhcpv6OptDNSServers:
			for i := 0; i+16 <= len(optData); i += 16 {
				lease.DNSServers = append(lease.DNSServers, net.IP(optData[i:i+16]).String())
			}
		}
	}

	return msgType, lease, nil
}

// BuildRouterAdvertisementICMPv6 constructs an RFC 4861 / RFC 8106 ICMPv6 Router Advertisement
// (Type 134, Code 0) payload advertising one or more /64 prefixes (SLAAC L=1, A=1) and RDNSS.
func BuildRouterAdvertisementICMPv6(prefixes []string, rdnssIPv6 string, mtu uint32, routerLifetimeSec uint16) ([]byte, error) {
	// 16-byte ICMPv6 RA header:
	// Type(1)=134, Code(1)=0, Checksum(2)=0, CurHopLimit(1)=64, Flags(1)=0x00, RouterLifetime(2), ReachableTime(4)=0, RetransTimer(4)=0
	ra := make([]byte, 16)
	ra[0] = 134 // Type: Router Advertisement
	ra[1] = 0
	ra[4] = 64 // Cur Hop Limit
	ra[5] = 0  // M=0, O=0 (SLAAC + RDNSS)
	binary.BigEndian.PutUint16(ra[6:8], routerLifetimeSec)

	// Prefix Information Options (Type 3, Length 4 = 32 bytes each)
	for _, pStr := range prefixes {
		if strings.TrimSpace(pStr) == "" {
			continue
		}
		ip, ipNet, err := net.ParseCIDR(strings.TrimSpace(pStr))
		if err != nil {
			return nil, err
		}
		v6 := ip.To16()
		if v6 == nil || ip.To4() != nil {
			return nil, fmt.Errorf("non-IPv6 RA prefix %q", pStr)
		}
		ones, _ := ipNet.Mask.Size()
		masked := v6.Mask(ipNet.Mask)

		pio := make([]byte, 32)
		pio[0] = 3            // Option Type: Prefix Information
		pio[1] = 4            // Length in 8-octet units (32 bytes)
		pio[2] = byte(ones)   // Prefix Length (e.g. 64)
		pio[3] = 0xc0         // Flags: L=1 (on-link), A=1 (autonomous address-configuration)
		binary.BigEndian.PutUint32(pio[4:8], 86400)  // Valid Lifetime: 24h
		binary.BigEndian.PutUint32(pio[8:12], 14400) // Preferred Lifetime: 4h
		copy(pio[16:32], masked)
		ra = append(ra, pio...)
	}

	// Recursive DNS Server Option (RFC 8106 Type 25, Length 3 = 24 bytes for 1 IPv6 address)
	if strings.TrimSpace(rdnssIPv6) != "" {
		dnsStr := strings.Split(strings.TrimSpace(rdnssIPv6), "/")[0]
		dnsIP := net.ParseIP(dnsStr)
		if dnsIP != nil && dnsIP.To16() != nil && dnsIP.To4() == nil {
			rdnss := make([]byte, 24)
			rdnss[0] = 25 // Type: RDNSS
			rdnss[1] = 3  // Length: 3 * 8 = 24 bytes
			binary.BigEndian.PutUint32(rdnss[4:8], 3600) // Lifetime: 1h
			copy(rdnss[8:24], dnsIP.To16())
			ra = append(ra, rdnss...)
		}
	}

	// MTU Option (Type 5, Length 1 = 8 bytes)
	if mtu > 0 {
		mtuOpt := make([]byte, 8)
		mtuOpt[0] = 5
		mtuOpt[1] = 1
		binary.BigEndian.PutUint32(mtuOpt[4:8], mtu)
		ra = append(ra, mtuOpt...)
	}

	return ra, nil
}

func appendDHCPv6Opt(buf []byte, code uint16, payload []byte) []byte {
	hdr := make([]byte, 4)
	binary.BigEndian.PutUint16(hdr[0:2], code)
	binary.BigEndian.PutUint16(hdr[2:4], uint16(len(payload)))
	buf = append(buf, hdr...)
	buf = append(buf, payload...)
	return buf
}
