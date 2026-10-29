package engine

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"net"
	"syscall"
	"time"
)

// DHCPv4 constants (RFC 2131 & RFC 2132)
const (
	bootpRequest = 1
	bootpReply   = 2
	htypeEther   = 1

	dhcpMagicCookie = 0x63825363

	dhcpOptSubnetMask   = 1
	dhcpOptRouter       = 3
	dhcpOptDNS          = 6
	dhcpOptRequestedIP  = 50
	dhcpOptLeaseTime    = 51
	dhcpOptMsgType      = 53
	dhcpOptServerID     = 54
	dhcpOptParamReqList = 55
	dhcpOptEnd          = 255

	dhcpMsgDiscover = 1
	dhcpMsgOffer    = 2
	dhcpMsgRequest  = 3
	dhcpMsgAck      = 5
)

// DHCPv4Lease represents a leased IPv4 configuration obtained from a DHCP server.
type DHCPv4Lease struct {
	CIDR      string        // e.g. "203.0.113.42/24"
	IP        net.IP        // e.g. 203.0.113.42
	Netmask   net.IPMask    // e.g. ffffff00
	Gateway   string        // e.g. "203.0.113.1"
	ServerIP  net.IP        // DHCP server identifier
	LeaseTime time.Duration // e.g. 24h
}

// BuildDHCPv4Packet constructs a 300-byte RFC 2131 BOOTP/DHCPv4 packet.
func BuildDHCPv4Packet(msgType byte, xid uint32, mac net.HardwareAddr, requestedIP, serverID net.IP) []byte {
	pkt := make([]byte, 300)
	pkt[0] = bootpRequest
	pkt[1] = htypeEther
	pkt[2] = 6 // Ethernet MAC length
	pkt[3] = 0 // hops
	binary.BigEndian.PutUint32(pkt[4:8], xid)
	// Broadcast flag (0x8000) so server replies via broadcast before interface has an IP
	binary.BigEndian.PutUint16(pkt[10:12], 0x8000)
	copy(pkt[28:34], mac)

	// Magic cookie at offset 236
	binary.BigEndian.PutUint32(pkt[236:240], dhcpMagicCookie)

	opt := 240
	// Option 53: DHCP Message Type
	pkt[opt] = dhcpOptMsgType
	pkt[opt+1] = 1
	pkt[opt+2] = msgType
	opt += 3

	if msgType == dhcpMsgRequest {
		if ip4 := requestedIP.To4(); ip4 != nil {
			pkt[opt] = dhcpOptRequestedIP
			pkt[opt+1] = 4
			copy(pkt[opt+2:opt+6], ip4)
			opt += 6
		}
		if srv4 := serverID.To4(); srv4 != nil {
			pkt[opt] = dhcpOptServerID
			pkt[opt+1] = 4
			copy(pkt[opt+2:opt+6], srv4)
			opt += 6
		}
	}

	// Option 55: Parameter Request List (Subnet Mask, Router, DNS)
	pkt[opt] = dhcpOptParamReqList
	pkt[opt+1] = 3
	pkt[opt+2] = dhcpOptSubnetMask
	pkt[opt+3] = dhcpOptRouter
	pkt[opt+4] = dhcpOptDNS
	opt += 5

	// Option 255: End
	pkt[opt] = dhcpOptEnd
	return pkt
}

// ParseDHCPv4Packet parses a BOOTP/DHCPv4 reply packet matching xid.
func ParseDHCPv4Packet(pkt []byte, expectedXID uint32) (msgType byte, lease DHCPv4Lease, err error) {
	if len(pkt) < 240 {
		return 0, lease, fmt.Errorf("packet too short (%d bytes)", len(pkt))
	}
	if pkt[0] != bootpReply {
		return 0, lease, fmt.Errorf("not a BOOTP reply (op=%d)", pkt[0])
	}
	xid := binary.BigEndian.Uint32(pkt[4:8])
	if xid != expectedXID {
		return 0, lease, fmt.Errorf("xid mismatch: got 0x%x, want 0x%x", xid, expectedXID)
	}
	cookie := binary.BigEndian.Uint32(pkt[236:240])
	if cookie != dhcpMagicCookie {
		return 0, lease, fmt.Errorf("invalid DHCP magic cookie 0x%x", cookie)
	}

	yiaddr := net.IPv4(pkt[16], pkt[17], pkt[18], pkt[19])
	lease.IP = yiaddr
	lease.Netmask = net.CIDRMask(24, 32) // default /24 if server omits Option 1
	lease.LeaseTime = 3600 * time.Second

	pos := 240
	for pos < len(pkt) {
		code := pkt[pos]
		if code == dhcpOptEnd {
			break
		}
		if code == 0 { // Pad
			pos++
			continue
		}
		if pos+1 >= len(pkt) {
			break
		}
		l := int(pkt[pos+1])
		if pos+2+l > len(pkt) {
			break
		}
		val := pkt[pos+2 : pos+2+l]
		switch code {
		case dhcpOptMsgType:
			if l >= 1 {
				msgType = val[0]
			}
		case dhcpOptSubnetMask:
			if l == 4 {
				lease.Netmask = net.IPv4Mask(val[0], val[1], val[2], val[3])
			}
		case dhcpOptRouter:
			if l >= 4 {
				lease.Gateway = net.IPv4(val[0], val[1], val[2], val[3]).String()
			}
		case dhcpOptServerID:
			if l == 4 {
				lease.ServerIP = net.IPv4(val[0], val[1], val[2], val[3])
			}
		case dhcpOptLeaseTime:
			if l == 4 {
				secs := binary.BigEndian.Uint32(val)
				lease.LeaseTime = time.Duration(secs) * time.Second
			}
		}
		pos += 2 + l
	}

	ones, _ := lease.Netmask.Size()
	if ones == 0 {
		ones = 24
	}
	lease.CIDR = fmt.Sprintf("%s/%d", lease.IP.String(), ones)
	return msgType, lease, nil
}

// AcquireDHCPv4Lease performs a pure-Go RFC 2131 DORA handshake on `dev` without external binaries.
func AcquireDHCPv4Lease(dev string, timeout time.Duration) (DHCPv4Lease, error) {
	var lease DHCPv4Lease
	iface, err := net.InterfaceByName(dev)
	if err != nil {
		return lease, fmt.Errorf("interface %s not found: %w", dev, err)
	}
	if len(iface.HardwareAddr) < 6 {
		return lease, fmt.Errorf("interface %s has no 6-byte Ethernet MAC", dev)
	}

	var xidBytes [4]byte
	_, _ = rand.Read(xidBytes[:])
	xid := binary.BigEndian.Uint32(xidBytes[:])

	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM|syscall.SOCK_CLOEXEC, syscall.IPPROTO_UDP)
	if err != nil {
		return lease, err
	}
	defer syscall.Close(fd)

	_ = syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1)
	_ = syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_BROADCAST, 1)
	_ = syscall.SetsockoptString(fd, syscall.SOL_SOCKET, syscall.SO_BINDTODEVICE, dev)

	if timeout <= 0 {
		timeout = 3 * time.Second
	}
	tv := syscall.NsecToTimeval(timeout.Nanoseconds())
	_ = syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &tv)

	if err := syscall.Bind(fd, &syscall.SockaddrInet4{Port: 68}); err != nil {
		return lease, fmt.Errorf("DHCPv4 bind :68 on %s failed: %w", dev, err)
	}

	bcastAddr := &syscall.SockaddrInet4{
		Port: 67,
		Addr: [4]byte{255, 255, 255, 255},
	}

	// 1. Send DHCPDISCOVER
	discover := BuildDHCPv4Packet(dhcpMsgDiscover, xid, iface.HardwareAddr, nil, nil)
	if err := syscall.Sendto(fd, discover, 0, bcastAddr); err != nil {
		return lease, fmt.Errorf("DHCPDISCOVER send failed: %w", err)
	}

	// 2. Wait for DHCPOFFER
	buf := make([]byte, 1500)
	var offer DHCPv4Lease
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		n, _, recvErr := syscall.Recvfrom(fd, buf, 0)
		if recvErr != nil {
			break
		}
		mType, parsed, pErr := ParseDHCPv4Packet(bytes.Clone(buf[:n]), xid)
		if pErr == nil && mType == dhcpMsgOffer {
			offer = parsed
			break
		}
	}
	if offer.IP == nil {
		return lease, fmt.Errorf("timed out waiting for DHCPOFFER on %s", dev)
	}

	// 3. Send DHCPREQUEST
	request := BuildDHCPv4Packet(dhcpMsgRequest, xid, iface.HardwareAddr, offer.IP, offer.ServerIP)
	if err := syscall.Sendto(fd, request, 0, bcastAddr); err != nil {
		return lease, fmt.Errorf("DHCPREQUEST send failed: %w", err)
	}

	// 4. Wait for DHCPACK
	for time.Now().Before(deadline) {
		n, _, recvErr := syscall.Recvfrom(fd, buf, 0)
		if recvErr != nil {
			break
		}
		mType, parsed, pErr := ParseDHCPv4Packet(bytes.Clone(buf[:n]), xid)
		if pErr == nil && mType == dhcpMsgAck {
			return parsed, nil
		}
	}

	return offer, nil
}
