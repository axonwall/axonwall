package engine

import (
	"encoding/binary"
	"fmt"
	"net"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

type tcpDiagMetrics struct {
	RttMs       float64
	Retransmits uint32
}

const (
	sockDiagByFamily = 20
	inetDiagInfoFlag = 1 << 1 // INET_DIAG_INFO (1<<1 -> attribute type 2)
	nlmsgNoop        = 1
	nlmsgError       = 2
	nlmsgDone        = 3
)

// readTCPDiagMetrics queries Linux NETLINK_SOCK_DIAG for active TCP socket smoothed RTT & retransmits.
// Degrades cleanly to an empty map in unprivileged/container environments.
func readTCPDiagMetrics() map[string]tcpDiagMetrics {
	out := make(map[string]tcpDiagMetrics)
	for _, fam := range []uint8{unix.AF_INET, unix.AF_INET6} {
		_ = querySockDiagFamily(fam, out)
	}
	return out
}

func querySockDiagFamily(family uint8, out map[string]tcpDiagMetrics) error {
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW, unix.NETLINK_SOCK_DIAG)
	if err != nil {
		return err
	}
	defer unix.Close(fd)

	_ = unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &unix.Timeval{Sec: 0, Usec: 250_000})

	// Build inet_diag_req_v2 (56 bytes) + nlmsghdr (16 bytes) = 72 bytes.
	req := make([]byte, 72)
	// nlmsghdr
	binary.LittleEndian.PutUint32(req[0:4], 72)
	binary.LittleEndian.PutUint16(req[4:6], sockDiagByFamily)
	binary.LittleEndian.PutUint16(req[6:8], unix.NLM_F_REQUEST|unix.NLM_F_DUMP)
	binary.LittleEndian.PutUint32(req[8:12], 1)
	// inet_diag_req_v2
	req[16] = family
	req[17] = unix.IPPROTO_TCP
	req[18] = inetDiagInfoFlag // ext = INET_DIAG_INFO
	req[19] = 0
	// idiag_states: TCP_ESTABLISHED(1<<1) | TCP_SYN_SENT(1<<2) | TCP_SYN_RECV(1<<3)
	binary.LittleEndian.PutUint32(req[20:24], (1<<1)|(1<<2)|(1<<3))

	sa := &unix.SockaddrNetlink{Family: unix.AF_NETLINK}
	if err := unix.Sendto(fd, req, 0, sa); err != nil {
		return err
	}

	buf := make([]byte, 64*1024)
	for {
		n, _, err := unix.Recvfrom(fd, buf, 0)
		if err != nil || n <= 0 {
			return err
		}
		msgs, err := syscall.ParseNetlinkMessage(buf[:n])
		if err != nil {
			return err
		}
		for _, m := range msgs {
			switch m.Header.Type {
			case nlmsgDone, nlmsgError:
				return nil
			case nlmsgNoop:
				continue
			case sockDiagByFamily:
				parseInetDiagMsg(family, m.Data, out)
			}
		}
	}
}

func parseInetDiagMsg(family uint8, data []byte, out map[string]tcpDiagMetrics) {
	// struct inet_diag_msg is 72 bytes
	if len(data) < 72 {
		return
	}
	sport := binary.BigEndian.Uint16(data[4:6])
	dport := binary.BigEndian.Uint16(data[6:8])

	var srcIP, dstIP string
	if family == unix.AF_INET {
		srcIP = net.IP(data[8:12]).String()
		dstIP = net.IP(data[24:28]).String()
	} else {
		srcIP = net.IP(data[8:24]).String()
		dstIP = net.IP(data[24:40]).String()
	}

	// Parse netlink attributes following the 72-byte inet_diag_msg
	attrOff := 72
	for attrOff+4 <= len(data) {
		aLen := int(binary.LittleEndian.Uint16(data[attrOff : attrOff+2]))
		aType := binary.LittleEndian.Uint16(data[attrOff+2 : attrOff+4])
		if aLen < 4 || attrOff+aLen > len(data) {
			break
		}
		if aType == 2 && aLen >= 4+int(unsafe.Sizeof(unix.TCPInfo{})) {
			// INET_DIAG_INFO carries struct tcp_info
			var ti unix.TCPInfo
			payload := data[attrOff+4 : attrOff+4+int(unsafe.Sizeof(ti))]
			copy((*[unsafe.Sizeof(ti)]byte)(unsafe.Pointer(&ti))[:], payload)
			rttMs := float64(ti.Rtt) / 1000.0
			retrans := ti.Total_retrans
			if rttMs > 0 || retrans > 0 {
				key := fmt.Sprintf("%s|%d|%s|%d", srcIP, sport, dstIP, dport)
				out[key] = tcpDiagMetrics{RttMs: rttMs, Retransmits: retrans}
			}
		}
		aligned := (aLen + 3) &^ 3
		attrOff += aligned
	}
}
