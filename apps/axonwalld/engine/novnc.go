package engine

import (
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
)

const wsMagicGUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

type ConsoleProxy struct {
	mu sync.Mutex
}

func NewConsoleProxy() *ConsoleProxy {
	return &ConsoleProxy{}
}

// computeAcceptKey calculates RFC 6455 Sec-WebSocket-Accept
func computeAcceptKey(clientKey string) string {
	h := sha1.New()
	h.Write([]byte(clientKey + wsMagicGUID))
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}

func (p *ConsoleProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	targetType := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("type")))
	if targetType == "" {
		targetType = "vnc"
	}
	idStr := strings.TrimSpace(r.URL.Query().Get("vmid"))
	if idStr == "" {
		idStr = strings.TrimSpace(r.URL.Query().Get("ctid"))
	}
	id, err := strconv.Atoi(idStr)
	if err != nil || id <= 0 {
		http.Error(w, "Invalid or missing vmid/ctid parameter", http.StatusBadRequest)
		return
	}

	var socketPath string
	switch targetType {
	case "vnc":
		socketPath = fmt.Sprintf("/run/axonwall/vnc/vm-%d.sock", id)
	case "serial":
		socketPath = fmt.Sprintf("/run/axonwall/serial/vm-%d.sock", id)
	case "lxc":
		socketPath = fmt.Sprintf("/run/axonwall/lxc/ct-%d.sock", id)
	default:
		http.Error(w, "Unsupported console type: "+targetType, http.StatusBadRequest)
		return
	}

	if _, err := os.Stat(socketPath); os.IsNotExist(err) {
		http.Error(w, fmt.Sprintf("Console socket not found for target %d (%s). Is the workload running?", id, socketPath), http.StatusNotFound)
		return
	}

	// Verify WebSocket upgrade request and Origin header
	if origin := strings.TrimSpace(r.Header.Get("Origin")); origin != "" {
		u, err := url.Parse(origin)
		if err != nil || u.Host == "" {
			http.Error(w, "Invalid Origin header", http.StatusForbidden)
			return
		}
		if r.Host != "" && !strings.EqualFold(u.Host, r.Host) && !strings.EqualFold(u.Hostname(), strings.Split(r.Host, ":")[0]) {
			http.Error(w, "Cross-origin WebSocket connection rejected", http.StatusForbidden)
			return
		}
	}
	if !strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
		http.Error(w, "Upgrade header must be websocket", http.StatusBadRequest)
		return
	}
	clientKey := r.Header.Get("Sec-WebSocket-Key")
	if clientKey == "" {
		http.Error(w, "Missing Sec-WebSocket-Key", http.StatusBadRequest)
		return
	}

	// Connect to the target Unix domain socket
	backendConn, err := net.Dial("unix", socketPath)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to connect to backend socket %s: %v", socketPath, err), http.StatusBadGateway)
		return
	}
	defer backendConn.Close()

	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "WebSocket hijack unsupported", http.StatusInternalServerError)
		return
	}

	clientConn, clientBuf, err := hijacker.Hijack()
	if err != nil {
		log.Printf("[ConsoleProxy] Hijack error: %v", err)
		return
	}
	defer clientConn.Close()

	// Negotiate subprotocol if requested (noVNC supports 'binary')
	subproto := ""
	for _, p := range strings.Split(r.Header.Get("Sec-WebSocket-Protocol"), ",") {
		p = strings.TrimSpace(p)
		if p == "binary" {
			subproto = "Sec-WebSocket-Protocol: binary\r\n"
			break
		}
	}

	acceptKey := computeAcceptKey(clientKey)
	handshake := fmt.Sprintf("HTTP/1.1 101 Switching Protocols\r\n"+
		"Upgrade: websocket\r\n"+
		"Connection: Upgrade\r\n"+
		"%s"+
		"Sec-WebSocket-Accept: %s\r\n\r\n", subproto, acceptKey)

	if _, err := clientBuf.WriteString(handshake); err != nil {
		return
	}
	if err := clientBuf.Flush(); err != nil {
		return
	}

	errChan := make(chan error, 2)

	// Goroutine 1: Backend -> WebSocket Client (pack into binary frames)
	go func() {
		buf := make([]byte, 16384)
		for {
			n, err := backendConn.Read(buf)
			if n > 0 {
				if err := writeWSFrame(clientConn, buf[:n], 0x2); err != nil {
					errChan <- err
					return
				}
			}
			if err != nil {
				errChan <- err
				return
			}
		}
	}()

	// Goroutine 2: WebSocket Client -> Backend (decode WS frames, write to unix socket)
	go func() {
		for {
			payload, opcode, err := readWSFrame(clientBuf)
			if err != nil {
				errChan <- err
				return
			}
			if opcode == 0x8 { // Close frame
				_ = writeWSFrame(clientConn, nil, 0x8)
				errChan <- io.EOF
				return
			}
			if opcode == 0x9 { // Ping
				_ = writeWSFrame(clientConn, payload, 0xA) // Pong
				continue
			}
			if len(payload) > 0 {
				if _, err := backendConn.Write(payload); err != nil {
					errChan <- err
					return
				}
			}
		}
	}()

	<-errChan
}

func writeWSFrame(w io.Writer, payload []byte, opcode byte) error {
	length := len(payload)
	header := make([]byte, 10)
	header[0] = 0x80 | (opcode & 0x0F) // FIN + opcode

	headerLen := 2
	if length <= 125 {
		header[1] = byte(length)
	} else if length <= 65535 {
		header[1] = 126
		binary.BigEndian.PutUint16(header[2:4], uint16(length))
		headerLen = 4
	} else {
		header[1] = 127
		binary.BigEndian.PutUint64(header[2:10], uint64(length))
		headerLen = 10
	}

	if _, err := w.Write(header[:headerLen]); err != nil {
		return err
	}
	if length > 0 {
		if _, err := w.Write(payload); err != nil {
			return err
		}
	}
	return nil
}

func readWSFrame(r io.Reader) ([]byte, byte, error) {
	head := make([]byte, 2)
	if _, err := io.ReadFull(r, head); err != nil {
		return nil, 0, err
	}

	opcode := head[0] & 0x0F
	masked := (head[1] & 0x80) != 0
	payloadLen := int64(head[1] & 0x7F)

	if payloadLen == 126 {
		var extLen uint16
		if err := binary.Read(r, binary.BigEndian, &extLen); err != nil {
			return nil, 0, err
		}
		payloadLen = int64(extLen)
	} else if payloadLen == 127 {
		var extLen uint64
		if err := binary.Read(r, binary.BigEndian, &extLen); err != nil {
			return nil, 0, err
		}
		if extLen > 10*1024*1024 {
			return nil, 0, fmt.Errorf("websocket frame payload exceeds 10MB limit")
		}
		payloadLen = int64(extLen)
	}

	var maskKey [4]byte
	if masked {
		if _, err := io.ReadFull(r, maskKey[:]); err != nil {
			return nil, 0, err
		}
	}

	if payloadLen > 10*1024*1024 {
		return nil, 0, fmt.Errorf("websocket frame payload exceeds 10MB limit")
	}

	data := make([]byte, payloadLen)
	if _, err := io.ReadFull(r, data); err != nil {
		return nil, 0, err
	}

	if masked {
		for i := 0; i < len(data); i++ {
			data[i] ^= maskKey[i%4]
		}
	}

	return data, opcode, nil
}
