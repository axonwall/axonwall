package engine

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"testing"
	"time"
)

// writeTestWSFrame encodes one client-to-server WebSocket frame.
// fin selects the FIN bit; mask applies a fixed client mask.
func writeTestWSFrame(buf *bytes.Buffer, fin bool, opcode byte, payload []byte, mask bool) {
	b0 := opcode
	if fin {
		b0 |= 0x80
	}
	buf.WriteByte(b0)
	length := len(payload)
	if length <= 125 {
		b1 := byte(length)
		if mask {
			b1 |= 0x80
		}
		buf.WriteByte(b1)
	} else {
		b1 := byte(126)
		if mask {
			b1 |= 0x80
		}
		buf.WriteByte(b1)
		var ext [2]byte
		binary.BigEndian.PutUint16(ext[:], uint16(length))
		buf.Write(ext[:])
	}
	if mask {
		key := []byte{0x11, 0x22, 0x33, 0x44}
		buf.Write(key)
		masked := make([]byte, len(payload))
		for i, b := range payload {
			masked[i] = b ^ key[i%4]
		}
		buf.Write(masked)
		return
	}
	buf.Write(payload)
}

// runForward feeds frames into forwardClientFrames over a net.Pipe and
// returns the chunks the backend side read (net.Pipe preserves write
// boundaries, so one backend Write is one Read) and the terminal error.
func runForward(t *testing.T, frames []byte) ([][]byte, error) {
	t.Helper()
	clientConn, backendConn := net.Pipe()
	defer clientConn.Close()
	defer backendConn.Close()

	errChan := make(chan error, 1)
	go forwardClientFrames(bufio.NewReader(bytes.NewReader(frames)), backendConn, func([]byte, byte) error { return nil }, errChan)

	var chunks [][]byte
	readDone := make(chan struct{})
	go func() {
		defer close(readDone)
		buf := make([]byte, 65536)
		for {
			// The forwarder writes to backendConn; net.Pipe delivers
			// each write to the other end, clientConn.
			_ = clientConn.SetReadDeadline(time.Now().Add(2 * time.Second))
			n, err := clientConn.Read(buf)
			if n > 0 {
				cp := make([]byte, n)
				copy(cp, buf[:n])
				chunks = append(chunks, cp)
			}
			if err != nil {
				return
			}
		}
	}()

	// The forwarder terminates on its own once the input is consumed
	// (ReadFull on the exhausted reader returns EOF) or when it
	// rejects a frame.
	select {
	case err := <-errChan:
		clientConn.Close()
		backendConn.Close()
		<-readDone
		return chunks, err
	case <-time.After(3 * time.Second):
		clientConn.Close()
		backendConn.Close()
		<-readDone
		return chunks, errors.New("forwardClientFrames did not terminate")
	}
}

// A-L6 regression: fragmented binary messages must be reassembled and
// delivered as one write. Pre-fix, each fragment was written to the
// backend separately.
func TestBatch6NoVNCReassemblesFragmentedFrames(t *testing.T) {
	var frames bytes.Buffer
	writeTestWSFrame(&frames, false, 0x2, []byte("HELLO "), true)
	writeTestWSFrame(&frames, true, 0x0, []byte("WORLD"), true)

	chunks, err := runForward(t, frames.Bytes())
	if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("forwarder failed: %v", err)
	}
	if len(chunks) != 1 || string(chunks[0]) != "HELLO WORLD" {
		t.Fatalf("expected one reassembled write %q, got %q", "HELLO WORLD", chunks)
	}
}

// A-L6 regression: a text frame must be rejected, never forwarded as
// RFB bytes. Pre-fix, the text payload was written to the backend raw.
func TestBatch6NoVNCRejectsTextFrames(t *testing.T) {
	var frames bytes.Buffer
	writeTestWSFrame(&frames, true, 0x1, []byte("EVIL-TEXT"), true)

	chunks, err := runForward(t, frames.Bytes())
	if err == nil {
		t.Fatal("expected the forwarder to reject a text frame")
	}
	if len(chunks) != 0 {
		t.Fatalf("text frame payload reached the backend: %q", chunks)
	}
}

// A-L6 regression: pong frames must be ignored, never forwarded.
func TestBatch6NoVNCIgnoresPongFrames(t *testing.T) {
	var frames bytes.Buffer
	writeTestWSFrame(&frames, true, 0xA, []byte("pong!"), true)
	writeTestWSFrame(&frames, true, 0x2, []byte("RFB"), true)

	chunks, err := runForward(t, frames.Bytes())
	if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("forwarder failed: %v", err)
	}
	if len(chunks) != 1 || string(chunks[0]) != "RFB" {
		t.Fatalf("expected only the binary message %q at the backend, got %q", "RFB", chunks)
	}
}
