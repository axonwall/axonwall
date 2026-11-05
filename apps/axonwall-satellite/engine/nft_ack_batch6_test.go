package engine

import (
	"encoding/binary"
	"syscall"
	"testing"
)

// A-L1 regression: the compiled nftables batch must request a kernel
// acknowledgement on its batch-end message, so ApplyNftBatchNetlink
// can wait for the kernel's verdict instead of assuming success.
// Pre-fix, no message in the batch carried NLM_F_ACK and the sender
// did a single non-blocking recv, so a batch the kernel rejected
// (bad rule, missing set/table) was recorded as applied and could
// later be confirmed into last-known-good.
//
// The kernel side of this was confirmed separately in the sandbox:
// a batch-end with NLM_F_ACK produces exactly one NLMSG_ERROR
// verdict datagram (errno 0 on success; here the sandbox lacks
// CAP_NET_ADMIN, so the verdict is EPERM — a permission failure,
// not a protocol failure). The miss itself is timing-dependent and
// was not reproducible against the instantly-failing sandbox
// batch, so a rejected real ruleset still needs live-box
// verification; the ack mechanics this test pins are the fix.
func TestBatch6SerializedBatchRequestsAck(t *testing.T) {
	batch := &NftCompiledBatch{TableName: "axonwall"}
	msgs := serializeNftBatch(batch)
	if len(msgs) < 2 {
		t.Fatalf("expected at least batch-begin and batch-end messages, got %d", len(msgs))
	}
	last := msgs[len(msgs)-1]
	if len(last) < 8 {
		t.Fatalf("batch-end message too short: %d bytes", len(last))
	}
	msgType := binary.NativeEndian.Uint16(last[4:6])
	flags := binary.NativeEndian.Uint16(last[6:8])
	if msgType != nfnlMsgBatchEnd {
		t.Fatalf("last message is not the batch end (type %d, expected %d)", msgType, nfnlMsgBatchEnd)
	}
	if flags&syscall.NLM_F_ACK == 0 {
		t.Fatalf("batch-end message does not request NLM_F_ACK (flags 0x%x); the kernel verdict would never be awaited", flags)
	}
	if flags&syscall.NLM_F_REQUEST == 0 {
		t.Fatalf("batch-end message lost NLM_F_REQUEST (flags 0x%x)", flags)
	}
}
