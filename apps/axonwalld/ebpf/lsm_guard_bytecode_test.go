package ebpf

import (
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
)

func assertNoBpfNegInCollectionSpec(t *testing.T, source string, spec *ebpf.CollectionSpec) {
	t.Helper()

	wantProgs := []string{
		LsmGuardProgCopyfailGuard,
		LsmGuardProgRestrictBpfLoad,
		LsmGuardProgBlockUringSqpoll,
		LsmGuardProgGuardBpfTokenCreate,
		LsmGuardProgAuditBpfTokenCmd,
	}
	for _, progName := range wantProgs {
		if _, ok := spec.Programs[progName]; !ok {
			t.Fatalf("%s: missing expected BPF-LSM program %q", source, progName)
		}
	}

	for progName, progSpec := range spec.Programs {
		if progSpec == nil {
			t.Fatalf("%s: nil ProgramSpec for %q", source, progName)
		}
		if len(progSpec.Instructions) == 0 {
			t.Fatalf("%s: program %q has 0 instructions", source, progName)
		}
		for idx, ins := range progSpec.Instructions {
			rawOp := byte(ins.OpCode & 0xff)
			isNeg32 := ins.OpCode.Class() == asm.ALUClass && rawOp == 0x84
			isNeg64 := ins.OpCode.Class() == asm.ALU64Class && rawOp == 0x87
			if ins.OpCode == 0x84 || ins.OpCode == 0x87 || isNeg32 || isNeg64 || ins.OpCode.ALUOp() == asm.Neg {
				t.Errorf("%s: program %q instruction %d uses forbidden BPF_NEG opcode 0x%02x (%v)",
					source, progName, idx, rawOp, ins)
			}
		}
	}
}

func TestLsmGuardBytecodeHasNoBpfNeg(t *testing.T) {
	fileSpec, err := ebpf.LoadCollectionSpec("lsmguard_bpfel.o")
	if err != nil {
		t.Fatalf("ebpf.LoadCollectionSpec(lsmguard_bpfel.o) failed: %v", err)
	}
	assertNoBpfNegInCollectionSpec(t, "lsmguard_bpfel.o", fileSpec)

	embeddedSpec, err := LoadLsmGuard()
	if err != nil {
		t.Fatalf("LoadLsmGuard() failed: %v", err)
	}
	assertNoBpfNegInCollectionSpec(t, "embedded LoadLsmGuard()", embeddedSpec)
}
