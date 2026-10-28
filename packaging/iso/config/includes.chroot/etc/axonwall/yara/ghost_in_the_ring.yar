// =============================================================================
// Axonwall Ghost-in-the-Ring YARA Rule Pack
// Targets: TripleCross, Boopkit, Symbiote, BPFDoor, Curing, RingReaper
// =============================================================================

rule Linux_eBPF_Rootkit_TripleCross_Boopkit {
    meta:
        author = "Axonwall Security Engineering"
        severity = "CRITICAL"
        description = "Detects offensive eBPF rootkits abusing bpf_probe_write_user (#36) and getdents64/sys_bpf hooks"
    strings:
        $h1 = "bpf_probe_write_user" ascii
        $h2 = "bpf_override_return" ascii
        $s1 = "tp/syscalls/sys_exit_getdents64" ascii
        $s2 = "fexit/__x64_sys_bpf" ascii
        $s3 = "TripleCross" ascii nocase
        $s4 = "boopkit" ascii nocase
    condition:
        uint32(0) == 0x464c457f and ((1 of ($h*) and 1 of ($s*)) or 2 of ($s*))
}

rule Linux_IoUring_Implant_Curing_RingReaper {
    meta:
        author = "Axonwall Security Engineering"
        severity = "CRITICAL"
        description = "Detects syscall-less io_uring implants (Curing / RingReaper) utilizing SQPOLL and FIXED_FILE"
    strings:
        $u1 = "io_uring_queue_init_params" ascii
        $u2 = "io_uring_register_files" ascii
        $u3 = "anon_inode:[io_uring]" ascii
        $c1 = "RingReaper" ascii nocase
        $c2 = "IORING_SETUP_SQPOLL" ascii
    condition:
        uint32(0) == 0x464c457f and (all of ($u1, $u2) or 1 of ($c*) or ($u1 and $u3))
}

rule Linux_Stealth_Backdoor_BPFDoor_Symbiote {
    meta:
        author = "Axonwall Security Engineering"
        severity = "CRITICAL"
        description = "Detects BPFDoor classic/eBPF magic packet filters and Symbiote LD_PRELOAD/BPF hooks"
    strings:
        $b1 = { 72 55 00 00 }
        $b2 = "hald-addon-acpi" ascii
        $b3 = "HIDE_THIS_SHELL" ascii
        $b4 = "symbiote" ascii nocase
    condition:
        uint32(0) == 0x464c457f and 1 of ($b*)
}
