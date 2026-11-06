package ebpf

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -no-strip -target bpfel -cc clang FlowTracker flow_tracker.c -- -I/usr/include/bpf -I/usr/include/aarch64-linux-gnu -I/usr/include/x86_64-linux-gnu
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -no-strip -target bpfel -cc clang -type lsm_exe_id -type lsm_event LsmGuard lsm_guard.c -- -I/usr/include/bpf -I/usr/include/aarch64-linux-gnu -I/usr/include/x86_64-linux-gnu
