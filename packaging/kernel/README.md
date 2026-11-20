# Axonwall Hardened Linux Kernel System

Axonwall ships two complementary kernel build profiles based on **Linux 6.12 LTS**:

1. **Universal Hardened (`--mode universal`)** — Equivalent in hardware breadth to Debian 13 (`linux-image-amd64`), layered with Kernel Self-Protection Project (KSPP) memory/allocator/control-flow mitigations, Integrity Lockdown LSM (`integrity`, not `confidentiality`), `BPF_UNPRIV_DEFAULT_OFF`, CO-RE `BTF` + `BPF_LSM`, `nftables` fastpath flowtable offload, `K3s`/`containerd` namespaces & cgroups v2, and OpenZFS exported symbol preservation (`CONFIG_TRIM_UNUSED_KSYMS=n`).
2. **Hardware-Locked Stripped (`--mode stripped`)** — Uses host `/proc/modules` (`make localmodconfig`) plus detected PCIe/NVMe/NIC/TPM/Watchdog fragments and `06-strip-desktop-bloat.config` to strip >90% of unused drivers (audio, wireless, Bluetooth, DRM GPUs, FireWire, legacy serial/FDDI/ISDN).

## Design Rationale (Why Not Desktop `linux-hardened`)
Desktop-targeted `linux-hardened` kernels disable unprivileged user namespaces (`CONFIG_USER_NS` / `kernel.unprivileged_userns_clone=0`), restrict overlay filesystems, or force Lockdown `confidentiality`, breaking rootless containers, K3s, Cilium/Falco eBPF `bpf_probe_read_kernel()`, and external OpenZFS DKMS builds. Axonwall adopts **Talos Linux + Fedora CoreOS/Flatcar + Alpine `linux-virt`** server hardening principles instead.

## Quick Usage
```bash
# 1. Deterministic config-only export (no compilation)
./packaging/kernel/build-kernel.sh --mode config-only --output-dir /tmp/kout

# 2. Universal Debian-equivalent hardened .deb build
./packaging/kernel/build-kernel.sh --mode universal

# 3. Hardware-stripped .deb build from host lsmod + fragment
./packaging/kernel/build-kernel.sh \
  --mode stripped \
  --lsmod-file /proc/modules \
  --hardware-fragment /tmp/host-hardware.config \
  --march x86-64-v3
```

## Cross-compiling for arm64

`--arch arm64` on an x86_64 host cross-compiles with
`CROSS_COMPILE=aarch64-linux-gnu-` (the same pattern as
`build-edge-uki.sh`). The builder fails fast if the cross toolchain is
absent — install it first (`apt-get install -y gcc-aarch64-linux-gnu`).
On a native aarch64 host no cross toolchain is needed.

## `--march native` is refused

`--march native` produces a kernel locked to the build host's CPU, and
`build-iso.sh` stages any built kernel `.deb` into every ISO — a
`native` build would ship an image that faults with illegal
instructions on older or different appliance CPUs. The builder refuses
`native` outright (R4-D-M3); use a named, auditable baseline instead
(`x86-64-v3` is the stripped-mode default). As a second line of
defence, `build-iso.sh` also refuses to stage a kernel `.deb` whose
`build-manifest.json` records `"march": "native"` (e.g. one built by an
older builder version).

## Build Prerequisites (Debian 13 Trixie)
```bash
apt-get update && apt-get install -y \
  build-essential bc flex bison dwarves libssl-dev libelf-dev \
  debhelper dpkg-dev rsync cpio zstd xz-utils curl
```
