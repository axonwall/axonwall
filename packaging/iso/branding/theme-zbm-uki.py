#!/usr/bin/env python3
"""
Axonwall ZFSBootMenu Unified Kernel Image (UKI) Themer & Assembler
==================================================================
Embeds branded 24-bit uncompressed BMP splash screen, custom kernel
command line parameters, and early-boot visual theme + watchdog hooks
directly into ZFSBootMenu UEFI executable binaries (UKI) and Legacy BIOS
Syslinux kernel/initramfs pairs.

Conforms to UEFI systemd-stub specification and ZFSBootMenu generate-zbm
section layout (.osrel, .cmdline, .splash, .initrd, .linux).
"""

from __future__ import annotations

import argparse
import os
import shutil
import struct
import subprocess
import tempfile

CPIO_MAGIC_INO = 0x41584F4E  # "AXON" in ASCII hex -> 07070141584f4e
CPIO_SIGNATURE = b"07070141584f4e"

DEFAULT_THEME_HOOK = r"""#!/bin/bash
# ==============================================================================
# Axonwall ZFSBootMenu Visual Theme & Console Styling Hook
# Runs in early-setup.d AFTER 20-dracut-console-init.sh & 30-console-autosize.sh
# ==============================================================================

TERM_DEV="${control_term:-/dev/tty1}"
case "$TERM_DEV" in
  /dev/tty[0-9]*) ;;
  *) TERM_DEV="/dev/tty1" ;;
esac
[ -c "$TERM_DEV" ] || TERM_DEV="/dev/tty0"

if [ -c "$TERM_DEV" ]; then
  # 0=Black(bg), 1=Red, 2=Green, 3=Yellow, 4=Blue, 5=Magenta, 6=Cyan, 7=White(fg)
  # 8=BrBlack, 9=BrRed, A=BrGreen, B=BrYellow, C=BrBlue, D=BrMagenta, E=BrCyan, F=BrWhite
  printf '\033]P0090e1a\033]P1f43f5e\033]P210b981\033]P3f59e0b\033]P40284c7\033]P58b5cf6\033]P606b6d4\033]P7cbd5e1\033]P81e293b\033]P9fb7185\033]PA34d399\033]PBfbbf24\033]PC38bdf8\033]PDa78bfa\033]PE22d3ee\033]PFf8fafc' > "$TERM_DEV" 2>/dev/null || true
  printf '\033[2J\033[H' > "$TERM_DEV" 2>/dev/null || true
fi

for fzf_cfg in /lib/fzf-defaults.sh /usr/lib/fzf-defaults.sh; do
  if [ -f "$fzf_cfg" ] && ! grep -q "AXONWALL_FZF_THEME" "$fzf_cfg" 2>/dev/null; then
    cat << 'FZF_EOF' >> "$fzf_cfg"

# AXONWALL_FZF_THEME
fuzzy_default_options+=(
  "--color=border:cyan,label:bright-cyan,preview-label:bright-green,current-fg:bright-green,selected-fg:bright-cyan,prompt:bright-green,pointer:bright-green,marker:bright-green,header:cyan,info:bright-blue,spinner:bright-green,hl:bright-green,hl+:bright-cyan"
)
export FZF_DEFAULT_OPTS="${fuzzy_default_options[*]}"
FZF_EOF
  fi
done

exit 0
"""

DEFAULT_INIT_STAGE_45 = r"""#!/bin/bash
# ==============================================================================
# Axonwall ZFSBootMenu Init Stage 45: Branded Countdown & Console Palette
# Sourced directly by /libexec/zfsbootmenu-init after 40-early-hooks
# ==============================================================================

[ "${ZFSBOOTMENU_INITIALIZATION}" = "yes" ] || return 0

if [ -x /libexec/hooks/early-setup.d/90-axonwall-theme.sh.completed ]; then
  sh /libexec/hooks/early-setup.d/90-axonwall-theme.sh.completed 2>/dev/null || true
elif [ -x /libexec/hooks/early-setup.d/90-axonwall-theme.sh ]; then
  sh /libexec/hooks/early-setup.d/90-axonwall-theme.sh 2>/dev/null || true
fi

# Inject Axonwall Cyber-Emerald ASCII banner into timed_prompt countdown screen
if declare -f timed_prompt >/dev/null 2>&1 && [ -z "${_AXONWALL_TIMED_PROMPT_WRAPPED:-}" ]; then
  readonly _AXONWALL_TIMED_PROMPT_WRAPPED=1
  eval "_orig_$(declare -f timed_prompt)"
  timed_prompt() {
    local _has_banner=0
    local _arg
    for _arg in "$@"; do
      if [ "$_arg" = "boot now " ]; then
        _has_banner=1
        break
      fi
    done
    if [ "$_has_banner" -eq 1 ]; then
      _orig_timed_prompt \
        -m "$( colorize lightgreen "   ___   _  ______  _  ___      _____   __   __ " )" \
        -m "$( colorize lightgreen "  / _ | | |/_/ __ \/ |/ / | /| / / _ | / /  / / " )" \
        -m "$( colorize cyan       " / __ |_>  </ /_/ /    /| |/ |/ / __ |/ /__/ /__" )" \
        -m "$( colorize cyan       "/_/ |_/_/|_|\____/_/|_/ |__/|__/_/ |_/____/____/" )" \
        -m "" \
        -m "$( colorize lightgray  "Next-Gen Firewall & Root-on-ZFS Boot Manager" )" \
        -m "$( colorize darkgray   "================================================" )" \
        -m "" \
        "$@"
      return $?
    else
      _orig_timed_prompt "$@"
      return $?
    fi
  }
fi
"""

DEFAULT_INIT_STAGE_60 = r"""#!/bin/bash
# ==============================================================================
# Axonwall ZFSBootMenu Init Stage 60: Pre-Boot Autonomous Watchdog
# Sourced by /libexec/zfsbootmenu-init after 50-import-pools on every boot
# ==============================================================================

[ "${ZFSBOOTMENU_INITIALIZATION}" = "yes" ] || return 0

if [ ! -e "${BASE:-/zfsbootmenu}/axonwall_watchdog_ran" ]; then
  : > "${BASE:-/zfsbootmenu}/axonwall_watchdog_ran"
  if [ -x /libexec/hooks/setup.d/20-axonwall-watchdog.sh ]; then
    /libexec/hooks/setup.d/20-axonwall-watchdog.sh >/dev/null 2>&1 || true
    # Refresh BOOTFS if watchdog rolled back zroot bootfs property
    _new_bootfs="$(zpool get -H -o value bootfs zroot 2>/dev/null || true)"
    if [ -n "$_new_bootfs" ] && [ "$_new_bootfs" != "-" ]; then
      BOOTFS="$_new_bootfs"
      export BOOTFS
      echo "$BOOTFS" > "${BASE:-/zfsbootmenu}/bootfs" 2>/dev/null || true
    fi
  fi
fi
"""

DEFAULT_WATCHDOG_HOOK = r"""#!/bin/sh
# ZFSBootMenu v3.1.x Pre-Boot Autonomous Watchdog Hook for Axonwall Root-on-ZFS
# Located at /etc/zfsbootmenu/hooks/setup.d/20-axonwall-watchdog.sh

POOL="zroot"
PARENT="${POOL}/ROOT"

if ! zpool list "$POOL" >/dev/null 2>&1; then
  zpool import -N -o readonly=off "$POOL" 2>/dev/null || exit 0
fi

ACTIVE_BE="$(zfs get -H -o value org.axonwall:active_be "$PARENT" 2>/dev/null || echo "-")"
FALLBACK_BE="$(zfs get -H -o value org.axonwall:fallback_be "$PARENT" 2>/dev/null || echo "-")"
BOOTCOUNT_RAW="$(zfs get -H -o value org.axonwall:bootcount "$PARENT" 2>/dev/null || echo "0")"
BOOTLIMIT_RAW="$(zfs get -H -o value org.axonwall:bootlimit "$PARENT" 2>/dev/null || echo "3")"

[ "$ACTIVE_BE" = "-" ] && ACTIVE_BE=""
[ "$FALLBACK_BE" = "-" ] && FALLBACK_BE=""
BOOTCOUNT=$(echo "$BOOTCOUNT_RAW" | tr -cd '0-9')
[ -z "$BOOTCOUNT" ] && BOOTCOUNT=0
BOOTLIMIT=$(echo "$BOOTLIMIT_RAW" | tr -cd '0-9')
[ -z "$BOOTLIMIT" ] || [ "$BOOTLIMIT" -le 0 ] && BOOTLIMIT=3

if [ -n "$ACTIVE_BE" ] && [ -n "$FALLBACK_BE" ] && [ "$ACTIVE_BE" != "$FALLBACK_BE" ]; then
  # Ensure pool is writable if ZBM imported it readonly=on
  RO_STATE="$(zpool get -H -o value readonly "$POOL" 2>/dev/null || echo "off")"
  if [ "$RO_STATE" = "on" ]; then
    zpool export "$POOL" 2>/dev/null || true
    zpool import -N -o readonly=off "$POOL" 2>/dev/null || exit 0
  fi

  if [ "$BOOTCOUNT" -ge "$BOOTLIMIT" ]; then
    zpool set bootfs="${FALLBACK_BE}" "$POOL" 2>/dev/null || true
    zfs set org.axonwall:bootcount=0 "$PARENT" 2>/dev/null || true
    zfs set org.axonwall:active_be="${FALLBACK_BE}" "$PARENT" 2>/dev/null || true
  else
    NEW_COUNT=$(( BOOTCOUNT + 1 ))
    zfs set org.axonwall:bootcount="${NEW_COUNT}" "$PARENT" 2>/dev/null || true
  fi

  if [ "$RO_STATE" = "on" ]; then
    zpool export "$POOL" 2>/dev/null || true
    zpool import -N -o readonly=on "$POOL" 2>/dev/null || true
  fi
fi

exit 0
"""


def round_up(val: int, align: int) -> int:
    return ((val + align - 1) // align) * align


def _cpio_entry(name: str, data: bytes, mode: int, ino: int, nlink: int = 1) -> bytes:
    name_b = name.encode("ascii") + b"\x00"
    hdr = (
        f"070701"
        f"{ino:08x}"
        f"{mode:08x}"
        f"{0:08x}"
        f"{0:08x}"
        f"{nlink:08x}"
        f"{0:08x}"
        f"{len(data):08x}"
        f"{3:08x}"
        f"{1:08x}"
        f"{0:08x}"
        f"{0:08x}"
        f"{len(name_b):08x}"
        f"{0:08x}"
    ).encode("ascii")
    out = bytearray(hdr) + name_b
    pad_hdr = (4 - (len(out) % 4)) % 4
    out.extend(b"\x00" * pad_hdr)
    out.extend(data)
    pad_data = (4 - (len(data) % 4)) % 4
    out.extend(b"\x00" * pad_data)
    return bytes(out)


def build_hooks_cpio(theme_hook_bytes: bytes, watchdog_hook_bytes: bytes) -> bytes:
    """Build an uncompressed SVR4 newc cpio archive starting with signature 07070141584f4e."""
    ino = CPIO_MAGIC_INO
    chunks: list[bytes] = []
    for dname in [
        "libexec",
        "libexec/hooks",
        "libexec/hooks/early-setup.d",
        "libexec/hooks/setup.d",
        "libexec/init.d",
    ]:
        chunks.append(_cpio_entry(dname, b"", 0o040755, ino, nlink=2))
        ino += 1

    chunks.append(
        _cpio_entry(
            "libexec/hooks/early-setup.d/90-axonwall-theme.sh",
            theme_hook_bytes,
            0o100755,
            ino,
        )
    )
    ino += 1
    chunks.append(
        _cpio_entry(
            "libexec/hooks/setup.d/20-axonwall-watchdog.sh",
            watchdog_hook_bytes,
            0o100755,
            ino,
        )
    )
    ino += 1
    chunks.append(
        _cpio_entry(
            "libexec/init.d/45-axonwall-theme",
            DEFAULT_INIT_STAGE_45.encode("utf-8"),
            0o100755,
            ino,
        )
    )
    ino += 1
    chunks.append(
        _cpio_entry(
            "libexec/init.d/60-axonwall-watchdog",
            DEFAULT_INIT_STAGE_60.encode("utf-8"),
            0o100755,
            ino,
        )
    )
    ino += 1
    chunks.append(_cpio_entry("TRAILER!!!", b"", 0, ino, nlink=1))

    raw = b"".join(chunks)
    pad = (512 - (len(raw) % 512)) % 512
    return raw + (b"\x00" * pad)


def inject_hooks_into_initrd(initrd_path: str, hooks_dir: str | None = None) -> None:
    """Idempotently strip any previous Axonwall cpio overlay and append fresh hooks cpio."""
    with open(initrd_path, "rb") as f:
        data = f.read()

    sig_idx = data.find(CPIO_SIGNATURE)
    if sig_idx != -1:
        data = data[:sig_idx]

    # Strip trailing FileAlignment NUL padding from previous PE extraction
    data = data.rstrip(b"\x00")
    pad4 = (4 - (len(data) % 4)) % 4
    data = data + (b"\x00" * pad4)

    base_hooks = hooks_dir or "/etc/zfsbootmenu/hooks"
    theme_bytes = DEFAULT_THEME_HOOK.encode("utf-8")
    for cand in [
        os.path.join(base_hooks, "early-setup.d/90-axonwall-theme.sh"),
        os.path.join(base_hooks, "early-setup.d/15-axonwall-theme.sh"),
    ]:
        if os.path.isfile(cand):
            with open(cand, "rb") as f:
                raw_h = f.read()
            if b"AXONWALL_FZF_THEME" in raw_h:
                theme_bytes = raw_h
                break

    watchdog_bytes = DEFAULT_WATCHDOG_HOOK.encode("utf-8")
    cand_wd = os.path.join(base_hooks, "setup.d/20-axonwall-watchdog.sh")
    if os.path.isfile(cand_wd):
        with open(cand_wd, "rb") as f:
            raw_w = f.read()
        if b"RO_STATE" in raw_w:
            watchdog_bytes = raw_w

    overlay = build_hooks_cpio(theme_bytes, watchdog_bytes)
    with open(initrd_path, "wb") as f:
        f.write(data + overlay)


def get_stub_info(stub_path: str) -> tuple[int, int]:
    """Retrieve SectionAlignment and ending VMA of the base UEFI stub."""
    out_p = subprocess.check_output(["objdump", "-p", stub_path], text=True)
    align = 4096
    for line in out_p.splitlines():
        if "SectionAlignment" in line:
            parts = line.split()
            if len(parts) >= 2:
                align = int(parts[1], 16)
                break

    out_h = subprocess.check_output(["objdump", "-h", stub_path], text=True)
    max_end = 0
    for line in out_h.splitlines():
        parts = line.split()
        if len(parts) >= 5 and parts[0].isdigit():
            size = int(parts[2], 16)
            vma = int(parts[3], 16)
            if vma + size > max_end:
                max_end = vma + size

    start_offset = round_up(max_end, align)
    return align, start_offset


def verify_and_fix_pe_headers(efi_path: str, section_sizes: dict[str, int]) -> None:
    """
    Ensure PE32+ section headers for added UKI payload sections have valid
    VirtualSize, SizeOfRawData, and Characteristics (0x40000040: INITIALIZED_DATA | MEM_READ).
    Protects against binutils objcopy variations that leave SizeOfRawData=0.
    """
    with open(efi_path, "r+b") as f:
        buf = bytearray(f.read())
        pe_off = struct.unpack_from("<I", buf, 0x3C)[0]
        num_sec = struct.unpack_from("<H", buf, pe_off + 6)[0]
        opt_hdr_size = struct.unpack_from("<H", buf, pe_off + 20)[0]
        file_align = struct.unpack_from("<I", buf, pe_off + 24 + 36)[0] or 512
        sec_align = struct.unpack_from("<I", buf, pe_off + 24 + 32)[0] or 4096
        sec_table_off = pe_off + 24 + opt_hdr_size

        modified = False
        max_vma_end = 0
        for i in range(num_sec):
            off = sec_table_off + i * 40
            name = buf[off : off + 8].rstrip(b"\x00").decode("ascii", "replace")
            vsize, vaddr, rawsize, rawptr, relptr, linenoptr, nrel, nline, chars = (
                struct.unpack_from("<IIIIIIHHI", buf, off + 8)
            )
            if name in section_sizes:
                true_sz = section_sizes[name]
                aligned_raw = round_up(true_sz, file_align)
                target_chars = 0x40000040  # IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ
                if vsize == 0 or vsize > aligned_raw:
                    vsize = true_sz
                    modified = True
                if rawsize != aligned_raw:
                    rawsize = aligned_raw
                    modified = True
                if chars != target_chars:
                    chars = target_chars
                    modified = True
                struct.pack_into(
                    "<IIIIIIHHI",
                    buf,
                    off + 8,
                    vsize,
                    vaddr,
                    rawsize,
                    rawptr,
                    relptr,
                    linenoptr,
                    nrel,
                    nline,
                    chars,
                )
            v_end = round_up(vaddr + max(vsize, rawsize), sec_align)
            if v_end > max_vma_end:
                max_vma_end = v_end

        if max_vma_end > 0:
            cur_size_of_image = struct.unpack_from("<I", buf, pe_off + 24 + 56)[0]
            if cur_size_of_image != max_vma_end:
                struct.pack_into("<I", buf, pe_off + 24 + 56, max_vma_end)
                modified = True

        if modified:
            f.seek(0)
            f.write(buf)
            f.truncate()


def normalize_zbm_cmdline(raw_cmd: str, font: str | None = None) -> str:
    """
    Normalize ZFSBootMenu kernel command line:
    - Ensure console=tty1 is ALWAYS the final console= parameter so ZBM sets control_term=/dev/tty1
    - Avoid forcing invalid rd.vconsole.font=ter-132b by default so 30-console-autosize.sh works
    """
    tokens = [t for t in raw_cmd.split() if not t.startswith("console=")]
    tokens = ["zbm.timeout=5" if t.startswith("zbm.timeout=") else t for t in tokens]
    if font and font not in ("auto", "default", "ter-132b"):
        tokens = [t for t in tokens if not t.startswith("rd.vconsole.font=")]
        tokens.append(f"rd.vconsole.font={font}")
    elif font in ("auto", "default", "ter-132b", None):
        tokens = [t for t in tokens if not t.startswith("rd.vconsole.font=")]

    required = [
        "zbm.timeout=5",
        "zbm.autosize=1",
        "zbm.hookroot=LABEL=AXON_EFI//EFI/ZBM/hooks",
    ]
    for req in required:
        key = req.split("=")[0]
        if not any(p.startswith(f"{key}=") or p == key for p in tokens):
            tokens.append(req)

    # Critical: console=tty1 MUST come AFTER console=ttyS0 so ZFSBootMenu sets control_term=/dev/tty1
    tokens.append("console=ttyS0,115200")
    tokens.append("console=tty1")
    return " ".join(tokens)


def extract_clean_section(efi_path: str, sec_name: str, out_path: str) -> None:
    """Extract a PE section using its exact VirtualSize (stripping FileAlignment NUL padding)."""
    with open(efi_path, "rb") as f:
        buf = f.read()
    pe_off = struct.unpack_from("<I", buf, 0x3C)[0]
    num_sec = struct.unpack_from("<H", buf, pe_off + 6)[0]
    opt_hdr_size = struct.unpack_from("<H", buf, pe_off + 20)[0]
    sec_table_off = pe_off + 24 + opt_hdr_size
    for i in range(num_sec):
        off = sec_table_off + i * 40
        name = buf[off : off + 8].rstrip(b"\x00").decode("ascii", "replace")
        if name == sec_name:
            vsize, _vaddr, rawsize, rawptr = struct.unpack_from("<IIII", buf, off + 8)
            length = vsize if (0 < vsize <= rawsize or rawsize == 0) else rawsize
            with open(out_path, "wb") as out_f:
                out_f.write(buf[rawptr : rawptr + length])
            return
    subprocess.run(["objcopy", "--dump-section", f"{sec_name}={out_path}", efi_path], check=True)


def theme_zbm_uki(
    in_efi: str,
    out_efi: str,
    splash_bmp: str | None = None,
    cmdline_str: str | None = None,
    font: str | None = None,
    extract_linux: str | None = None,
    extract_initrd: str | None = None,
    hooks_dir: str | None = None,
) -> None:
    if not os.path.isfile(in_efi):
        raise FileNotFoundError(f"Input EFI file not found: {in_efi}")

    with tempfile.TemporaryDirectory(prefix="zbm-theme-") as tmpdir:
        osrel_path = os.path.join(tmpdir, "osrel")
        cmdline_path = os.path.join(tmpdir, "cmdline")
        initrd_path = os.path.join(tmpdir, "initrd")
        linux_path = os.path.join(tmpdir, "linux")
        stub_path = os.path.join(tmpdir, "stub.efi")

        # 1. Extract payload sections from input UKI
        extract_clean_section(in_efi, ".osrel", osrel_path)
        extract_clean_section(in_efi, ".initrd", initrd_path)
        extract_clean_section(in_efi, ".linux", linux_path)

        # Strip trailing NULs from linux bzImage if padded by prior objcopy
        with open(linux_path, "rb") as f:
            linux_data = f.read()
        if len(linux_data) > 0x200:
            # bzImage SizeOfImage is in PE header of the kernel itself
            k_pe_off = struct.unpack_from("<I", linux_data, 0x3C)[0]
            if k_pe_off + 24 + 60 < len(linux_data) and linux_data[k_pe_off : k_pe_off + 4] == b"PE\x00\x00":
                k_num_sec = struct.unpack_from("<H", linux_data, k_pe_off + 6)[0]
                k_opt_sz = struct.unpack_from("<H", linux_data, k_pe_off + 20)[0]
                k_sec_off = k_pe_off + 24 + k_opt_sz
                max_raw_end = 0
                for i in range(k_num_sec):
                    s_off = k_sec_off + i * 40
                    _vs, _va, r_sz, r_ptr = struct.unpack_from("<IIII", linux_data, s_off + 8)
                    if r_ptr + r_sz > max_raw_end:
                        max_raw_end = r_ptr + r_sz
                if 0 < max_raw_end < len(linux_data):
                    with open(linux_path, "wb") as f:
                        f.write(linux_data[:max_raw_end])

        # 2. Inject Axonwall theme and watchdog hooks directly into initramfs
        inject_hooks_into_initrd(initrd_path, hooks_dir=hooks_dir)

        # 3. Determine command-line to embed
        if cmdline_str is None:
            try:
                extract_clean_section(in_efi, ".cmdline", cmdline_path)
                with open(cmdline_path, "rb") as f:
                    raw_cmd = f.read().decode("ascii", "ignore").strip("\x00 \r\n")
            except Exception:
                raw_cmd = "ro quiet loglevel=3 net.ifnames=0"
            cmdline_str = normalize_zbm_cmdline(raw_cmd, font=font)
        else:
            cmdline_str = normalize_zbm_cmdline(cmdline_str, font=font)

        with open(cmdline_path, "wb") as f:
            f.write(cmdline_str.strip().encode("ascii") + b"\x00")

        # 4. Strip payload sections to leave the pure systemd-boot stub
        shutil.copyfile(in_efi, stub_path)
        for sec in [".linux", ".initrd", ".cmdline", ".osrel", ".splash"]:
            subprocess.run(
                ["objcopy", "--remove-section", sec, stub_path],
                stderr=subprocess.DEVNULL,
            )

        # 5. Read stub alignment and compute start VMA
        align, curr_offset = get_stub_info(stub_path)

        # 6. Build section sequence: .osrel, .cmdline, [.splash], .initrd, .linux
        sections: list[tuple[str, str]] = [
            (".osrel", osrel_path),
            (".cmdline", cmdline_path),
        ]
        if splash_bmp and os.path.isfile(splash_bmp):
            sections.append((".splash", splash_bmp))
        sections.append((".initrd", initrd_path))
        sections.append((".linux", linux_path))

        section_sizes: dict[str, int] = {}
        cmd = ["objcopy"]
        for name, path in sections:
            sz = os.path.getsize(path)
            section_sizes[name] = sz
            cmd.extend(["--add-section", f"{name}={path}"])
            cmd.extend(["--change-section-vma", f"{name}=0x{curr_offset:x}"])
            cmd.extend(["--set-section-flags", f"{name}=contents,alloc,load,readonly,data"])
            curr_offset = round_up(curr_offset + sz, align)

        out_abs = os.path.abspath(out_efi)
        os.makedirs(os.path.dirname(out_abs), exist_ok=True)
        out_tmp = os.path.join(tmpdir, "out.efi")
        cmd.extend([stub_path, out_tmp])
        subprocess.run(cmd, check=True)

        verify_and_fix_pe_headers(out_tmp, section_sizes)
        shutil.move(out_tmp, out_abs)

        # Also update companion Legacy BIOS Syslinux kernel/initramfs if requested or present in same dir
        out_dir = os.path.dirname(out_abs)
        bios_linux = extract_linux or os.path.join(out_dir, "vmlinuz-bootmenu")
        bios_initrd = extract_initrd or os.path.join(out_dir, "initramfs-bootmenu.img")
        if extract_linux or os.path.exists(bios_linux):
            shutil.copyfile(linux_path, bios_linux)
        if extract_initrd or os.path.exists(bios_initrd):
            shutil.copyfile(initrd_path, bios_initrd)

        print(f"[✓] Successfully themed ZBM UKI -> {out_efi} ({os.path.getsize(out_abs):,} bytes)")


def main() -> int:
    parser = argparse.ArgumentParser(description="Theme ZFSBootMenu Unified Kernel Image (UKI)")
    parser.add_argument("input", help="Source ZFSBootMenu .EFI UKI image")
    parser.add_argument("-o", "--output", required=True, help="Destination themed .EFI binary")
    parser.add_argument("-s", "--splash", help="Path to 24-bit uncompressed BMP splash image")
    parser.add_argument("-c", "--cmdline", help="Override kernel command line string")
    parser.add_argument("-f", "--font", default="auto", help="Console font face (default: auto)")
    parser.add_argument("--extract-linux", help="Also write extracted .linux bzImage to this path")
    parser.add_argument("--extract-initrd", help="Also write themed .initrd image to this path")
    parser.add_argument("--hooks-dir", help="Optional path to ZFSBootMenu hooks directory")

    args = parser.parse_args()

    theme_zbm_uki(
        in_efi=args.input,
        out_efi=args.output,
        splash_bmp=args.splash,
        cmdline_str=args.cmdline,
        font=args.font,
        extract_linux=args.extract_linux,
        extract_initrd=args.extract_initrd,
        hooks_dir=args.hooks_dir,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
