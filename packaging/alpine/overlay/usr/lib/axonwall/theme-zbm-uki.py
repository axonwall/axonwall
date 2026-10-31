#!/usr/bin/env python3
"""
Axonwall ZFSBootMenu Unified Kernel Image (UKI) Themer & Assembler
==================================================================
Embeds branded 24-bit uncompressed BMP splash screen and custom kernel
command line parameters (font, autosize, hookroot, console) directly into
ZFSBootMenu UEFI executable binaries (UKI) using objcopy.

Conforms to UEFI systemd-stub specification and ZFSBootMenu generate-zbm
section layout (.osrel, .cmdline, .splash, .initrd, .linux).
"""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
import tempfile


def round_up(val: int, align: int) -> int:
    return ((val + align - 1) // align) * align


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


def theme_zbm_uki(
    in_efi: str,
    out_efi: str,
    splash_bmp: str | None = None,
    cmdline_str: str | None = None,
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
        subprocess.run(["objcopy", "--dump-section", f".osrel={osrel_path}", in_efi], check=True)
        subprocess.run(["objcopy", "--dump-section", f".initrd={initrd_path}", in_efi], check=True)
        subprocess.run(["objcopy", "--dump-section", f".linux={linux_path}", in_efi], check=True)

        # 2. Determine command-line to embed
        if cmdline_str is None:
            # Try to read existing cmdline, or use default
            try:
                subprocess.run(
                    ["objcopy", "--dump-section", f".cmdline={cmdline_path}", in_efi],
                    check=True,
                    stderr=subprocess.DEVNULL,
                )
                with open(cmdline_path, "rb") as f:
                    raw_cmd = f.read().decode("ascii", "ignore").strip("\x00 \r\n")
            except Exception:
                raw_cmd = "ro quiet loglevel=3 net.ifnames=0"

            # Ensure Axonwall theme & hook parameters are present
            params = raw_cmd.split()
            required = [
                "rd.vconsole.font=ter-132b",
                "zbm.autosize=1",
                "zbm.hookroot=LABEL=AXON_EFI//EFI/ZBM/hooks",
                "console=tty0",
                "console=ttyS0,115200",
            ]
            for req in required:
                key = req.split("=")[0]
                if not any(p.startswith(f"{key}=") or p == key for p in params):
                    params.append(req)
            cmdline_str = " ".join(params)

        with open(cmdline_path, "wb") as f:
            f.write(cmdline_str.strip().encode("ascii") + b"\x00")

        # 3. Strip payload sections to leave the pure systemd-boot stub
        shutil.copyfile(in_efi, stub_path)
        for sec in [".linux", ".initrd", ".cmdline", ".osrel", ".splash"]:
            subprocess.run(
                ["objcopy", "--remove-section", sec, stub_path],
                stderr=subprocess.DEVNULL,
            )

        # 4. Read stub alignment and compute start VMA
        align, curr_offset = get_stub_info(stub_path)

        # 5. Build section sequence: .osrel, .cmdline, [.splash], .initrd, .linux
        sections: list[tuple[str, str]] = [
            (".osrel", osrel_path),
            (".cmdline", cmdline_path),
        ]
        if splash_bmp and os.path.isfile(splash_bmp):
            sections.append((".splash", splash_bmp))
        sections.append((".initrd", initrd_path))
        sections.append((".linux", linux_path))

        cmd = ["objcopy"]
        for name, path in sections:
            sz = os.path.getsize(path)
            cmd.extend(["--add-section", f"{name}={path}"])
            cmd.extend(["--change-section-vma", f"{name}=0x{curr_offset:x}"])
            cmd.extend(["--set-section-flags", f"{name}=alloc,readonly,data"])
            curr_offset = round_up(curr_offset + sz, align)

        os.makedirs(os.path.dirname(os.path.abspath(out_efi)), exist_ok=True)
        cmd.extend([stub_path, out_efi])
        subprocess.run(cmd, check=True)
        print(f"[✓] Successfully themed ZBM UKI -> {out_efi} ({os.path.getsize(out_efi):,} bytes)")


def main() -> int:
    parser = argparse.ArgumentParser(description="Theme ZFSBootMenu Unified Kernel Image (UKI)")
    parser.add_argument("input", help="Source ZFSBootMenu .EFI UKI image")
    parser.add_argument("-o", "--output", required=True, help="Destination themed .EFI binary")
    parser.add_argument("-s", "--splash", help="Path to 24-bit uncompressed BMP splash image")
    parser.add_argument("-c", "--cmdline", help="Override kernel command line string")
    parser.add_argument("-f", "--font", default="ter-132b", help="Console font face (default: ter-132b)")

    args = parser.parse_args()

    cmdline = args.cmdline
    if cmdline is None:
        cmdline = (
            f"ro quiet loglevel=3 net.ifnames=0 rd.vconsole.font={args.font} "
            "zbm.autosize=1 zbm.hookroot=LABEL=AXON_EFI//EFI/ZBM/hooks "
            "console=tty0 console=ttyS0,115200"
        )

    theme_zbm_uki(
        in_efi=args.input,
        out_efi=args.output,
        splash_bmp=args.splash,
        cmdline_str=cmdline,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
