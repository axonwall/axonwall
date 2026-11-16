#!/usr/bin/env python3
"""
Axonwall Bootloader Splash Screen Generator (640x480 PNG)
=========================================================
Zero-dependency pure-Python vector/pixel renderer that generates the branded
BIOS (ISOLINUX vesamenu) and UEFI (GRUB2 gfxterm) 640x480 background splash
images for Axonwall Appliance ISOs:
  - splash.png       (Axonwall Enterprise Linux Next-Generation Firewall)
  - splash-vault.png (Axonwall Vault Immutable Backup & Storage Appliance)
"""

from __future__ import annotations

import math
import os
import struct
import sys
import zlib

WIDTH = 640
HEIGHT = 480

# Built-in 5x7 uppercase/symbol pixel font for crisp hardware-grade headers
FONT_5X7: dict[str, list[str]] = {
    "A": ["01110", "10001", "10001", "11111", "10001", "10001", "10001"],
    "B": ["11110", "10001", "10001", "11110", "10001", "10001", "11110"],
    "C": ["01111", "10000", "10000", "10000", "10000", "10000", "01111"],
    "D": ["11110", "10001", "10001", "10001", "10001", "10001", "11110"],
    "E": ["11111", "10000", "10000", "11110", "10000", "10000", "11111"],
    "F": ["11111", "10000", "10000", "11110", "10000", "10000", "10000"],
    "G": ["01111", "10000", "10000", "10011", "10001", "10001", "01111"],
    "H": ["10001", "10001", "10001", "11111", "10001", "10001", "10001"],
    "I": ["11111", "00100", "00100", "00100", "00100", "00100", "11111"],
    "J": ["00111", "00010", "00010", "00010", "10010", "10010", "01100"],
    "K": ["10001", "10010", "10100", "11000", "10100", "10010", "10001"],
    "L": ["10000", "10000", "10000", "10000", "10000", "10000", "11111"],
    "M": ["10001", "11011", "10101", "10101", "10001", "10001", "10001"],
    "N": ["10001", "11001", "10101", "10011", "10001", "10001", "10001"],
    "O": ["01110", "10001", "10001", "10001", "10001", "10001", "01110"],
    "P": ["11110", "10001", "10001", "11110", "10000", "10000", "10000"],
    "Q": ["01110", "10001", "10001", "10001", "10101", "10010", "01101"],
    "R": ["11110", "10001", "10001", "11110", "10100", "10010", "10001"],
    "S": ["01111", "10000", "10000", "01110", "00001", "00001", "11110"],
    "T": ["11111", "00100", "00100", "00100", "00100", "00100", "00100"],
    "U": ["10001", "10001", "10001", "10001", "10001", "10001", "01110"],
    "V": ["10001", "10001", "10001", "10001", "10001", "01010", "00100"],
    "W": ["10001", "10001", "10001", "10101", "10101", "11011", "10001"],
    "X": ["10001", "10001", "01010", "00100", "01010", "10001", "10001"],
    "Y": ["10001", "10001", "01010", "00100", "00100", "00100", "00100"],
    "Z": ["11111", "00010", "00100", "01000", "10000", "10000", "11111"],
    "0": ["01110", "10001", "10011", "10101", "11001", "10001", "01110"],
    "1": ["00100", "01100", "00100", "00100", "00100", "00100", "01110"],
    "2": ["01110", "10001", "00001", "00110", "01000", "10000", "11111"],
    "3": ["11110", "00001", "00001", "01110", "00001", "00001", "11110"],
    "4": ["00010", "00110", "01010", "10010", "11111", "00010", "00010"],
    "5": ["11111", "10000", "10000", "11110", "00001", "00001", "11110"],
    "6": ["01110", "10000", "10000", "11110", "10001", "10001", "01110"],
    "7": ["11111", "00001", "00010", "00100", "01000", "01000", "01000"],
    "8": ["01110", "10001", "10001", "01110", "10001", "10001", "01110"],
    "9": ["01110", "10001", "10001", "01111", "00001", "00001", "01110"],
    "-": ["00000", "00000", "00000", "11111", "00000", "00000", "00000"],
    ".": ["00000", "00000", "00000", "00000", "00000", "00110", "00110"],
    ":": ["00000", "00110", "00110", "00000", "00110", "00110", "00000"],
    "/": ["00001", "00010", "00100", "01000", "10000", "00000", "00000"],
    "+": ["00000", "00100", "00100", "11111", "00100", "00100", "00000"],
    "&": ["01100", "10010", "10100", "01000", "10101", "10010", "01101"],
    " ": ["00000", "00000", "00000", "00000", "00000", "00000", "00000"],
}


def lerp_color(c1: tuple[int, int, int], c2: tuple[int, int, int], t: float) -> tuple[int, int, int]:
    t = max(0.0, min(1.0, t))
    return (
        int(c1[0] + (c2[0] - c1[0]) * t),
        int(c1[1] + (c2[1] - c1[1]) * t),
        int(c1[2] + (c2[2] - c1[2]) * t),
    )


def blend_pixel(buf: bytearray, x: int, y: int, color: tuple[int, int, int], alpha: float) -> None:
    if x < 0 or x >= WIDTH or y < 0 or y >= HEIGHT or alpha <= 0.0:
        return
    if alpha >= 1.0:
        idx = (y * WIDTH + x) * 3
        buf[idx] = color[0]
        buf[idx + 1] = color[1]
        buf[idx + 2] = color[2]
        return
    idx = (y * WIDTH + x) * 3
    inv = 1.0 - alpha
    buf[idx] = int(buf[idx] * inv + color[0] * alpha)
    buf[idx + 1] = int(buf[idx + 1] * inv + color[1] * alpha)
    buf[idx + 2] = int(buf[idx + 2] * inv + color[2] * alpha)


def draw_line_aa(
    buf: bytearray,
    x0: float,
    y0: float,
    x1: float,
    y1: float,
    color: tuple[int, int, int],
    thickness: float = 1.8,
    alpha: float = 1.0,
) -> None:
    min_x = max(0, int(min(x0, x1) - thickness - 2))
    max_x = min(WIDTH - 1, int(max(x0, x1) + thickness + 2))
    min_y = max(0, int(min(y0, y1) - thickness - 2))
    max_y = min(HEIGHT - 1, int(max(y0, y1) + thickness + 2))
    dx = x1 - x0
    dy = y1 - y0
    len_sq = dx * dx + dy * dy
    half_t = thickness * 0.5
    for py in range(min_y, max_y + 1):
        for px in range(min_x, max_x + 1):
            if len_sq == 0.0:
                dist = math.hypot(px - x0, py - y0)
            else:
                t = max(0.0, min(1.0, ((px - x0) * dx + (py - y0) * dy) / len_sq))
                proj_x = x0 + t * dx
                proj_y = y0 + t * dy
                dist = math.hypot(px - proj_x, py - proj_y)
            if dist <= half_t + 1.0:
                cov = max(0.0, min(1.0, half_t + 0.5 - dist))
                blend_pixel(buf, px, py, color, cov * alpha)


def draw_circle_aa(
    buf: bytearray,
    cx: float,
    cy: float,
    radius: float,
    fill_color: tuple[int, int, int] | None,
    stroke_color: tuple[int, int, int] | None = None,
    stroke_width: float = 1.5,
    alpha: float = 1.0,
) -> None:
    r_outer = radius + (stroke_width * 0.5 if stroke_color else 0.0)
    min_x = max(0, int(cx - r_outer - 2))
    max_x = min(WIDTH - 1, int(cx + r_outer + 2))
    min_y = max(0, int(cy - r_outer - 2))
    max_y = min(HEIGHT - 1, int(cy + r_outer + 2))
    for py in range(min_y, max_y + 1):
        for px in range(min_x, max_x + 1):
            dist = math.hypot(px - cx, py - cy)
            if fill_color is not None and dist <= radius + 0.5:
                cov = max(0.0, min(1.0, radius + 0.5 - dist))
                blend_pixel(buf, px, py, fill_color, cov * alpha)
            if stroke_color is not None:
                sd = abs(dist - radius)
                if sd <= stroke_width * 0.5 + 0.5:
                    cov = max(0.0, min(1.0, stroke_width * 0.5 + 0.5 - sd))
                    blend_pixel(buf, px, py, stroke_color, cov * alpha)


def draw_rect(
    buf: bytearray,
    x0: int,
    y0: int,
    w: int,
    h: int,
    fill: tuple[int, int, int] | None,
    border: tuple[int, int, int] | None = None,
    fill_alpha: float = 1.0,
    border_alpha: float = 1.0,
) -> None:
    if fill is not None:
        for y in range(max(0, y0), min(HEIGHT, y0 + h)):
            for x in range(max(0, x0), min(WIDTH, x0 + w)):
                blend_pixel(buf, x, y, fill, fill_alpha)
    if border is not None:
        for x in range(max(0, x0), min(WIDTH, x0 + w)):
            blend_pixel(buf, x, y0, border, border_alpha)
            blend_pixel(buf, x, y0 + h - 1, border, border_alpha)
        for y in range(max(0, y0), min(HEIGHT, y0 + h)):
            blend_pixel(buf, x0, y, border, border_alpha)
            blend_pixel(buf, x0 + w - 1, y, border, border_alpha)


def draw_text(
    buf: bytearray,
    text: str,
    x: int,
    y: int,
    scale: int,
    color_fn,
    spacing: int = 1,
) -> int:
    cur_x = x
    for ch in text.upper():
        glyph = FONT_5X7.get(ch, FONT_5X7[" "])
        for row_idx, row in enumerate(glyph):
            for col_idx, bit in enumerate(row):
                if bit == "1":
                    c = color_fn(cur_x + col_idx * scale, y + row_idx * scale)
                    for sy in range(scale):
                        for sx in range(scale):
                            blend_pixel(buf, cur_x + col_idx * scale + sx, y + row_idx * scale + sy, c, 1.0)
        cur_x += (5 + spacing) * scale
    return cur_x


def draw_polygon_aa(
    buf: bytearray,
    points: list[tuple[float, float]],
    fill_color: tuple[int, int, int] | None,
    stroke_color: tuple[int, int, int] | None = None,
    stroke_width: float = 1.4,
    alpha: float = 1.0,
) -> None:
    if len(points) < 3:
        return
    if fill_color is not None:
        xs = [p[0] for p in points]
        ys = [p[1] for p in points]
        min_x = max(0, int(min(xs) - 1))
        max_x = min(WIDTH - 1, int(max(xs) + 1))
        min_y = max(0, int(min(ys) - 1))
        max_y = min(HEIGHT - 1, int(max(ys) + 1))
        n = len(points)
        for py in range(min_y, max_y + 1):
            cy = py + 0.5
            intersections: list[float] = []
            for i in range(n):
                x0, y0 = points[i]
                x1, y1 = points[(i + 1) % n]
                if (y0 <= cy < y1) or (y1 <= cy < y0):
                    t = (cy - y0) / (y1 - y0)
                    intersections.append(x0 + t * (x1 - x0))
            intersections.sort()
            for i in range(0, len(intersections) - 1, 2):
                lx = max(min_x, int(math.ceil(intersections[i] - 0.5)))
                rx = min(max_x, int(math.floor(intersections[i + 1] - 0.5)))
                for px in range(lx, rx + 1):
                    blend_pixel(buf, px, py, fill_color, alpha)
    if stroke_color is not None:
        n = len(points)
        for i in range(n):
            x0, y0 = points[i]
            x1, y1 = points[(i + 1) % n]
            draw_line_aa(buf, x0, y0, x1, y1, stroke_color, thickness=stroke_width, alpha=alpha)


def draw_brick_wall_pattern(
    buf: bytearray,
    primary: tuple[int, int, int],
    secondary: tuple[int, int, int],
) -> None:
    """Render subtle fortified dark basalt masonry brick courses across the backdrop."""
    brick_w = 48
    brick_h = 24
    for row in range((HEIGHT // brick_h) + 1):
        y0 = row * brick_h
        offset_x = (brick_w // 2) if (row % 2 == 1) else 0
        # Horizontal mortar joint
        if y0 > 0:
            for x in range(WIDTH):
                c = lerp_color((14, 24, 38), primary, 0.14 if x < WIDTH // 2 else 0.06)
                blend_pixel(buf, x, y0, c, 0.42)
                if y0 + 1 < HEIGHT:
                    blend_pixel(buf, x, y0 + 1, (6, 10, 18), 0.55)
        for col in range(-1, (WIDTH // brick_w) + 2):
            x0 = col * brick_w + offset_x
            # Subtle alternating brick shading
            shade_color = (16, 28, 44) if ((row + col) % 2 == 0) else (12, 20, 34)
            bx_start = max(0, x0 + 2)
            bx_end = min(WIDTH, x0 + brick_w - 1)
            by_start = max(0, y0 + 2)
            by_end = min(HEIGHT, y0 + brick_h)
            for py in range(by_start, by_end):
                for px in range(bx_start, bx_end):
                    blend_pixel(buf, px, py, shade_color, 0.22)
            # Vertical mortar joint
            if 0 <= x0 < WIDTH:
                c = lerp_color((14, 24, 38), secondary, 0.12)
                for py in range(max(0, y0 + 1), min(HEIGHT, y0 + brick_h)):
                    blend_pixel(buf, x0, py, c, 0.40)


def draw_shield_emblem(buf: bytearray, cx: float, cy: float, scale: float, accent_primary: tuple[int, int, int], accent_secondary: tuple[int, int, int]) -> None:
    def pt(nx: float, ny: float) -> tuple[float, float]:
        return (cx + (nx - 24.0) * scale, cy + (ny - 24.0) * scale)

    # 1. Back Layer: Fortified dark masonry brick crest patch & emerald/cyan radial backlight
    patch_r = 25.0 * scale
    for py in range(max(0, int(cy - patch_r)), min(HEIGHT, int(cy + patch_r))):
        for px in range(max(0, int(cx - patch_r)), min(WIDTH, int(cx + patch_r))):
            d = math.hypot(px - cx, py - cy)
            if d < patch_r:
                # Radial glow onto brick wall behind shield
                t = 1.0 - (d / patch_r)
                glow_col = accent_primary if px <= cx else accent_secondary
                blend_pixel(buf, px, py, glow_col, (t * t) * 0.34)
                # Highlight local miniature masonry mortar lines inside crest zone
                nx = (px - cx) / scale + 24.0
                ny = (py - cy) / scale + 24.0
                row_y = int(ny) % 7
                col_offset = 6 if (int(ny // 7) % 2 == 1) else 0
                col_x = int(nx + col_offset) % 12
                if row_y == 0 or col_x == 0:
                    blend_pixel(buf, px, py, glow_col, (t * 0.45) + 0.10)

    # 2. Middle Layer: Fill shield interior
    top_y = int(cy + (5.5 - 24.0) * scale)
    bot_y = int(cy + (42.5 - 24.0) * scale)
    for py in range(max(0, top_y), min(HEIGHT, bot_y + 1)):
        ny = (py - cy) / scale + 24.0
        if ny < 5.5 or ny > 42.5:
            continue
        if ny <= 10.2:
            half_w = ((ny - 5.5) / 4.7) * 14.5
        else:
            u = (ny - 10.2) / 32.3
            half_w = 14.5 * (1.0 - u * u * 0.96)
        lx = int(cx - half_w * scale)
        rx = int(cx + half_w * scale)
        row_color = lerp_color((15, 23, 42), (2, 44, 34), (ny - 5.5) / 37.0)
        for px in range(max(0, lx), min(WIDTH, rx + 1)):
            blend_pixel(buf, px, py, row_color, 0.96)

    # Shield border segments
    shield_pts = [
        pt(24, 5.5),
        pt(38.5, 10.2),
        pt(37.5, 20.5),
        pt(32.5, 31.5),
        pt(24, 42.5),
        pt(15.5, 31.5),
        pt(10.5, 20.5),
        pt(9.5, 10.2),
        pt(24, 5.5),
    ]
    for i in range(len(shield_pts) - 1):
        x0, y0 = shield_pts[i]
        x1, y1 = shield_pts[i + 1]
        c = lerp_color(accent_primary, accent_secondary, i / (len(shield_pts) - 1))
        draw_line_aa(buf, x0, y0, x1, y1, c, thickness=2.0 * scale)

    # Synaptic pathways inside shield (core lifted to y=21.5 above crossed axes)
    center = pt(24, 21.5)
    nodes = [
        (pt(24, 12.5), accent_primary),
        (pt(16.5, 17), accent_secondary),
        (pt(31.5, 17), accent_secondary),
        (pt(17.5, 28), accent_primary),
        (pt(30.5, 28), accent_primary),
    ]
    for n_pos, n_col in nodes:
        draw_line_aa(buf, center[0], center[1], n_pos[0], n_pos[1], n_col, thickness=1.5 * scale)
        draw_circle_aa(buf, n_pos[0], n_pos[1], 2.0 * scale, n_col)

    # Sub-branches
    b1_start, b1_end = pt(16.5, 17), pt(13.5, 19.5)
    b2_start, b2_end = pt(31.5, 17), pt(34.5, 19.5)
    draw_line_aa(buf, b1_start[0], b1_start[1], b1_end[0], b1_end[1], accent_secondary, thickness=1.1 * scale)
    draw_line_aa(buf, b2_start[0], b2_start[1], b2_end[0], b2_end[1], accent_secondary, thickness=1.1 * scale)

    # Core nerve center
    draw_circle_aa(buf, center[0], center[1], 3.2 * scale, (4, 47, 46), stroke_color=accent_primary, stroke_width=1.7 * scale)
    draw_circle_aa(buf, center[0], center[1], 1.3 * scale, (255, 255, 255))

    # 3. Front Layer: Two Forged Battle Axes Crossing IN FRONT of the Shield
    l_start, l_end = pt(10.2, 12.6), pt(35.2, 41.2)
    r_start, r_end = pt(37.8, 12.6), pt(12.8, 41.2)

    # Shadow separation over shield face so foreground layering is unmistakable
    draw_line_aa(buf, l_start[0], l_start[1], l_end[0], l_end[1], (2, 6, 23), thickness=4.0 * scale, alpha=0.88)
    draw_line_aa(buf, r_start[0], r_start[1], r_end[0], r_end[1], (2, 6, 23), thickness=4.0 * scale, alpha=0.88)

    # Metallic titanium/slate axe hafts
    draw_line_aa(buf, l_start[0], l_start[1], l_end[0], l_end[1], (176, 194, 214), thickness=2.1 * scale, alpha=0.98)
    draw_line_aa(buf, r_start[0], r_start[1], r_end[0], r_end[1], (176, 194, 214), thickness=2.1 * scale, alpha=0.98)

    # Left curved bearded axe blade (flaring outward upper-left past shield rim)
    left_blade = [
        pt(11.4, 11.4),
        pt(6.2, 11.4),
        pt(2.6, 10.2),
        pt(2.0, 15.4),
        pt(6.4, 21.6),
        pt(9.8, 17.6),
        pt(12.2, 15.6),
    ]
    draw_polygon_aa(buf, left_blade, fill_color=(45, 58, 78), stroke_color=accent_primary, stroke_width=1.3 * scale, alpha=0.96)
    # Bright cutting edge arc highlighting outer left blade
    draw_line_aa(buf, *pt(2.6, 10.2), *pt(2.0, 15.4), accent_primary, thickness=1.6 * scale)
    draw_line_aa(buf, *pt(2.0, 15.4), *pt(6.4, 21.6), accent_primary, thickness=1.6 * scale)

    # Right curved bearded axe blade (flaring outward upper-right past shield rim)
    right_blade = [
        pt(36.6, 11.4),
        pt(41.8, 11.4),
        pt(45.4, 10.2),
        pt(46.0, 15.4),
        pt(41.6, 21.6),
        pt(38.2, 17.6),
        pt(35.8, 15.6),
    ]
    draw_polygon_aa(buf, right_blade, fill_color=(45, 58, 78), stroke_color=accent_secondary, stroke_width=1.3 * scale, alpha=0.96)
    # Bright cutting edge arc highlighting outer right blade
    draw_line_aa(buf, *pt(45.4, 10.2), *pt(46.0, 15.4), accent_secondary, thickness=1.6 * scale)
    draw_line_aa(buf, *pt(46.0, 15.4), *pt(41.6, 21.6), accent_secondary, thickness=1.6 * scale)


def encode_bmp(buf: bytearray, width: int, height: int) -> bytes:
    """Encode RGB pixel buffer into standard uncompressed 24-bit Windows BMP.

    Format complies with Microsoft BMP3 standard and UEFI systemd-stub / ZFSBootMenu
    .splash section requirements (bottom-to-top scanlines, BGR order, 4-byte row padding).
    """
    row_stride = ((width * 3 + 3) // 4) * 4
    padding_len = row_stride - (width * 3)
    padding = b"\x00" * padding_len

    img_size = row_stride * height
    file_size = 54 + img_size

    # Bitmap File Header (14 bytes)
    # bfType (2B='BM'), bfSize (4B), bfReserved1 (2B=0), bfReserved2 (2B=0), bfOffBits (4B=54)
    file_header = struct.pack("<2sIHHI", b"BM", file_size, 0, 0, 54)

    # DIB Header (BITMAPINFOHEADER, 40 bytes)
    # biSize (4B=40), biWidth (4B), biHeight (4B), biPlanes (2B=1), biBitCount (2B=24),
    # biCompression (4B=0 BI_RGB), biSizeImage (4B), biXPelsPerMeter (4B), biYPelsPerMeter (4B),
    # biClrUsed (4B=0), biClrImportant (4B=0)
    dib_header = struct.pack(
        "<IIIHHIIIIII",
        40,
        width,
        height,
        1,
        24,
        0,
        img_size,
        2835,  # 72 DPI
        2835,  # 72 DPI
        0,
        0,
    )

    # Pixel data (bottom-to-top, BGR order)
    pixel_data = bytearray()
    for y in range(height - 1, -1, -1):
        row_start = y * width * 3
        for x in range(width):
            px = row_start + x * 3
            pixel_data.extend((buf[px + 2], buf[px + 1], buf[px]))  # B, G, R
        if padding_len > 0:
            pixel_data.extend(padding)

    return file_header + dib_header + bytes(pixel_data)


def encode_png(buf: bytearray, width: int, height: int) -> bytes:
    raw_rows = bytearray()
    stride = width * 3
    for y in range(height):
        raw_rows.append(0)  # Filter type 0 (None)
        row_start = y * stride
        raw_rows.extend(buf[row_start : row_start + stride])

    def chunk(chunk_type: bytes, data: bytes) -> bytes:
        crc = zlib.crc32(chunk_type + data) & 0xFFFFFFFF
        return struct.pack(">I", len(data)) + chunk_type + data + struct.pack(">I", crc)

    ihdr = struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0)
    compressed = zlib.compress(bytes(raw_rows), level=9)
    return b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", ihdr) + chunk(b"IDAT", compressed) + chunk(b"IEND", b"")


def render_splash_buffer(subtitle: str, badge_text: str, primary: tuple[int, int, int], secondary: tuple[int, int, int]) -> bytearray:
    buf = bytearray(WIDTH * HEIGHT * 3)

    # 1. Deep cyber-slate vertical + radial gradient background
    bg_top = (9, 14, 26)      # #090e1a
    bg_mid = (11, 22, 34)     # #0b1622
    bg_bot = (4, 24, 22)      # #041816
    for y in range(HEIGHT):
        t = y / (HEIGHT - 1)
        base = lerp_color(bg_top, bg_mid, t * 1.4) if t < 0.6 else lerp_color(bg_mid, bg_bot, (t - 0.6) / 0.4)
        row_idx = y * WIDTH * 3
        for x in range(WIDTH):
            buf[row_idx + x * 3] = base[0]
            buf[row_idx + x * 3 + 1] = base[1]
            buf[row_idx + x * 3 + 2] = base[2]

    # 2. Fortified Brick Masonry Wall Pattern Behind UI Cards
    draw_brick_wall_pattern(buf, primary, secondary)

    # 3. Top Accent Bar (Emerald -> Cyan gradient)
    for y in range(4):
        for x in range(WIDTH):
            c = lerp_color(primary, secondary, x / (WIDTH - 1))
            blend_pixel(buf, x, y, c, 1.0)

    # 4. Header Card & Shield Logo
    draw_rect(buf, 40, 22, WIDTH - 80, 110, fill=(13, 21, 36), border=(28, 75, 70), fill_alpha=0.88, border_alpha=0.9)
    # Corner accent ticks on header card
    for dx in range(14):
        blend_pixel(buf, 40 + dx, 22, primary, 1.0)
        blend_pixel(buf, WIDTH - 41 - dx, 22, secondary, 1.0)
        blend_pixel(buf, 40 + dx, 131, primary, 1.0)
        blend_pixel(buf, WIDTH - 41 - dx, 131, secondary, 1.0)

    draw_shield_emblem(buf, cx=92.0, cy=77.0, scale=1.65, accent_primary=primary, accent_secondary=secondary)

    # 5. "AXONWALL" Wordmark (AXON in Crisp White, WALL in Emerald->Cyan Gradient)
    end_axon = draw_text(
        buf,
        "AXON",
        x=142,
        y=44,
        scale=5,
        color_fn=lambda px, py: (248, 250, 252),
        spacing=1,
    )
    end_wall = draw_text(
        buf,
        "WALL",
        x=end_axon + 4,
        y=44,
        scale=5,
        color_fn=lambda px, py: lerp_color(primary, secondary, (px - end_axon) / 120.0),
        spacing=1,
    )

    # Version / Architecture Pill Badge on right of header
    draw_rect(buf, WIDTH - 186, 44, 128, 24, fill=(6, 42, 36), border=primary, fill_alpha=0.9, border_alpha=0.85)
    draw_text(
        buf,
        badge_text,
        x=WIDTH - 175,
        y=52,
        scale=1,
        color_fn=lambda px, py: primary,
        spacing=1,
    )

    # Subtitle below AXONWALL
    draw_text(
        buf,
        subtitle,
        x=144,
        y=96,
        scale=1,
        color_fn=lambda px, py: lerp_color(primary, secondary, (px - 144) / 380.0),
        spacing=2,
    )

    # 6. Boot Menu Viewport Frame (matches GRUB boot_menu & ISOLINUX vshift)
    draw_rect(buf, 40, 148, WIDTH - 80, 268, fill=(9, 15, 26), border=(30, 64, 68), fill_alpha=0.82, border_alpha=0.85)
    # Top highlight bar of menu frame
    for x in range(41, WIDTH - 41):
        c = lerp_color(primary, secondary, (x - 40) / (WIDTH - 80))
        blend_pixel(buf, x, 148, c, 0.75)

    # 7. Footer Status / Hardware Bar
    draw_rect(buf, 40, 428, WIDTH - 80, 32, fill=(11, 19, 32), border=(24, 52, 58), fill_alpha=0.85, border_alpha=0.7)
    draw_text(
        buf,
        "A/B DUAL-ROOT  :  ZFSBOOTMENU  :  RAID-1/ZFS  :  LUKS2+TPM2  :  SERIAL TTYS0",
        x=62,
        y=441,
        scale=1,
        color_fn=lambda px, py: (148, 163, 184),
        spacing=1,
    )

    return buf


def render_splash_png(subtitle: str, badge_text: str, primary: tuple[int, int, int], secondary: tuple[int, int, int]) -> bytes:
    buf = render_splash_buffer(subtitle, badge_text, primary, secondary)
    return encode_png(buf, WIDTH, HEIGHT)


def render_splash_bmp(subtitle: str, badge_text: str, primary: tuple[int, int, int], secondary: tuple[int, int, int]) -> bytes:
    buf = render_splash_buffer(subtitle, badge_text, primary, secondary)
    return encode_bmp(buf, WIDTH, HEIGHT)


def render_splash(subtitle: str, badge_text: str, primary: tuple[int, int, int], secondary: tuple[int, int, int]) -> bytes:
    """Backward compatibility wrapper returning PNG bytes."""
    return render_splash_png(subtitle, badge_text, primary, secondary)


def main() -> int:
    out_dir = os.path.dirname(os.path.abspath(__file__))
    if len(sys.argv) > 1:
        out_dir = sys.argv[1]
    os.makedirs(out_dir, exist_ok=True)

    # 1. Axonwall Enterprise Firewall (Emerald -> Cyan theme)
    fw_buf = render_splash_buffer(
        subtitle="ENTERPRISE LINUX NEXT-GENERATION FIREWALL",
        badge_text="NGFW APPLIANCE",
        primary=(52, 211, 153),    # Emerald #34d399
        secondary=(6, 182, 212),   # Cyan #06b6d4
    )
    fw_png = encode_png(fw_buf, WIDTH, HEIGHT)
    fw_bmp = encode_bmp(fw_buf, WIDTH, HEIGHT)

    fw_png_path = os.path.join(out_dir, "splash.png")
    fw_bmp_path = os.path.join(out_dir, "splash.bmp")
    with open(fw_png_path, "wb") as f:
        f.write(fw_png)
    with open(fw_bmp_path, "wb") as f:
        f.write(fw_bmp)

    # 2. Axonwall Vault Storage Edition (Sky Cyan -> Emerald theme)
    vault_buf = render_splash_buffer(
        subtitle="IMMUTABLE S3 BACKUP & STORAGE VAULT APPLIANCE",
        badge_text="VAULT EDITION",
        primary=(56, 189, 248),    # Sky Cyan #38bdf8
        secondary=(52, 211, 153),  # Emerald #34d399
    )
    vault_png = encode_png(vault_buf, WIDTH, HEIGHT)
    vault_bmp = encode_bmp(vault_buf, WIDTH, HEIGHT)

    vault_png_path = os.path.join(out_dir, "splash-vault.png")
    vault_bmp_path = os.path.join(out_dir, "splash-vault.bmp")
    with open(vault_png_path, "wb") as f:
        f.write(vault_png)
    with open(vault_bmp_path, "wb") as f:
        f.write(vault_bmp)

    print(f"[✓] Generated {fw_png_path} ({len(fw_png)} bytes)")
    print(f"[✓] Generated {fw_bmp_path} ({len(fw_bmp)} bytes)")
    print(f"[✓] Generated {vault_png_path} ({len(vault_png)} bytes)")
    print(f"[✓] Generated {vault_bmp_path} ({len(vault_bmp)} bytes)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
