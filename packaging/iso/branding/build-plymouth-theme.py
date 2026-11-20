#!/usr/bin/env python3
"""
Axonwall Plymouth Boot Splash Theme Builder
==========================================
Deterministically builds the custom `axonwall` Plymouth script theme from the
master Axonwall Hero Emblem artwork (fortified brick wall + neural cyber-shield
+ twin crossed battle axes) and syncs the complete theme bundle into the Debian
live-build chroot overlay (/usr/share/plymouth/themes/axonwall).
"""

from __future__ import annotations

import argparse
import math
import os
import shutil
import struct
import subprocess
import sys
import zlib
from pathlib import Path

import numpy as np


def encode_rgba_png(rgba: np.ndarray) -> bytes:
    """Encode a HxWx4 uint8 RGBA numpy array into a PNG byte stream."""
    height, width, channels = rgba.shape
    if channels != 4:
        raise ValueError(f"Expected 4 RGBA channels, got {channels}")
    stride = width * 4
    raw = bytearray(height * (1 + stride))
    flat = np.ascontiguousarray(rgba, dtype=np.uint8).tobytes()
    for y in range(height):
        row_off = y * (1 + stride)
        raw[row_off] = 0  # Filter type 0 (None)
        raw[row_off + 1 : row_off + 1 + stride] = flat[y * stride : (y + 1) * stride]

    def chunk(chunk_type: bytes, data: bytes) -> bytes:
        crc = zlib.crc32(chunk_type + data) & 0xFFFFFFFF
        return struct.pack(">I", len(data)) + chunk_type + data + struct.pack(">I", crc)

    ihdr = struct.pack(">IIBBBBB", width, height, 8, 6, 0, 0, 0)
    compressed = zlib.compress(bytes(raw), level=9)
    return b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", ihdr) + chunk(b"IDAT", compressed) + chunk(b"IEND", b"")


def write_rgba_png(path: Path, rgba: np.ndarray) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(encode_rgba_png(rgba))


def generate_hero_emblem(hero_src: Path, dest: Path, width: int = 880, height: int = 491) -> None:
    """Resize master hero artwork to 16:9 and softly feather edges into transparency."""
    if not hero_src.is_file():
        raise FileNotFoundError(f"Hero artwork source not found: {hero_src}")

    if shutil.which("convert"):
        raw_rgba = subprocess.check_output(
            [
                "convert",
                str(hero_src),
                "-resize",
                f"{width}x{height}!",
                "-alpha",
                "set",
                "rgba:-",
            ]
        )
        img = np.frombuffer(raw_rgba, dtype=np.uint8).reshape((height, width, 4)).copy()
    else:
        raise RuntimeError("ImageMagick 'convert' is required to decode hero artwork")

    # Apply smooth elliptical edge feathering so the brick vignette melts cleanly into #080c14
    yy, xx = np.mgrid[0:height, 0:width].astype(np.float32)
    nx = (xx - (width - 1) * 0.5) / (width * 0.5)
    ny = (yy - (height - 1) * 0.5) / (height * 0.5)
    ellip = np.sqrt(nx * nx * 0.92 + ny * ny * 1.05)

    # Full opacity across central 68% crest/wall region, cosine fade to 0 at 98% boundary
    alpha_mask = np.clip((0.98 - ellip) / (0.98 - 0.66), 0.0, 1.0)
    alpha_mask = alpha_mask * alpha_mask * (3.0 - 2.0 * alpha_mask)

    # Also apply subtle corner rectangular edge fade to avoid hard top/bottom/side edges
    edge_x = np.clip(np.minimum(xx, width - 1 - xx) / (width * 0.08), 0.0, 1.0)
    edge_y = np.clip(np.minimum(yy, height - 1 - yy) / (height * 0.10), 0.0, 1.0)
    final_alpha = np.clip(alpha_mask * edge_x * edge_y, 0.0, 1.0)

    img[:, :, 3] = np.clip(img[:, :, 3].astype(np.float32) * final_alpha, 0, 255).astype(np.uint8)
    write_rgba_png(dest, img)


def generate_glow(dest: Path, size: int = 480) -> None:
    """Create a soft radial emerald-to-cyan breathing halo PNG."""
    yy, xx = np.mgrid[0:size, 0:size].astype(np.float32)
    cx = (size - 1) * 0.5
    cy = (size - 1) * 0.5
    dist = np.hypot(xx - cx, yy - cy) / (size * 0.5)
    falloff = np.clip(1.0 - dist, 0.0, 1.0)
    alpha = (falloff ** 2.4) * 0.72

    # Horizontal blend from emerald (#10b981) on left to cyan (#06b6d4) on right
    tx = np.clip(xx / (size - 1), 0.0, 1.0)
    r = (16.0 * (1.0 - tx) + 6.0 * tx).astype(np.uint8)
    g = (185.0 * (1.0 - tx) + 182.0 * tx).astype(np.uint8)
    b = (129.0 * (1.0 - tx) + 212.0 * tx).astype(np.uint8)

    rgba = np.zeros((size, size, 4), dtype=np.uint8)
    rgba[:, :, 0] = r
    rgba[:, :, 1] = g
    rgba[:, :, 2] = b
    rgba[:, :, 3] = np.clip(alpha * 255.0, 0, 255).astype(np.uint8)
    write_rgba_png(dest, rgba)


def generate_wordmark(dest: Path) -> None:
    """Render crisp centered anti-aliased AXONWALL wordmark + subtitle RGBA PNG."""
    dest.parent.mkdir(parents=True, exist_ok=True)
    sans_font = "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf"
    mono_font = "/usr/share/fonts/truetype/dejavu/DejaVuSansMono-Bold.ttf"

    if shutil.which("convert") and os.path.isfile(sans_font) and os.path.isfile(mono_font):
        def render_label_rgba(text: str, font_path: str, pointsize: int, color: str) -> np.ndarray:
            out = subprocess.check_output(
                [
                    "convert",
                    "-background",
                    "none",
                    "-font",
                    font_path,
                    "-pointsize",
                    str(pointsize),
                    "-fill",
                    color,
                    f"label:{text}",
                    "-trim",
                    "+repage",
                    "png:-",
                ]
            )
            dims = subprocess.check_output(["identify", "-format", "%w %h", "png:-"], input=out).decode("utf-8").split()
            w, h = int(dims[0]), int(dims[1])
            raw = subprocess.check_output(["convert", "png:-", "rgba:-"], input=out)
            return np.frombuffer(raw, dtype=np.uint8).reshape((h, w, 4)).copy()

        axon_arr = render_label_rgba("AXON", sans_font, 40, "#f8fafc")
        wall_arr = render_label_rgba("WALL", sans_font, 40, "#ffffff")
        # Colorize WALL smoothly from #34d399 (left) to #06b6d4 (right) while keeping exact alpha
        ww = wall_arr.shape[1]
        tx = np.broadcast_to(np.linspace(0.0, 1.0, ww, dtype=np.float32), (wall_arr.shape[0], ww))
        wall_arr[:, :, 0] = (52.0 * (1.0 - tx) + 6.0 * tx).astype(np.uint8)
        wall_arr[:, :, 1] = (211.0 * (1.0 - tx) + 182.0 * tx).astype(np.uint8)
        wall_arr[:, :, 2] = (153.0 * (1.0 - tx) + 212.0 * tx).astype(np.uint8)

        sub_arr = render_label_rgba("SOVEREIGN LINUX NGFW & SECURITY OS", mono_font, 13, "#34d399")

        canvas_w, canvas_h = 520, 82
        canvas = np.zeros((canvas_h, canvas_w, 4), dtype=np.uint8)

        gap = 3
        word_h = max(axon_arr.shape[0], wall_arr.shape[0])
        word_w = axon_arr.shape[1] + gap + wall_arr.shape[1]
        wx0 = (canvas_w - word_w) // 2
        wy_base = 8 + word_h

        ay0 = wy_base - axon_arr.shape[0]
        canvas[ay0:ay0 + axon_arr.shape[0], wx0:wx0 + axon_arr.shape[1]] = axon_arr

        wall_x0 = wx0 + axon_arr.shape[1] + gap
        wall_y0 = wy_base - wall_arr.shape[0]
        canvas[wall_y0:wall_y0 + wall_arr.shape[0], wall_x0:wall_x0 + wall_arr.shape[1]] = wall_arr

        sx0 = (canvas_w - sub_arr.shape[1]) // 2
        sy0 = canvas_h - sub_arr.shape[0] - 8
        canvas[sy0:sy0 + sub_arr.shape[0], sx0:sx0 + sub_arr.shape[1]] = sub_arr

        write_rgba_png(dest, canvas)
        return

    raise RuntimeError("DejaVu fonts and ImageMagick 'convert' are required to render wordmark")


def rounded_box_mask(h: int, w: int, radius: float) -> np.ndarray:
    yy, xx = np.mgrid[0:h, 0:w].astype(np.float32)
    rx = np.maximum(0.0, np.abs(xx - (w - 1) * 0.5) - ((w - 1) * 0.5 - radius))
    ry = np.maximum(0.0, np.abs(yy - (h - 1) * 0.5) - ((h - 1) * 0.5 - radius))
    dist = np.hypot(rx, ry) - radius
    return dist


def generate_progress_assets(box_path: Path, bar_path: Path) -> None:
    # progress_box.png: 360x10 dark rounded track with subtle emerald border
    w, h = 360, 10
    dist = rounded_box_mask(h, w, 4.5)
    inside = np.clip(0.5 - dist, 0.0, 1.0)
    border = np.clip(1.0 - np.abs(dist + 0.6), 0.0, 1.0)

    box = np.zeros((h, w, 4), dtype=np.uint8)
    box[:, :, 0] = np.clip(11 * inside + 24 * border, 0, 255).astype(np.uint8)
    box[:, :, 1] = np.clip(22 * inside + 118 * border, 0, 255).astype(np.uint8)
    box[:, :, 2] = np.clip(36 * inside + 110 * border, 0, 255).astype(np.uint8)
    box[:, :, 3] = np.clip(np.maximum(inside * 225.0, border * 235.0), 0, 255).astype(np.uint8)
    write_rgba_png(box_path, box)

    # progress_bar.png: 356x6 emerald (#34d399) -> cyan (#06b6d4) gradient fill
    bw, bh = 356, 6
    bdist = rounded_box_mask(bh, bw, 2.8)
    binside = np.clip(0.5 - bdist, 0.0, 1.0)
    tx = np.broadcast_to(np.linspace(0.0, 1.0, bw, dtype=np.float32), (bh, bw))

    bar = np.zeros((bh, bw, 4), dtype=np.uint8)
    bar[:, :, 0] = (52.0 * (1.0 - tx) + 6.0 * tx).astype(np.uint8)
    bar[:, :, 1] = (211.0 * (1.0 - tx) + 182.0 * tx).astype(np.uint8)
    bar[:, :, 2] = (153.0 * (1.0 - tx) + 212.0 * tx).astype(np.uint8)
    bar[:, :, 3] = np.clip(binside * 255.0, 0, 255).astype(np.uint8)
    write_rgba_png(bar_path, bar)


def generate_password_assets(field_path: Path, dot_path: Path) -> None:
    # password_field.png: 340x36 dark obsidian box with #34d399 border
    w, h = 340, 36
    dist = rounded_box_mask(h, w, 7.0)
    inside = np.clip(0.5 - dist, 0.0, 1.0)
    border = np.clip(1.0 - np.abs(dist + 0.6), 0.0, 1.0)

    field = np.zeros((h, w, 4), dtype=np.uint8)
    field[:, :, 0] = np.clip(9 * inside + 52 * border, 0, 255).astype(np.uint8)
    field[:, :, 1] = np.clip(16 * inside + 211 * border, 0, 255).astype(np.uint8)
    field[:, :, 2] = np.clip(29 * inside + 153 * border, 0, 255).astype(np.uint8)
    field[:, :, 3] = np.clip(np.maximum(inside * 235.0, border * 250.0), 0, 255).astype(np.uint8)
    write_rgba_png(field_path, field)

    # password_dot.png: 14x14 glowing emerald bullet
    sz = 14
    yy, xx = np.mgrid[0:sz, 0:sz].astype(np.float32)
    d = np.hypot(xx - (sz - 1) * 0.5, yy - (sz - 1) * 0.5)
    core = np.clip(4.6 - d, 0.0, 1.0)
    halo = np.clip(1.0 - d / 6.8, 0.0, 1.0) ** 2.0

    dot = np.zeros((sz, sz, 4), dtype=np.uint8)
    dot[:, :, 0] = np.clip(52 * np.maximum(core, halo) + 180 * np.clip(2.0 - d, 0.0, 1.0), 0, 255).astype(np.uint8)
    dot[:, :, 1] = np.clip(225 * np.maximum(core, halo), 0, 255).astype(np.uint8)
    dot[:, :, 2] = np.clip(165 * np.maximum(core, halo) + 60 * np.clip(2.0 - d, 0.0, 1.0), 0, 255).astype(np.uint8)
    dot[:, :, 3] = np.clip(np.maximum(core, halo * 0.55) * 255.0, 0, 255).astype(np.uint8)
    write_rgba_png(dot_path, dot)


PLYMOUTH_DESCRIPTOR = """\
[Plymouth Theme]
Name=Axonwall Fortress Boot Splash
Description=Axonwall Cyber-Shield on Fortified Brick Wall with Crossed Axes
ModuleName=script

[script]
ImageDir=/usr/share/plymouth/themes/axonwall
ScriptFile=/usr/share/plymouth/themes/axonwall/axonwall.script
"""

PLYMOUTH_SCRIPT = r"""# ==============================================================================
# Axonwall Fortress Boot Splash Theme (Plymouth Script Plugin)
# Fortified Brick Wall + Neural Cyber-Shield + Twin Crossed Battle Axes
# ==============================================================================

Window.SetBackgroundTopColor(0.031, 0.047, 0.078);     # #080c14
Window.SetBackgroundBottomColor(0.016, 0.094, 0.086);  # #041816

win_w = Window.GetWidth();
win_h = Window.GetHeight();
win_x = Window.GetX();
win_y = Window.GetY();

# ------------------------------------------------------------------------------
# Visual Layers: Back Glow -> Hero Emblem -> Crisp Wordmark -> Progress Bar
# ------------------------------------------------------------------------------
emblem_raw = Image("hero_emblem.png");
glow_raw = Image("glow.png");
wordmark_raw = Image("wordmark.png");
progress_box_raw = Image("progress_box.png");
progress_bar_raw = Image("progress_bar.png");

emblem_aspect = emblem_raw.GetWidth() / emblem_raw.GetHeight();
target_h = Math.Int(win_h * 0.48);
if (target_h < 185) target_h = 185;
if (target_h > 491) target_h = 491;
target_w = Math.Int(target_h * emblem_aspect);

max_w = Math.Int(win_w * 0.88);
if (target_w > max_w) {
    target_w = max_w;
    target_h = Math.Int(target_w / emblem_aspect);
}

emblem_img = emblem_raw.Scale(target_w, target_h);

glow_size = Math.Int(target_h * 1.15);
glow_img = glow_raw.Scale(glow_size, glow_size);

wm_scale = 1.0;
max_wm_w = win_w * 0.78;
if (wordmark_raw.GetWidth() > max_wm_w) {
    wm_scale = max_wm_w / wordmark_raw.GetWidth();
} else if (win_h >= 1200) {
    wm_scale = 1.15;
}
wm_w = Math.Int(wordmark_raw.GetWidth() * wm_scale);
wm_h = Math.Int(wordmark_raw.GetHeight() * wm_scale);
wordmark_img = wordmark_raw.Scale(wm_w, wm_h);

box_scale = Math.Min(1.0, (win_w * 0.65) / progress_box_raw.GetWidth());
box_w = Math.Int(progress_box_raw.GetWidth() * box_scale);
box_h = Math.Max(6, Math.Int(progress_box_raw.GetHeight() * box_scale));
progress_box_img = progress_box_raw.Scale(box_w, box_h);

bar_max_w = Math.Max(4, box_w - 4);
bar_h = Math.Max(4, box_h - 4);

gap_emblem_wm = Math.Int(Math.Max(6, win_h * 0.016));
gap_wm_bar = Math.Int(Math.Max(8, win_h * 0.020));
gap_bar_status = Math.Int(Math.Max(10, win_h * 0.022));

stack_h = target_h + gap_emblem_wm + wm_h + gap_wm_bar + box_h + gap_bar_status + 28;
top_y = win_y + Math.Max(12, Math.Int((win_h - stack_h) * 0.42));

emblem_x = win_x + Math.Int((win_w - target_w) * 0.5);
emblem_y = top_y;

glow_sprite = Sprite(glow_img);
glow_sprite.SetPosition(
    win_x + Math.Int((win_w - glow_size) * 0.5),
    emblem_y + Math.Int((target_h - glow_size) * 0.5),
    1
);
glow_sprite.SetOpacity(0.55);

emblem_sprite = Sprite(emblem_img);
emblem_sprite.SetPosition(emblem_x, emblem_y, 2);

wm_x = win_x + Math.Int((win_w - wm_w) * 0.5);
wm_y = emblem_y + target_h + gap_emblem_wm;
wordmark_sprite = Sprite(wordmark_img);
wordmark_sprite.SetPosition(wm_x, wm_y, 3);

box_x = win_x + Math.Int((win_w - box_w) * 0.5);
box_y = wm_y + wm_h + gap_wm_bar;
progress_box_sprite = Sprite(progress_box_img);
progress_box_sprite.SetPosition(box_x, box_y, 4);

progress_bar_sprite = Sprite();
progress_bar_sprite.SetPosition(box_x + 2, box_y + 2, 5);
progress_bar_sprite.SetOpacity(0);

# ------------------------------------------------------------------------------
# Mode-Aware Default Status & Dynamic Message Display
# ------------------------------------------------------------------------------
status = "normal";
prompt_active = 0;
tick_counter = 0;
current_progress = 0.0;

boot_mode = Plymouth.GetMode();
default_status = "Booting Axonwall Security OS...";
if (boot_mode == "shutdown") {
    default_status = "Shutting Down Axonwall Appliance...";
} else if (boot_mode == "reboot") {
    default_status = "Rebooting Axonwall Appliance...";
} else if (boot_mode == "updates" || boot_mode == "system-upgrade" || boot_mode == "firmware-upgrade") {
    default_status = "Applying Firmware Update...";
}

status_y = box_y + box_h + gap_bar_status;
action_y = status_y + 22;

status_sprite = Sprite();
action_sprite = Sprite();

fun set_status_text(text) {
    if (!text || text == "") text = default_status;
    img = Image.Text(text, 0.796, 0.835, 0.882);  # #cbd5e1
    status_sprite.SetImage(img);
    status_sprite.SetPosition(
        win_x + Math.Int((win_w - img.GetWidth()) * 0.5),
        status_y,
        100
    );
    status_sprite.SetOpacity(1);
}

fun set_action_text(text) {
    if (!text || text == "") {
        action_sprite.SetOpacity(0);
        return;
    }
    img = Image.Text(text, 0.204, 0.827, 0.600);  # #34d399
    action_sprite.SetImage(img);
    action_sprite.SetPosition(
        win_x + Math.Int((win_w - img.GetWidth()) * 0.5),
        action_y,
        100
    );
    action_sprite.SetOpacity(1);
}

set_status_text(default_status);

# ------------------------------------------------------------------------------
# Boot Progress & 50Hz Breathing Halo Callbacks
# ------------------------------------------------------------------------------
fun boot_progress_callback(time, progress) {
    if (progress < 0.0) progress = 0.0;
    if (progress > 1.0) progress = 1.0;
    global.current_progress = progress;

    if (prompt_active) return;

    fill_w = Math.Int(bar_max_w * progress);
    if (fill_w < 3) {
        progress_bar_sprite.SetOpacity(0);
    } else {
        scaled = progress_bar_raw.Scale(fill_w, bar_h);
        progress_bar_sprite.SetImage(scaled);
        progress_bar_sprite.SetOpacity(1);
    }
}
Plymouth.SetBootProgressFunction(boot_progress_callback);

fun refresh_callback() {
    global.tick_counter++;
    pulse = 0.48 + 0.32 * Math.Cos(global.tick_counter * 0.045);
    glow_sprite.SetOpacity(pulse);
}
Plymouth.SetRefreshFunction(refresh_callback);

# ------------------------------------------------------------------------------
# String Helpers (Plymouth Script does not expose strstr/length builtins)
# ------------------------------------------------------------------------------
fun string_index(haystack, needle) {
    start = 0;
    while (String(haystack).CharAt(start)) {
        walk = 0;
        while (String(needle).CharAt(walk) == String(haystack).CharAt(start + walk)) {
            walk++;
            if (!String(needle).CharAt(walk)) return start;
        }
        start++;
    }
    return NULL;
}

fun string_length(str) {
    idx = 0;
    while (String(str).CharAt(idx)) idx++;
    return idx;
}

fun string_slice(src, start, end) {
    out = "";
    for (i = start; ((end == NULL || i <= end) && String(src).CharAt(i)); i++) {
        out += String(src).CharAt(i);
    }
    return out;
}

# ------------------------------------------------------------------------------
# Message & fsckd / Firstboot Status Callbacks
# ------------------------------------------------------------------------------
fun message_callback(message) {
    if (!message || message == "") {
        set_status_text(default_status);
        set_action_text("");
        return;
    }

    keys_idx = string_index(message, "keys:");
    if (keys_idx != NULL) {
        clean = string_slice(message, keys_idx + string_length("keys:"), NULL);
        if (!prompt_active) set_action_text(clean);
        return;
    }

    fsck_idx = string_index(message, "fsckd-cancel-msg:");
    if (fsck_idx != NULL) {
        clean = string_slice(message, fsck_idx + string_length("fsckd-cancel-msg:"), NULL);
        if (!prompt_active) set_action_text(clean);
        return;
    }

    set_status_text(message);
}
Plymouth.SetMessageFunction(message_callback);

fun update_status_callback(msg) {
    if (!msg || msg == "") return;

    it = 0;
    parts[0] = "";
    for (i = 0; String(msg).CharAt(i) != ""; i++) {
        ch = String(msg).CharAt(i);
        if (ch != ":") {
            parts[it] += ch;
        } else {
            it++;
            parts[it] = "";
        }
    }

    if (parts[0] == "fsck" && it >= 2) {
        set_status_text("Checking disk integrity (" + parts[1] + ": " + parts[2] + "%)...");
    } else if (parts[0] == "fsckd" && it >= 3) {
        set_status_text(parts[3]);
    }
}
Plymouth.SetUpdateStatusFunction(update_status_callback);

# ------------------------------------------------------------------------------
# Password (LUKS2) & Interactive Question Dialogs
# ------------------------------------------------------------------------------
pw_field_img = Image("password_field.png");
pw_dot_img = Image("password_dot.png");

fun ensure_pw_dialog(prompt_text) {
    if (global.pw_dialog) return;

    local.d;
    d.prompt_img = Image.Text(prompt_text, 0.973, 0.980, 0.988);
    d.prompt_sprite = Sprite(d.prompt_img);

    d.field_sprite = Sprite(pw_field_img);
    dlg_y = box_y + 18;
    if (dlg_y + pw_field_img.GetHeight() + 12 > win_y + win_h) {
        dlg_y = win_y + win_h - pw_field_img.GetHeight() - 16;
    }
    prompt_y = dlg_y - d.prompt_img.GetHeight() - 8;

    d.prompt_sprite.SetPosition(
        win_x + Math.Int((win_w - d.prompt_img.GetWidth()) * 0.5),
        prompt_y,
        10000
    );
    d.field_sprite.SetPosition(
        win_x + Math.Int((win_w - pw_field_img.GetWidth()) * 0.5),
        dlg_y,
        10000
    );
    d.field_x = win_x + Math.Int((win_w - pw_field_img.GetWidth()) * 0.5);
    d.field_y = dlg_y;
    global.pw_dialog = d;
}

fun clear_pw_dialog() {
    if (!global.pw_dialog) return;
    if (global.pw_dialog.prompt_sprite) global.pw_dialog.prompt_sprite.SetOpacity(0);
    if (global.pw_dialog.field_sprite) global.pw_dialog.field_sprite.SetOpacity(0);
    if (global.pw_dialog.entry_sprite) global.pw_dialog.entry_sprite.SetOpacity(0);
    if (global.pw_dialog.bullets) {
        for (i = 0; global.pw_dialog.bullets[i]; i++) {
            global.pw_dialog.bullets[i].SetOpacity(0);
        }
    }
    global.pw_dialog = NULL;
}

fun display_password_callback(prompt, bullets) {
    global.status = "password";
    global.prompt_active = 1;
    progress_box_sprite.SetOpacity(0);
    progress_bar_sprite.SetOpacity(0);
    status_sprite.SetOpacity(0);
    action_sprite.SetOpacity(0);

    ensure_pw_dialog(prompt);
    d = global.pw_dialog;
    d.prompt_sprite.SetOpacity(1);
    d.field_sprite.SetOpacity(1);

    dot_w = pw_dot_img.GetWidth();
    dot_h = pw_dot_img.GetHeight();
    step = dot_w + 4;
    margin = 14;
    max_bullets = Math.Int((pw_field_img.GetWidth() - margin * 2) / step);
    if (bullets > max_bullets) bullets = max_bullets;

    dot_y = d.field_y + Math.Int((pw_field_img.GetHeight() - dot_h) * 0.5);
    for (i = 0; (d.bullets[i] || i < bullets); i++) {
        if (!d.bullets[i]) {
            d.bullets[i] = Sprite(pw_dot_img);
            d.bullets[i].SetPosition(d.field_x + margin + i * step, dot_y, 10001);
        }
        if (i < bullets) {
            d.bullets[i].SetOpacity(1);
        } else {
            d.bullets[i].SetOpacity(0);
        }
    }
}
Plymouth.SetDisplayPasswordFunction(display_password_callback);

fun display_question_callback(prompt, entry) {
    global.status = "question";
    global.prompt_active = 1;
    progress_box_sprite.SetOpacity(0);
    progress_bar_sprite.SetOpacity(0);
    status_sprite.SetOpacity(0);
    action_sprite.SetOpacity(0);

    ensure_pw_dialog(prompt);
    d = global.pw_dialog;
    d.prompt_sprite.SetOpacity(1);
    d.field_sprite.SetOpacity(1);

    entry_img = Image.Text(entry, 0.204, 0.827, 0.600);
    if (!d.entry_sprite) d.entry_sprite = Sprite();
    d.entry_sprite.SetImage(entry_img);
    d.entry_sprite.SetPosition(
        d.field_x + 14,
        d.field_y + Math.Int((pw_field_img.GetHeight() - entry_img.GetHeight()) * 0.5),
        10001
    );
    d.entry_sprite.SetOpacity(1);
}
Plymouth.SetDisplayQuestionFunction(display_question_callback);

fun display_normal_callback() {
    global.status = "normal";
    global.prompt_active = 0;
    clear_pw_dialog();
    progress_box_sprite.SetOpacity(1);
    boot_progress_callback(0, global.current_progress);
    status_sprite.SetOpacity(1);
}
Plymouth.SetDisplayNormalFunction(display_normal_callback);

fun quit_callback() {
    glow_sprite.SetOpacity(0);
    emblem_sprite.SetOpacity(0);
    wordmark_sprite.SetOpacity(0);
    progress_box_sprite.SetOpacity(0);
    progress_bar_sprite.SetOpacity(0);
    status_sprite.SetOpacity(0);
    action_sprite.SetOpacity(0);
    clear_pw_dialog();
}
Plymouth.SetQuitFunction(quit_callback);
"""


def build_theme(hero_src: Path, out_dir: Path, sync_chroot: Path | None = None) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)

    generate_hero_emblem(hero_src, out_dir / "hero_emblem.png")
    generate_glow(out_dir / "glow.png")
    generate_wordmark(out_dir / "wordmark.png")
    generate_progress_assets(out_dir / "progress_box.png", out_dir / "progress_bar.png")
    generate_password_assets(out_dir / "password_field.png", out_dir / "password_dot.png")

    (out_dir / "axonwall.plymouth").write_text(PLYMOUTH_DESCRIPTOR, encoding="utf-8")
    (out_dir / "axonwall.script").write_text(PLYMOUTH_SCRIPT, encoding="utf-8")

    for f in out_dir.iterdir():
        if f.is_file():
            os.chmod(f, 0o644)

    if sync_chroot is not None:
        sync_chroot.mkdir(parents=True, exist_ok=True)
        for f in out_dir.iterdir():
            if f.is_file():
                dst = sync_chroot / f.name
                shutil.copy2(f, dst)
                os.chmod(dst, 0o644)


def main() -> int:
    script_dir = Path(__file__).resolve().parent
    repo_root = script_dir.parent.parent.parent

    parser = argparse.ArgumentParser(description="Build Axonwall Plymouth boot splash theme")
    parser.add_argument(
        "--hero",
        type=Path,
        default=repo_root / "axonwall.com" / "public" / "hero-axonwall.png",
        help="Path to master hero artwork PNG",
    )
    parser.add_argument(
        "--out-dir",
        type=Path,
        default=script_dir / "plymouth" / "axonwall",
        help="Output Plymouth theme directory",
    )
    parser.add_argument(
        "--sync-chroot",
        type=Path,
        default=repo_root / "packaging" / "iso" / "config" / "includes.chroot" / "usr" / "share" / "plymouth" / "themes" / "axonwall",
        help="Chroot Plymouth theme destination directory",
    )
    args = parser.parse_args()

    build_theme(args.hero, args.out_dir, args.sync_chroot)
    print(f"[✓] Built Plymouth theme 'axonwall' in {args.out_dir}")
    print(f"[✓] Synced Plymouth theme 'axonwall' to {args.sync_chroot}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
