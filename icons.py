"""
Tiny dependency-free icon renderer for the table.

ttk.Treeview can't give one cell a bigger font than the rest of the table, so
the row checkbox and the "update" button are drawn as anti-aliased RGBA images
instead (PNG data for tkinter.PhotoImage). Transparent background, so they look
right on any theme. No Tk import here: it can be tested headlessly.
"""

from __future__ import annotations

import base64
import math
import struct
import zlib
from typing import Callable, List, Tuple

Color = Tuple[int, int, int]
Shape = Tuple[Color, Callable[[float, float], bool]]

ACCENT: Color = (31, 111, 235)
OUTLINE: Color = (96, 104, 116)
WHITE: Color = (255, 255, 255)

_SS = 4  # sub-samples per pixel side (4 -> 16 samples, smooth edges)


# ---------------------------------------------------------------- PNG output
def png_bytes(width: int, height: int, rgba: bytes) -> bytes:
    raw = b"".join(b"\x00" + rgba[y * width * 4:(y + 1) * width * 4] for y in range(height))

    def chunk(kind: bytes, data: bytes) -> bytes:
        body = kind + data
        return struct.pack(">I", len(data)) + body + struct.pack(">I", zlib.crc32(body) & 0xFFFFFFFF)

    return (
        b"\x89PNG\r\n\x1a\n"
        + chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, 6, 0, 0, 0))
        + chunk(b"IDAT", zlib.compress(raw))
        + chunk(b"IEND", b"")
    )


def png_base64(width: int, height: int, rgba: bytes) -> str:
    """What PhotoImage(data=...) wants."""
    return base64.b64encode(png_bytes(width, height, rgba)).decode("ascii")


# ------------------------------------------------------------------ shapes
def _rounded_rect(x0: float, y0: float, x1: float, y1: float, r: float):
    cx, cy = (x0 + x1) / 2, (y0 + y1) / 2
    hw, hh = (x1 - x0) / 2, (y1 - y0) / 2

    def inside(x: float, y: float) -> bool:
        dx = max(abs(x - cx) - (hw - r), 0.0)
        dy = max(abs(y - cy) - (hh - r), 0.0)
        return dx * dx + dy * dy <= r * r

    return inside


def _segment(ax: float, ay: float, bx: float, by: float, width: float):
    vx, vy = bx - ax, by - ay
    length2 = vx * vx + vy * vy
    half2 = (width / 2) ** 2

    def inside(x: float, y: float) -> bool:
        t = max(0.0, min(1.0, ((x - ax) * vx + (y - ay) * vy) / length2)) if length2 else 0.0
        px, py = ax + t * vx - x, ay + t * vy - y
        return px * px + py * py <= half2

    return inside


def _arc(cx: float, cy: float, r_in: float, r_out: float, a0: float, a1: float):
    """Ring segment from angle a0 to a1 (degrees, clockwise on screen)."""
    span = (a1 - a0) % 360

    def inside(x: float, y: float) -> bool:
        d = math.hypot(x - cx, y - cy)
        if d < r_in or d > r_out:
            return False
        ang = math.degrees(math.atan2(y - cy, x - cx))
        return (ang - a0) % 360 <= span

    return inside


def _triangle(p1, p2, p3):
    (x1, y1), (x2, y2), (x3, y3) = p1, p2, p3
    den = (y2 - y3) * (x1 - x3) + (x3 - x2) * (y1 - y3)

    def inside(x: float, y: float) -> bool:
        a = ((y2 - y3) * (x - x3) + (x3 - x2) * (y - y3)) / den
        b = ((y3 - y1) * (x - x3) + (x1 - x3) * (y - y3)) / den
        return a >= 0 and b >= 0 and 1 - a - b >= 0

    return inside


def checkbox_shapes(ox: float, oy: float, size: float, checked: bool) -> List[Shape]:
    stroke = max(1.5, size / 11)
    r = size * 0.2
    outer = _rounded_rect(ox + 0.5, oy + 0.5, ox + size - 0.5, oy + size - 0.5, r)
    if not checked:
        inner = _rounded_rect(
            ox + 0.5 + stroke, oy + 0.5 + stroke,
            ox + size - 0.5 - stroke, oy + size - 0.5 - stroke, max(r - stroke, 0.5),
        )
        return [(OUTLINE, outer), (WHITE, inner)]
    w = max(1.9, size / 7.5)
    p1 = (ox + size * 0.24, oy + size * 0.53)
    p2 = (ox + size * 0.43, oy + size * 0.72)
    p3 = (ox + size * 0.78, oy + size * 0.30)
    return [
        (ACCENT, outer),
        (WHITE, _segment(*p1, *p2, w)),
        (WHITE, _segment(*p2, *p3, w)),
    ]


def refresh_shapes(ox: float, oy: float, size: float) -> List[Shape]:
    """A circular arrow: open ring with an arrow head at the end."""
    cx, cy = ox + size / 2, oy + size / 2
    r_mid = size * 0.28
    thick = max(1.9, size / 8.5)
    a0, a1 = 25.0, 305.0  # the gap sits at the upper right
    ring = _arc(cx, cy, r_mid - thick / 2, r_mid + thick / 2, a0, a1)
    t = math.radians(a1)
    px, py = cx + r_mid * math.cos(t), cy + r_mid * math.sin(t)
    tx, ty = -math.sin(t), math.cos(t)          # clockwise tangent
    nx, ny = math.cos(t), math.sin(t)           # outward normal
    head_len, half_w = size * 0.30, size * 0.18
    tip = (px + tx * head_len * 0.75, py + ty * head_len * 0.75)
    b1 = (px - tx * head_len * 0.25 + nx * half_w, py - ty * head_len * 0.25 + ny * half_w)
    b2 = (px - tx * head_len * 0.25 - nx * half_w, py - ty * head_len * 0.25 - ny * half_w)
    return [(ACCENT, ring), (ACCENT, _triangle(tip, b1, b2))]


# --------------------------------------------------------------- rasteriser
def render(width: int, height: int, shapes: List[Shape]) -> bytes:
    """Rasterise shapes (later ones on top) to straight-alpha RGBA bytes."""
    out = bytearray(width * height * 4)
    n = _SS * _SS
    step = 1.0 / _SS
    for py in range(height):
        for px in range(width):
            acc_r = acc_g = acc_b = 0
            hits = 0
            for sy in range(_SS):
                y = py + (sy + 0.5) * step
                for sx in range(_SS):
                    x = px + (sx + 0.5) * step
                    for color, inside in reversed(shapes):
                        if inside(x, y):
                            acc_r += color[0]
                            acc_g += color[1]
                            acc_b += color[2]
                            hits += 1
                            break
            if hits:
                i = (py * width + px) * 4
                out[i] = round(acc_r / hits)
                out[i + 1] = round(acc_g / hits)
                out[i + 2] = round(acc_b / hits)
                out[i + 3] = round(255 * hits / n)
    return bytes(out)


# ------------------------------------------------------------- the icon set
def layout(size: int) -> Tuple[int, int, int]:
    """(gap between the two icons, total width, refresh-icon x offset)."""
    gap = max(10, size // 2)
    return gap, size * 2 + gap, size + gap


def row_icon(size: int, checked: bool) -> Tuple[int, int, str]:
    """Checkbox + update button side by side -> (w, h, base64 PNG)."""
    _, width, refresh_x = layout(size)
    shapes = checkbox_shapes(0, 0, size, checked) + refresh_shapes(refresh_x, 0, size)
    return width, size, png_base64(width, size, render(width, size, shapes))


def header_icon(size: int, checked: bool) -> Tuple[int, int, str]:
    """Just the check-all box, for the column heading."""
    return size, size, png_base64(size, size, render(size, size, checkbox_shapes(0, 0, size, checked)))
