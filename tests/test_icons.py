"""Headless tests for the drawn checkbox / update icons."""

import base64
import os
import struct
import sys
import zlib

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import icons  # noqa: E402


def _decode(b64):
    """Minimal PNG decoder for what icons.png_bytes writes (8-bit RGBA, no filters)."""
    png = base64.b64decode(b64)
    assert png[:8] == b"\x89PNG\r\n\x1a\n"
    pos, idat, w, h = 8, b"", 0, 0
    while pos < len(png):
        (length,) = struct.unpack(">I", png[pos:pos + 4])
        kind, body = png[pos + 4:pos + 8], png[pos + 8:pos + 8 + length]
        assert struct.unpack(">I", png[pos + 8 + length:pos + 12 + length])[0] == zlib.crc32(kind + body) & 0xFFFFFFFF
        if kind == b"IHDR":
            w, h = struct.unpack(">II", body[:8])
        elif kind == b"IDAT":
            idat += body
        pos += 12 + length
    raw = zlib.decompress(idat)
    rows = [raw[y * (w * 4 + 1) + 1:(y + 1) * (w * 4 + 1)] for y in range(h)]
    assert all(raw[y * (w * 4 + 1)] == 0 for y in range(h))
    return w, h, lambda x, y: tuple(rows[y][x * 4:x * 4 + 4])


def test_row_icon_size_and_transparency():
    size = 22
    w, h, b64 = icons.row_icon(size, False)
    dw, dh, px = _decode(b64)
    assert (dw, dh) == (w, h) == (icons.layout(size)[1], size)
    assert px(0, 0)[3] == 0, "rounded corner must be transparent"
    gap_x = size + icons.layout(size)[0] // 2
    assert all(px(gap_x, y)[3] == 0 for y in range(size)), "gap between the icons is empty"


def test_checked_and_unchecked_boxes_differ():
    size = 22
    off = _decode(icons.row_icon(size, False)[2])[2]
    on = _decode(icons.row_icon(size, True)[2])[2]
    assert off(size // 2, 3) [:3] == icons.WHITE and off(size // 2, 3)[3] == 255  # empty box: white inside
    assert on(2, size // 2)[:3] == icons.ACCENT                                    # ticked box: accent fill
    assert off(2, size // 2) != on(2, size // 2)


def test_update_button_is_a_ring():
    size = 22
    _, _, px = _decode(icons.row_icon(size, False)[2])
    cx = icons.layout(size)[2] + size // 2
    assert px(cx, size // 2)[3] == 0, "ring is hollow"
    assert any(px(x, size // 2)[3] == 255 for x in range(icons.layout(size)[2], icons.layout(size)[1])), "ring is drawn"


def test_header_icon_is_just_the_box():
    w, h, b64 = icons.header_icon(20, True)
    assert (w, h) == (20, 20)
    assert _decode(b64)[2](10, 4)[:3] in (icons.ACCENT, icons.WHITE)


def test_app_icon_is_an_opaque_tile_in_all_sizes():
    for size in (16, 32, 64):
        w, h, data = icons.app_icon(size)
        assert (w, h) == (size, size) and data
