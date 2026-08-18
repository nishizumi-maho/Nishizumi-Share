#!/usr/bin/env python3
"""Generate packaging/app.ico without any image-library dependency.

The mark is a set of concentric "onion" rings over a dark rounded square,
rendered with 4x supersampling and written as PNG-framed ICO (Vista+).

Usage:
    python packaging/generate_icon.py [--out packaging/app.ico]
"""

from __future__ import annotations

import argparse
import math
import struct
import zlib
from pathlib import Path
from typing import List, Tuple

SIZES = (16, 32, 48, 64, 128, 256)
SUPERSAMPLE = 4

BACKGROUND = (24, 20, 34)
RING_OUTER = (156, 108, 214)
RING_INNER = (208, 168, 246)
CORE = (245, 232, 255)

RGBA = Tuple[int, int, int, int]


def _lerp(a: Tuple[int, int, int], b: Tuple[int, int, int], t: float) -> Tuple[int, int, int]:
    return tuple(round(x + (y - x) * t) for x, y in zip(a, b))


def _rounded_square_alpha(x: float, y: float, size: float, radius: float) -> bool:
    """True when (x, y) lies inside a rounded square filling ``size``."""
    cx = cy = size / 2.0
    dx = abs(x - cx) - (size / 2.0 - radius)
    dy = abs(y - cy) - (size / 2.0 - radius)

    if dx <= 0 and dy <= 0:
        return True
    dx = max(dx, 0.0)
    dy = max(dy, 0.0)
    return math.hypot(dx, dy) <= radius


def _shade(distance: float, size: float) -> Tuple[int, int, int]:
    """Colour for a point at ``distance`` from the centre."""
    outer_radius = size * 0.40
    normalised = min(1.0, distance / outer_radius)

    # Four concentric bands, brighter toward the middle.
    band = int(normalised * 4)
    if band >= 4:
        return BACKGROUND
    if band == 3:
        return RING_OUTER
    if band == 2:
        return _lerp(RING_OUTER, RING_INNER, 0.5)
    if band == 1:
        return RING_INNER
    return CORE


def render(size: int) -> List[List[RGBA]]:
    """Render one icon frame as a row-major RGBA grid."""
    scale = SUPERSAMPLE
    big = size * scale
    radius = big * 0.22
    centre = big / 2.0

    # Supersampled buffer, later box-filtered down to `size`.
    buffer: List[List[RGBA]] = []
    for py in range(big):
        row: List[RGBA] = []
        for px in range(big):
            x, y = px + 0.5, py + 0.5
            if not _rounded_square_alpha(x, y, big, radius):
                row.append((0, 0, 0, 0))
                continue

            distance = math.hypot(x - centre, y - centre)
            gap = (distance / (big * 0.40) * 4) % 1.0
            # Thin dark separator between the rings.
            if 0.86 < gap < 1.0 and distance < big * 0.40:
                row.append((*BACKGROUND, 255))
            else:
                row.append((*_shade(distance, big), 255))
        buffer.append(row)

    # Downsample.
    out: List[List[RGBA]] = []
    for y in range(size):
        row = []
        for x in range(size):
            r = g = b = a = 0
            for sy in range(scale):
                for sx in range(scale):
                    pr, pg, pb, pa = buffer[y * scale + sy][x * scale + sx]
                    # Weight colour by alpha for correct edge blending.
                    r += pr * pa
                    g += pg * pa
                    b += pb * pa
                    a += pa
            if a == 0:
                row.append((0, 0, 0, 0))
            else:
                row.append((r // a, g // a, b // a, a // (scale * scale)))
        out.append(row)
    return out


def to_png(pixels: List[List[RGBA]]) -> bytes:
    height = len(pixels)
    width = len(pixels[0])

    raw = bytearray()
    for row in pixels:
        raw.append(0)  # filter type: none
        for r, g, b, a in row:
            raw += bytes((r, g, b, a))

    def chunk(tag: bytes, payload: bytes) -> bytes:
        data = tag + payload
        return struct.pack(">I", len(payload)) + data + struct.pack(">I", zlib.crc32(data))

    header = struct.pack(">IIBBBBB", width, height, 8, 6, 0, 0, 0)  # 8-bit RGBA
    return (
        b"\x89PNG\r\n\x1a\n"
        + chunk(b"IHDR", header)
        + chunk(b"IDAT", zlib.compress(bytes(raw), 9))
        + chunk(b"IEND", b"")
    )


def to_ico(frames: List[Tuple[int, bytes]]) -> bytes:
    count = len(frames)
    header = struct.pack("<HHH", 0, 1, count)  # reserved, type=icon, count

    directory = b""
    payload = b""
    offset = 6 + 16 * count

    for size, png in frames:
        # 0 in the width/height byte means 256.
        dimension = 0 if size >= 256 else size
        directory += struct.pack(
            "<BBBBHHII", dimension, dimension, 0, 0, 1, 32, len(png), offset
        )
        payload += png
        offset += len(png)

    return header + directory + payload


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, default=Path(__file__).parent / "app.ico")
    args = parser.parse_args()

    frames = []
    for size in SIZES:
        frames.append((size, to_png(render(size))))
        print(f"  rendered {size}x{size}")

    args.out.write_bytes(to_ico(frames))
    print(f"Wrote {args.out} ({args.out.stat().st_size} bytes)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
