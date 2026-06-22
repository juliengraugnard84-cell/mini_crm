from __future__ import annotations

import math
import struct
import zlib
from pathlib import Path


SIZE = 256
ROOT_DIR = Path(__file__).resolve().parents[1]
ASSETS_DIR = ROOT_DIR / "assets"
PNG_PATH = ASSETS_DIR / "callflow_phone.png"
ICO_PATH = ASSETS_DIR / "callflow_phone.ico"


def clamp(value: float, low: float = 0.0, high: float = 1.0) -> float:
    return max(low, min(high, value))


def lerp(a: float, b: float, t: float) -> float:
    return a + (b - a) * t


def mix_color(color_a, color_b, t: float):
    return tuple(int(round(lerp(a, b, t))) for a, b in zip(color_a, color_b))


def point_segment_distance(px, py, ax, ay, bx, by) -> float:
    abx = bx - ax
    aby = by - ay
    apx = px - ax
    apy = py - ay
    ab_len_sq = (abx * abx) + (aby * aby)
    if ab_len_sq == 0:
        return math.hypot(apx, apy)
    t = clamp(((apx * abx) + (apy * aby)) / ab_len_sq)
    closest_x = ax + (abx * t)
    closest_y = ay + (aby * t)
    return math.hypot(px - closest_x, py - closest_y)


def signed_distance_round_rect(px, py, cx, cy, hx, hy, radius) -> float:
    qx = abs(px - cx) - hx
    qy = abs(py - cy) - hy
    ox = max(qx, 0.0)
    oy = max(qy, 0.0)
    return math.hypot(ox, oy) + min(max(qx, qy), 0.0) - radius


def rounded_rect_alpha(px, py, cx, cy, hx, hy, radius) -> float:
    distance = signed_distance_round_rect(px, py, cx, cy, hx, hy, radius)
    return clamp(0.85 - distance, 0.0, 1.0)


def circle_alpha(px, py, cx, cy, radius, softness=1.0) -> float:
    distance = math.hypot(px - cx, py - cy)
    return clamp((radius - distance) / max(softness, 0.001), 0.0, 1.0)


def polyline_alpha(px, py, points, radius, softness=1.15) -> float:
    best = 10_000.0
    for start, end in zip(points, points[1:]):
        best = min(best, point_segment_distance(px, py, start[0], start[1], end[0], end[1]))
    return clamp((radius - best) / max(softness, 0.001), 0.0, 1.0)


def alpha_composite(base, overlay):
    br, bg, bb, ba = base
    or_, og, ob, oa = overlay

    oa_f = oa / 255.0
    ba_f = ba / 255.0
    out_a = oa_f + (ba_f * (1.0 - oa_f))
    if out_a <= 0:
        return (0, 0, 0, 0)

    out_r = ((or_ * oa_f) + (br * ba_f * (1.0 - oa_f))) / out_a
    out_g = ((og * oa_f) + (bg * ba_f * (1.0 - oa_f))) / out_a
    out_b = ((ob * oa_f) + (bb * ba_f * (1.0 - oa_f))) / out_a
    return (
        int(round(out_r)),
        int(round(out_g)),
        int(round(out_b)),
        int(round(out_a * 255)),
    )


def rgba_bytes(pixels):
    raw = bytearray()
    for y in range(SIZE):
        raw.append(0)
        start = y * SIZE
        for pixel in pixels[start:start + SIZE]:
            raw.extend(pixel)
    return bytes(raw)


def png_chunk(chunk_type: bytes, payload: bytes) -> bytes:
    return (
        struct.pack(">I", len(payload))
        + chunk_type
        + payload
        + struct.pack(">I", zlib.crc32(chunk_type + payload) & 0xFFFFFFFF)
    )


def write_png(path: Path, pixels) -> bytes:
    data = rgba_bytes(pixels)
    compressed = zlib.compress(data, level=9)
    png_bytes = (
        b"\x89PNG\r\n\x1a\n"
        + png_chunk(b"IHDR", struct.pack(">IIBBBBB", SIZE, SIZE, 8, 6, 0, 0, 0))
        + png_chunk(b"IDAT", compressed)
        + png_chunk(b"IEND", b"")
    )
    path.write_bytes(png_bytes)
    return png_bytes


def write_ico(path: Path, png_bytes: bytes) -> None:
    header = struct.pack("<HHH", 0, 1, 1)
    width = 0
    height = 0
    color_count = 0
    reserved = 0
    planes = 1
    bit_count = 32
    image_size = len(png_bytes)
    image_offset = 6 + 16
    entry = struct.pack(
        "<BBBBHHII",
        width,
        height,
        color_count,
        reserved,
        planes,
        bit_count,
        image_size,
        image_offset,
    )
    path.write_bytes(header + entry + png_bytes)


def make_icon_pixels():
    navy_top = (18, 52, 76)
    navy_bottom = (38, 86, 116)
    gold = (225, 177, 76)
    gold_bright = (248, 214, 142)
    shadow = (8, 18, 28)
    soft_glow = (255, 227, 170)
    success = (84, 171, 122)
    pixels = [(0, 0, 0, 0)] * (SIZE * SIZE)

    phone_points = [
        (84, 77),
        (70, 93),
        (66, 110),
        (74, 126),
        (90, 145),
        (111, 166),
        (133, 184),
        (154, 195),
        (170, 192),
        (186, 177),
    ]

    highlight_points = [
        (90, 84),
        (79, 97),
        (77, 111),
        (85, 126),
        (100, 144),
        (120, 163),
        (140, 180),
        (157, 187),
    ]

    for y in range(SIZE):
        py = y + 0.5
        for x in range(SIZE):
            px = x + 0.5
            index = (y * SIZE) + x
            pixel = (0, 0, 0, 0)

            shadow_alpha = rounded_rect_alpha(px, py, 132, 136, 88, 88, 34) * 0.30
            if shadow_alpha > 0:
                pixel = alpha_composite(
                    pixel,
                    (
                        shadow[0],
                        shadow[1],
                        shadow[2],
                        int(round(255 * shadow_alpha)),
                    ),
                )

            panel_alpha = rounded_rect_alpha(px, py, 128, 128, 88, 88, 34)
            if panel_alpha > 0:
                vertical_t = clamp((py - 32) / 192.0)
                panel_color = mix_color(navy_top, navy_bottom, vertical_t)
                glow = circle_alpha(px, py, 104, 78, 84, softness=44) * 0.18
                if glow > 0:
                    panel_color = mix_color(panel_color, soft_glow, glow)
                pixel = alpha_composite(
                    pixel,
                    (
                        panel_color[0],
                        panel_color[1],
                        panel_color[2],
                        int(round(255 * panel_alpha)),
                    ),
                )

            inner_glow = circle_alpha(px, py, 116, 112, 72, softness=62) * 0.10
            if inner_glow > 0:
                pixel = alpha_composite(
                    pixel,
                    (
                        soft_glow[0],
                        soft_glow[1],
                        soft_glow[2],
                        int(round(255 * inner_glow)),
                    ),
                )

            phone_shadow_alpha = polyline_alpha(px, py, [(px_ + 6, py_ + 7) for px_, py_ in phone_points], 23, softness=1.25) * 0.38
            if phone_shadow_alpha > 0:
                pixel = alpha_composite(
                    pixel,
                    (0, 0, 0, int(round(255 * phone_shadow_alpha))),
                )

            handset_alpha = polyline_alpha(px, py, phone_points, 21, softness=1.1)
            if handset_alpha > 0:
                gold_t = clamp((py - 74) / 118.0)
                handset_color = mix_color(gold_bright, gold, gold_t)
                pixel = alpha_composite(
                    pixel,
                    (
                        handset_color[0],
                        handset_color[1],
                        handset_color[2],
                        int(round(255 * handset_alpha)),
                    ),
                )

            handset_highlight = polyline_alpha(px, py, highlight_points, 10, softness=1.0) * 0.72
            if handset_highlight > 0:
                pixel = alpha_composite(
                    pixel,
                    (
                        255,
                        243,
                        210,
                        int(round(255 * handset_highlight)),
                    ),
                )

            dot_alpha = circle_alpha(px, py, 185, 73, 15, softness=1.4)
            if dot_alpha > 0:
                pixel = alpha_composite(
                    pixel,
                    (
                        success[0],
                        success[1],
                        success[2],
                        int(round(220 * dot_alpha)),
                    ),
                )

            ring_alpha = circle_alpha(px, py, 185, 73, 22, softness=1.8) * 0.18
            if ring_alpha > 0:
                pixel = alpha_composite(
                    pixel,
                    (
                        255,
                        255,
                        255,
                        int(round(255 * ring_alpha)),
                    ),
                )

            pixels[index] = pixel

    return pixels


def main():
    ASSETS_DIR.mkdir(parents=True, exist_ok=True)
    pixels = make_icon_pixels()
    png_bytes = write_png(PNG_PATH, pixels)
    write_ico(ICO_PATH, png_bytes)
    print(PNG_PATH)
    print(ICO_PATH)


if __name__ == "__main__":
    main()
