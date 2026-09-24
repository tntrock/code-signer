"""產生 assets/icon.ico（只用 Python 標準函式庫）。

圖案：藍色圓角方塊上的白色勾號，代表「已簽章」。
執行：python assets/gen_icon.py
"""
import math
import struct
import zlib
from pathlib import Path

SIZES = [16, 32, 48, 256]
BG = (0x1F, 0x6F, 0xEB)
FG = (0xFF, 0xFF, 0xFF)


def dist_to_segment(px, py, ax, ay, bx, by):
    dx, dy = bx - ax, by - ay
    t = max(0.0, min(1.0, ((px - ax) * dx + (py - ay) * dy) / (dx * dx + dy * dy)))
    return math.hypot(px - (ax + t * dx), py - (ay + t * dy))


def pixel(u, v):
    """u, v ∈ [0,1)；回傳 RGBA。"""
    r = 0.2  # 圓角半徑
    cx = min(max(u, r), 1 - r)
    cy = min(max(v, r), 1 - r)
    if math.hypot(u - cx, v - cy) > r:
        return (0, 0, 0, 0)
    d = min(
        dist_to_segment(u, v, 0.26, 0.52, 0.43, 0.69),
        dist_to_segment(u, v, 0.43, 0.69, 0.76, 0.33),
    )
    return (*FG, 255) if d < 0.075 else (*BG, 255)


def png(size):
    ss = 4  # 超取樣抗鋸齒
    rows = []
    for y in range(size):
        row = bytearray([0])
        for x in range(size):
            acc = [0, 0, 0, 0]
            for sy in range(ss):
                for sx in range(ss):
                    p = pixel((x + (sx + 0.5) / ss) / size, (y + (sy + 0.5) / ss) / size)
                    for i in range(4):
                        acc[i] += p[i]
            row += bytes(c // (ss * ss) for c in acc)
        rows.append(bytes(row))

    def chunk(tag, data):
        return struct.pack(">I", len(data)) + tag + data + struct.pack(">I", zlib.crc32(tag + data))

    ihdr = struct.pack(">IIBBBBB", size, size, 8, 6, 0, 0, 0)
    return b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", ihdr) + chunk(b"IDAT", zlib.compress(b"".join(rows), 9)) + chunk(b"IEND", b"")


def ico(images):
    header = struct.pack("<HHH", 0, 1, len(images))
    offset = 6 + 16 * len(images)
    entries, blobs = b"", b""
    for size, data in images:
        dim = 0 if size >= 256 else size
        entries += struct.pack("<BBBBHHII", dim, dim, 0, 0, 1, 32, len(data), offset)
        offset += len(data)
        blobs += data
    return header + entries + blobs


out = Path(__file__).with_name("icon.ico")
out.write_bytes(ico([(s, png(s)) for s in SIZES]))
print(f"wrote {out}")
