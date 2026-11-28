#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""重新產生 docs/images 的桌寵表情圖與抓起動作預覽（純 stdlib）。"""
import os
import struct
import sys
import zlib

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, HERE)
import pet_art  # noqa: E402

OUT = os.path.join(ROOT, 'docs', 'images')
BG = (20, 22, 28, 255)


def _chunk(kind, data):
    return (struct.pack('>I', len(data)) + kind + data +
            struct.pack('>I', zlib.crc32(kind + data) & 0xffffffff))


def _save(path, w, h, rgba):
    raw = bytearray()
    stride = w * 4
    for y in range(h):
        raw.append(0)
        raw.extend(rgba[y * stride:(y + 1) * stride])
    data = (b'\x89PNG\r\n\x1a\n' +
            _chunk(b'IHDR', struct.pack('>IIBBBBB', w, h, 8, 6, 0, 0, 0)) +
            _chunk(b'IDAT', zlib.compress(bytes(raw), 9)) +
            _chunk(b'IEND', b''))
    with open(path, 'wb') as f:
        f.write(data)


def _canvas(w, h):
    return bytearray(BG * (w * h))


def _paste(dst, dw, bgra, size, x, y):
    for yy in range(size):
        src = yy * size * 4
        out = ((y + yy) * dw + x) * 4
        for xx in range(size):
            b, g, r, a = bgra[src + xx * 4:src + xx * 4 + 4]
            if not a:
                continue
            af = a / 255.0
            di = out + xx * 4
            for c, value in enumerate((r, g, b)):
                dst[di + c] = int(value * af + dst[di + c] * (1.0 - af))
            dst[di + 3] = 255


def _sprite(frame, size, scale=1.0, eye=None, mouth=None, tick=0):
    return pet_art.render(frame=frame, size=size, tick=tick, scale=scale,
                          eye=eye, mouth=mouth)


def make_faces():
    w, h = 1020, 644
    out = _canvas(w, h)
    large = [
        ('idle', None, None, 1.0), ('happy', None, None, 1.0),
        ('blink', None, None, 1.0), ('sleep', None, None, 1.0),
        ('idle', None, None, 1.0), ('alert', None, None, 1.0),
        ('drag', 'wide', 'o', 1.0), ('idle', 'wide', None, 1.0),
    ]
    for i, (frame, eye, mouth, scale) in enumerate(large):
        col, row = i % 4, i // 4
        size = 232
        x, y = 12 + col * 252, 12 + row * 252
        _paste(out, w, _sprite(frame, size, scale, eye, mouth), size, x, y)
    small = [
        ('idle', None, None, 1.0), ('happy', None, None, 1.0),
        ('alert', None, None, 1.0), ('drag', 'wide', 'o', 1.0),
    ]
    for i, (frame, eye, mouth, scale) in enumerate(small):
        size = 112
        x, y = 62 + i * 252, 522
        _paste(out, w, _sprite(frame, size, scale, eye, mouth), size, x, y)
    path = os.path.join(OUT, 'pet-faces.png')
    _save(path, w, h, out)
    return path


def make_grab():
    w, h = 760, 360
    out = _canvas(w, h)
    # 同一視窗基準；左＝預設 0.855，右＝抓起 0.9576（+12%）。
    size = 300
    _paste(out, w, _sprite('idle', size, 0.855), size, 40, 30)
    _paste(out, w, _sprite('drag', size, 0.855 * 1.12, 'wide', 'o'), size, 420, 30)
    path = os.path.join(OUT, 'pet-grab.png')
    _save(path, w, h, out)
    return path


if __name__ == '__main__':
    os.makedirs(OUT, exist_ok=True)
    for p in (make_faces(), make_grab()):
        print(p)
