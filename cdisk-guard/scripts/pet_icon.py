# -*- coding: utf-8 -*-
"""pet_icon.py — 由桌寵「機械人頭」產生托盤 ICO（純 stdlib，零 PIL／零外部圖檔）。

    python scripts/pet_icon.py        # 產生 assets/tray.ico 與 assets/tray-alert.ico

作法是直接呼叫 `pet_art.render()` 拿同一套造型的 BGRA 像素，只裁頭部
（貓耳＋頭殼＋面罩＋眼睛＋耳機），再用**預乘 alpha 的面積平均**縮到
64／32／16 三種尺寸 —— Windows 會依托盤 DPI 自動挑選。
警示版沿用 `alert` 幀（紅眼），與桌面上的桌寵完全一致。
ICO 為標準 BMP-DIB 格式（32bpp＋AND mask），`LoadImageW` 可直接讀。
"""
import math
import os
import struct
import tempfile
import threading

import pet_art

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ASSETS = os.path.join(ROOT, 'assets')

# 頭部裁切框（100×100 設計座標，x0,y0,x1,y1）：含貓耳尖到頸部
HEAD_BOX = (2.0, 0.0, 98.0, 80.0)
# 渲染基準尺寸：先畫大圖再縮小，鋸齒與細節比直接畫小圖好
SRC = 200


def _crop(src, size, box):
    """從 size×size 的 BGRA 取設計座標 box 的區域。"""
    u = size / 100.0
    x0 = max(0, int(round(box[0] * u)))
    y0 = max(0, int(round(box[1] * u)))
    x1 = min(size, int(round(box[2] * u)))
    y1 = min(size, int(round(box[3] * u)))
    cw, ch = x1 - x0, y1 - y0
    out = bytearray(cw * ch * 4)
    for y in range(ch):
        so = ((y0 + y) * size + x0) * 4
        out[y * cw * 4:(y + 1) * cw * 4] = src[so:so + cw * 4]
    return out, cw, ch


def _resize(src, sw, sh, dw, dh):
    """預乘 alpha 的面積平均縮放（避免透明邊發黑）。"""
    out = bytearray(dw * dh * 4)
    if dw <= 0 or dh <= 0:
        return out
    for dy in range(dh):
        y0f, y1f = dy * sh / float(dh), (dy + 1) * sh / float(dh)
        for dx in range(dw):
            x0f, x1f = dx * sw / float(dw), (dx + 1) * sw / float(dw)
            sa = sr = sg = sb = ws = 0.0
            for y in range(int(y0f), min(sh, int(math.ceil(y1f)))):
                wy = min(y + 1.0, y1f) - max(float(y), y0f)
                if wy <= 0:
                    continue
                for x in range(int(x0f), min(sw, int(math.ceil(x1f)))):
                    wx = min(x + 1.0, x1f) - max(float(x), x0f)
                    if wx <= 0:
                        continue
                    w = wx * wy
                    i = (y * sw + x) * 4
                    a = src[i + 3] / 255.0
                    ws += w
                    sa += a * w
                    sb += src[i] / 255.0 * a * w
                    sg += src[i + 1] / 255.0 * a * w
                    sr += src[i + 2] / 255.0 * a * w
            if ws <= 0:
                continue
            o = (dy * dw + dx) * 4
            a = sa / ws
            if a <= 0.0015:
                continue
            out[o] = min(255, int(round(sb / ws / a * 255)))
            out[o + 1] = min(255, int(round(sg / ws / a * 255)))
            out[o + 2] = min(255, int(round(sr / ws / a * 255)))
            out[o + 3] = min(255, int(round(a * 255)))
    return out


_SOURCES = {}
_SOURCE_LOCK = threading.Lock()


def _head_source(alert):
    """每種造型只渲染一次 200px 源圖，之後各尺寸共用同一裁切結果。"""
    key = bool(alert)
    with _SOURCE_LOCK:
        source = _SOURCES.get(key)
        if source is None:
            frame = 'alert' if key else 'idle'
            full = pet_art.render(frame, SRC, 0)
            source = _crop(full, SRC, HEAD_BOX)
            _SOURCES[key] = source
        return source


def draw(n=64, alert=False):
    """回傳 n×n BGRA bytearray（上到下），內容為機械人頭。"""
    part, cw, ch = _head_source(alert)
    k = min(n / float(cw), n / float(ch))
    tw, th = max(1, int(round(cw * k))), max(1, int(round(ch * k)))
    small = _resize(part, cw, ch, tw, th)
    out = bytearray(n * n * 4)
    ox, oy = (n - tw) // 2, (n - th) // 2
    for y in range(th):
        so = y * tw * 4
        do = ((oy + y) * n + ox) * 4
        out[do:do + tw * 4] = small[so:so + tw * 4]
    return out


def _ico_bytes(images):
    """images: [(size, BGRA top-down bytearray), ...] → ICO bytes。"""
    n = len(images)
    head = struct.pack('<HHH', 0, 1, n)
    offset = 6 + 16 * n
    entries, blobs = [], []
    for size, bgra in images:
        dib = struct.pack('<IiiHHIIiiII', 40, size, size * 2, 1, 32, 0,
                          size * size * 4, 0, 0, 0, 0)
        rows = b''.join(bytes(bgra[(size - 1 - y) * size * 4:
                                   size * size * 4 - y * size * 4])
                        for y in range(size))
        # AND mask（全 0：沿用 alpha 通道；1bpp 每行補到 4 bytes）
        stride = ((size + 31) // 32) * 4
        mask = b'\x00' * (stride * size)
        blob = dib + rows + mask
        entries.append(struct.pack('<BBBBHHII', size % 256, size % 256, 0, 0,
                                   1, 32, len(blob), offset))
        blobs.append(blob)
        offset += len(blob)
    return head + b''.join(entries) + b''.join(blobs)


def generate():
    if not os.path.isdir(ASSETS):
        os.makedirs(ASSETS)
    paths = []
    # 16 px 托盤要以清晰為先：小尺寸直接由大圖面積平均而來，不再二次縮放。
    # 也備好 20／24／40 —— 125%／150% 縮放下托盤實際要 20／24 px，
    # 若只給 16 就會被系統再放大一次（發糊）。
    for name, alert in (('tray', False), ('tray-alert', True)):
        imgs = [(s, draw(s, alert)) for s in (64, 48, 40, 32, 24, 20, 16)]
        data = _ico_bytes(imgs)
        p = os.path.join(ASSETS, name + '.ico')
        tmp = None
        try:
            fd, tmp = tempfile.mkstemp(prefix=name + '.', suffix='.tmp', dir=ASSETS)
            with os.fdopen(fd, 'wb') as f:
                f.write(data)
            os.replace(tmp, p)
        finally:
            if tmp:
                try:
                    os.remove(tmp)
                except OSError:
                    pass
        paths.append(p)
    return paths


_HANDLES = {}


def load_handle(alert=False):
    """回傳 HICON；失敗回 None（呼叫端可降級回系統圖示）。"""
    key = bool(alert)
    if key in _HANDLES:
        return _HANDLES[key]
    p = os.path.join(ASSETS, 'tray-alert.ico' if alert else 'tray.ico')
    if not os.path.exists(p):
        try:
            generate()
        except Exception:
            return None
    try:
        import ctypes
        from ctypes import wintypes
        u = ctypes.windll.user32
        u.LoadImageW.argtypes = [wintypes.HINSTANCE, wintypes.LPCWSTR,
                                 wintypes.UINT, ctypes.c_int, ctypes.c_int,
                                 wintypes.UINT]
        u.LoadImageW.restype = wintypes.HICON
        h = u.LoadImageW(0, p, 1, 0, 0, 0x10)   # IMAGE_ICON, LR_LOADFROMFILE
        if h:
            _HANDLES[key] = h
        return h or None
    except Exception:
        return None


if __name__ == '__main__':
    for p in generate():
        print('%s bytes=%d' % (p, os.path.getsize(p)))
