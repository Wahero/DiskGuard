#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""DiskGuard 桌寵美術：純 stdlib（無 numpy／無外部圖檔）的軟體渲染器。

設計：以 100×100 設計座標繪製「金邊黑貓型機械人」，輸出 BGRA bytes。
- 解析式抗鋸齒：每個形狀按掃描線算垂直／水平覆蓋率，不做超取樣。
- 金屬感：多段垂直漸層 + 左上高光 + 右側冷色輪光 + 底部接觸陰影。
- 只依賴 array / math，可直接被 pet.py 與離線預覽共用。
"""
from __future__ import annotations

import math
from array import array

# ---------------------------------------------------------------- 調色盤
GOLD_HI = (244, 214, 148)
GOLD = (205, 162, 74)
GOLD_LO = (140, 100, 38)
SHELL_HI = (82, 92, 108)
SHELL = (50, 56, 66)
SHELL_LO = (24, 28, 35)
VISOR_HI = (26, 33, 44)
VISOR = (10, 13, 18)
VISOR_LO = (5, 6, 9)
AMBER = (255, 205, 132)
AMBER_HOT = (255, 158, 62)
RED_EYE = (255, 132, 104)
BLUSH = (255, 150, 96)


def _clamp(v, lo=0.0, hi=1.0):
    return lo if v < lo else (hi if v > hi else v)


def _mix(a, b, t):
    t = _clamp(t)
    return (a[0] + (b[0] - a[0]) * t,
            a[1] + (b[1] - a[1]) * t,
            a[2] + (b[2] - a[2]) * t)


def _grad(stops, t):
    """stops = [(pos, rgb), ...]，t∈[0,1]。"""
    t = _clamp(t)
    if t <= stops[0][0]:
        return stops[0][1]
    for i in range(1, len(stops)):
        p0, c0 = stops[i - 1]
        p1, c1 = stops[i]
        if t <= p1:
            span = (p1 - p0) or 1.0
            return _mix(c0, c1, (t - p0) / span)
    return stops[-1][1]


def _ear_path(start, curves, steps=12):
    """三次 Bézier 取樣；讓耳尖與耳廓不再是死板直線三角形。"""
    pts = [start]
    p0 = start
    for c1, c2, p3 in curves:
        for i in range(1, steps + 1):
            t = i / float(steps)
            u = 1.0 - t
            x = (u * u * u * p0[0] + 3 * u * u * t * c1[0] +
                 3 * u * t * t * c2[0] + t * t * t * p3[0])
            y = (u * u * u * p0[1] + 3 * u * u * t * c1[1] +
                 3 * u * t * t * c2[1] + t * t * t * p3[1])
            pts.append((x, y))
        p0 = p3
    return pts


# 固定耳廓與漸層只算一次；右耳仍以 x=50 鏡像，避免動作切換時跳形。
_EAR_OUTER_PATH = _ear_path((17.8, 20.2), [
    ((19.6, 10.5), (24.0, 3.9), (28.0, 2.8)),
    ((31.2, 3.8), (36.2, 10.5), (40.0, 19.8)),
    ((36.0, 22.0), (22.0, 22.6), (17.8, 20.2)),
])
_EAR_INNER_PATH = _ear_path((21.8, 17.6), [
    ((23.0, 11.0), (25.7, 6.8), (28.2, 6.6)),
    ((30.5, 7.2), (34.2, 11.8), (36.2, 17.4)),
    ((31.5, 19.0), (26.0, 19.2), (21.8, 17.6)),
])
_EAR_OUTER_GRAD = ((0.0, GOLD_HI), (0.42, GOLD), (1.0, GOLD_LO))
_EAR_INNER_GRAD = ((0.0, (88, 58, 39)),
                   (0.55, (51, 32, 24)),
                   (1.0, (20, 15, 13)))


def _ear_outer_grad(t):
    return _grad(_EAR_OUTER_GRAD, t)


def _ear_inner_grad(t):
    return _grad(_EAR_INNER_GRAD, t)


class Canvas:
    """RGBA 浮點畫布（0..1，非預乘），輸出時轉 BGRA bytes。"""

    def __init__(self, w, h):
        self.w, self.h = w, h
        self.px = array('f', [0.0]) * (w * h * 4)

    # ---- 基本混色
    def _blend(self, x, y, rgb, a):
        if a <= 0.002 or x < 0 or y < 0 or x >= self.w or y >= self.h:
            return
        i = (y * self.w + x) * 4
        p = self.px
        if a == 1.0:
            p[i] = rgb[0] / 255.0
            p[i + 1] = rgb[1] / 255.0
            p[i + 2] = rgb[2] / 255.0
            p[i + 3] = 1.0
            return
        da = p[i + 3]
        na = a + da * (1.0 - a)
        if na <= 0.0:
            return
        inv = da * (1.0 - a)
        r, g, b = rgb[0] / 255.0, rgb[1] / 255.0, rgb[2] / 255.0
        p[i] = (r * a + p[i] * inv) / na
        p[i + 1] = (g * a + p[i + 1] * inv) / na
        p[i + 2] = (b * a + p[i + 2] * inv) / na
        p[i + 3] = na

    # ---- 形狀：圓角矩形（可帶漸層）
    def rrect(self, x0, y0, x1, y1, r, color=None, alpha=1.0, grad=None):
        r = max(0.0, min(r, (x1 - x0) / 2.0, (y1 - y0) / 2.0))
        hgt = (y1 - y0) or 1.0
        ys = max(0, int(math.floor(y0)))
        ye = min(self.h - 1, int(math.ceil(y1)))
        for y in range(ys, ye + 1):
            cy = y + 0.5
            cov_y = _clamp(min(y + 1.0, y1) - max(float(y), y0))
            if cov_y <= 0:
                continue
            inset = 0.0
            if cy < y0 + r:
                d = (y0 + r) - cy
                inset = r - math.sqrt(max(0.0, r * r - d * d))
            elif cy > y1 - r:
                d = cy - (y1 - r)
                inset = r - math.sqrt(max(0.0, r * r - d * d))
            xa, xb = x0 + inset, x1 - inset
            if xb <= xa:
                continue
            xs = max(0, int(math.floor(xa)))
            xe = min(self.w - 1, int(math.ceil(xb)))
            t = ((cy - y0) / hgt)
            c = grad(t) if grad else color
            for x in range(xs, xe + 1):
                cov = _clamp(min(x + 1.0, xb) - max(float(x), xa))
                if cov > 0:
                    self._blend(x, y, c, alpha * cov * cov_y)

    # ---- 形狀：橢圓
    def ellipse(self, cx, cy, rx, ry, color=None, alpha=1.0, grad=None,
                inner=0.0):
        if rx <= 0 or ry <= 0:
            return
        ys = max(0, int(math.floor(cy - ry)))
        ye = min(self.h - 1, int(math.ceil(cy + ry)))
        for y in range(ys, ye + 1):
            dy = (y + 0.5 - cy) / ry
            if abs(dy) >= 1.0:
                continue
            half = rx * math.sqrt(max(0.0, 1.0 - dy * dy))
            cov_y = _clamp(min(y + 1.0, cy + ry) - max(float(y), cy - ry))
            if cov_y <= 0:
                continue
            if inner > 0:
                half_in = half * (1.0 - inner)
                xa, xb = cx - half, cx + half
                xai, xbi = cx - half_in, cx + half_in
            else:
                xa, xb = cx - half, cx + half
                xai = xbi = None
            t = (y + 0.5 - (cy - ry)) / (2 * ry)
            c = grad(t) if grad else color
            xs = max(0, int(math.floor(xa)))
            xe = min(self.w - 1, int(math.ceil(xb)))
            for x in range(xs, xe + 1):
                cov = _clamp(min(x + 1.0, xb) - max(float(x), xa))
                if cov <= 0:
                    continue
                if xai is not None:
                    inside = _clamp(min(x + 1.0, xbi) - max(float(x), xai))
                    cov *= (1.0 - inside)
                    if cov <= 0:
                        continue
                self._blend(x, y, c, alpha * cov * cov_y)

    # ---- 形狀：多邊形（貓耳、身體）
    def poly(self, pts, color=None, alpha=1.0, grad=None):
        if not pts:
            return
        y0 = min(p[1] for p in pts)
        y1 = max(p[1] for p in pts)
        ys = max(0, int(math.floor(y0)))
        ye = min(self.h - 1, int(math.ceil(y1)))
        n = len(pts)
        for y in range(ys, ye + 1):
            cy = y + 0.5
            xs = []
            for i in range(n):
                ax, ay = pts[i]
                bx, by = pts[(i + 1) % n]
                if (ay <= cy < by) or (by <= cy < ay):
                    xs.append(ax + (cy - ay) * (bx - ax) / (by - ay))
            if len(xs) < 2:
                continue
            xa, xb = min(xs), max(xs)
            t = (cy - y0) / ((y1 - y0) or 1.0)
            c = grad(t) if grad else color
            px0 = max(0, int(math.floor(xa)))
            px1 = min(self.w - 1, int(math.ceil(xb)))
            for x in range(px0, px1 + 1):
                cov = _clamp(min(x + 1.0, xb) - max(float(x), xa))
                if cov > 0:
                    self._blend(x, y, c, alpha * cov)

    def glow(self, cx, cy, rx, ry, color, alpha=0.5, power=2.0):
        """柔和光暈（供眼睛 bloom 用）。"""
        ys = max(0, int(cy - ry))
        ye = min(self.h - 1, int(cy + ry))
        for y in range(ys, ye + 1):
            dy = (y + 0.5 - cy) / ry
            if abs(dy) >= 1.0:
                continue
            half = rx * math.sqrt(max(0.0, 1.0 - dy * dy))
            xs = max(0, int(math.floor(cx - half)))
            xe = min(self.w - 1, int(math.ceil(cx + half)))
            for x in range(xs, xe + 1):
                dx = (x + 0.5 - cx) / rx
                d = math.sqrt(dx * dx + dy * dy)
                if d >= 1.0:
                    continue
                f = (1.0 - d) ** power
                self._blend(x, y, color, alpha * f)

    def out_bgra(self):
        """轉成 BGRA bytes（straight alpha，供 UpdateLayeredWindow）。"""
        buf = bytearray(self.w * self.h * 4)
        p = self.px
        for i in range(0, len(p), 4):
            a = p[i + 3]
            if a <= 0.004:
                continue
            j = i
            buf[j] = int(_clamp(p[i + 2]) * 255)
            buf[j + 1] = int(_clamp(p[i + 1]) * 255)
            buf[j + 2] = int(_clamp(p[i]) * 255)
            buf[j + 3] = int(_clamp(a) * 255)
        return bytes(buf)


# ---------------------------------------------------------------- 造型
def _eye_style(frame, tick):
    """回傳眼睛表現：'open' / 'blink' / 'happy' / 'sleep' / 'wide' / 'scan' / 'pause'。"""
    if frame == 'blink':
        return 'blink'
    if frame == 'happy':
        return 'happy'
    if frame == 'sleep':
        return 'sleep'
    if frame == 'drag':
        return 'wide'
    if frame == 'scan':
        return 'scan'
    if frame == 'degraded':
        return 'blink'
    if frame == 'paused':
        return 'pause'
    if frame == 'alert':
        return 'wide'
    return 'open'


def render(frame='idle', size=96, tick=0, scale=1.0, eye=None, mouth=None):
    """渲染單一幀，回傳 BGRA bytes（size×size）。

    scale  整體縮放（1.0 = 設計尺寸；滑鼠移入時由 pet.py 傳 1.05 做「放大」）
    eye    覆寫眼睛表情（'open'／'happy'／'blink'／'wide'／'sleep'／'scan'／'pause'）
    mouth  額外畫嘴：'smile'（∪ 弧）／'talk'（開合）／'o'（小圓）

    縮放作法：先畫在 big×big 畫布上（u = big/100），再裁切／補邊回 size×size。
    不可把位移加進 P()——P() 同時用於半徑與尺寸，加了位移會把所有圓角與
    眼睛一起縮小（曾因此讓嘴巴、眼睛在 104 px 消失）。
    """
    big = max(8, int(round(size * max(0.4, min(2.0, scale)))))
    u = big / 100.0                       # 設計單位 → 像素
    cv = Canvas(big, big)

    def P(v):                              # 設計座標 → 像素
        return v * u

    alert = frame in ('alert', 'degraded')
    eye_rgb = RED_EYE if alert else AMBER
    eye_hot = (255, 96, 72) if alert else AMBER_HOT

    # 落地陰影；抓起時縮小、變淡，強化「被拎起來」的感覺。
    grabbed = frame == 'drag'
    cv.ellipse(P(50), P(94.5), P(20 if grabbed else 27),
               P(2.4 if grabbed else 3.4), (0, 0, 0), 0.18 if grabbed else 0.30)
    cv.ellipse(P(50), P(94.0), P(12 if grabbed else 17),
               P(1.5 if grabbed else 2.2), (0, 0, 0), 0.12 if grabbed else 0.22)

    # ---- 貓耳（圓弧機械耳殼＋柔軟內耳），畫在頭後面
    # 左耳標準輪廓；右耳以 x=50 鏡像，確保動作切換時不會跳形。
    for sx in (-1, 1):
        mirror = (lambda p: (p[0], p[1])) if sx == -1 else \
                 (lambda p: (100.0 - p[0], p[1]))
        outer = [mirror(p) for p in _EAR_OUTER_PATH]
        # 深一階的外框讓小尺寸也有清晰輪廓，內層再保留金屬漸層。
        cv.poly([(P(x), P(y)) for x, y in outer], GOLD_LO, 1.0)
        cx, cy = (29.0 if sx == -1 else 71.0), 14.8
        inset = [(cx + (x - cx) * 0.93, cy + (y - cy) * 0.91)
                 for x, y in outer]
        cv.poly([(P(x), P(y)) for x, y in inset], None, 1.0,
                grad=_ear_outer_grad)
        inner = [mirror(p) for p in _EAR_INNER_PATH]
        cv.poly([(P(x), P(y)) for x, y in inner], None, 0.98,
                grad=_ear_inner_grad)
        # 內耳底部一點暖色反射，避免看起來像貼上的黑色紙片。
        cv.ellipse(P(28.5 if sx == -1 else 71.5), P(17.2),
                   P(4.0), P(1.1), (150, 92, 52), 0.16)

    # ---- 頭戴耳機橫樑（在頭後面露出一段）
    cv.rrect(P(17), P(20), P(83), P(27), P(3.5), None, 1.0,
             grad=lambda t: _grad([(0.0, GOLD_HI), (0.5, GOLD), (1.0, GOLD_LO)], t))

    # ---- 頭殼（金屬漸層＋高光＋輪光）
    cv.rrect(P(13.0), P(19.0), P(87.0), P(71.0), P(25.0), None, 1.0,
             grad=lambda t: _grad([(0.0, SHELL_HI), (0.30, SHELL),
                                   (0.72, (40, 45, 54)), (1.0, SHELL_LO)], t))
    # 金色細邊（加亮）
    cv.rrect(P(13.0), P(19.0), P(87.0), P(71.0), P(25.0), None, 0.80,
             grad=lambda t: _grad([(0.0, GOLD_HI), (0.45, GOLD), (1.0, GOLD_LO)], t))
    cv.rrect(P(15.2), P(21.0), P(84.8), P(69.0), P(23.0), None, 1.0,
             grad=lambda t: _grad([(0.0, (92, 102, 118)), (0.30, (56, 62, 73)),
                                   (0.75, (36, 40, 48)), (1.0, (22, 25, 31))], t))
    # 左上金屬高光（橢圓反光 + 亮邊）
    cv.ellipse(P(37), P(26.5), P(18), P(6.0), (255, 255, 255), 0.20)
    cv.ellipse(P(33), P(24.8), P(9), P(2.6), (255, 255, 255), 0.22)
    cv.rrect(P(20), P(21.6), P(52), P(23.4), P(1.0), (255, 255, 255), 0.16)
    # 註：右側輪光已於 2026-11-25 09:30 整條移除。
    # 任何貼著輪廓的冷光／高光帶，在深色桌布上都會被讀成「背後有藍色／白色底」，
    # 立體感改由頭殼四段漸層與左上橢圓高光表現。
    # 耳機側罩
    for sx in (-1, 1):
        cx = 50 + sx * 38.5
        cv.ellipse(P(cx), P(45), P(6.4), P(10.5), None, 1.0,
                   grad=lambda t: _grad([(0.0, (96, 104, 118)), (0.5, (52, 58, 68)),
                                         (1.0, (28, 31, 37))], t))
        cv.ellipse(P(cx), P(45), P(4.2), P(7.6), None, 1.0,
                   grad=lambda t: _grad([(0.0, GOLD_HI), (0.45, GOLD), (1.0, GOLD_LO)], t))
        cv.ellipse(P(cx), P(45), P(2.2), P(4.4), (18, 20, 25), 0.92)
        cv.ellipse(P(cx - sx * 1.2), P(39), P(1.6), P(2.6), (255, 255, 255), 0.22)

    # ---- 面罩（近黑玻璃）
    cv.rrect(P(19.5), P(28.5), P(80.5), P(62.5), P(15), None, 1.0,
             grad=lambda t: _grad([(0.0, VISOR_HI), (0.30, VISOR), (1.0, VISOR_LO)], t))
    # 面罩頂部反光帶
    cv.rrect(P(24), P(30.0), P(76), P(34.2), P(6), (150, 190, 230), 0.10)
    # 面罩內緣暗線（上緣加深，做出凹陷玻璃感）
    cv.rrect(P(21.5), P(29.5), P(78.5), P(33.0), P(5), (0, 0, 0), 0.28)

    style = eye or _eye_style(frame, tick)
    if frame == 'drag' and mouth is None:
        mouth = 'o'
    ey = 45.2

    # 面罩底色（供「切半」用）：與面罩漸層完全一致，切完看不出接縫
    def _visor_cut(x0, y0, x1, y1):
        for yy in range(int(math.floor(y0)), int(math.ceil(y1))):
            c = _grad([(0.0, VISOR_HI), (0.30, VISOR), (1.0, VISOR_LO)],
                      _clamp((yy + 0.5 - 28.5) / 34.0))
            cv.rrect(x0, yy, x1, yy + 1, 0.0, c, 1.0)

    def _amber(t):
        return _grad([(0.0, AMBER), (0.45, eye_rgb), (1.0, eye_hot)], t)

    if style in ('open', 'scan', 'blink', 'pause'):
        hgt = {'blink': 1.3, 'pause': 2.8}.get(style, 4.4)
        cv.glow(P(50), P(ey), P(30), P(12), eye_hot, 0.14, 2.4)
        for sx in (-1, 1):
            cx = 50 + sx * 11.5
            cv.rrect(P(cx - 6.6), P(ey - hgt / 2), P(cx + 6.6), P(ey + hgt / 2),
                     P(hgt / 2), None, 1.0,
                     grad=lambda t: _grad([(0.0, AMBER), (0.42, eye_rgb),
                                           (1.0, eye_hot)], t))
            cv.glow(P(cx), P(ey), P(9.5), P(6.2), eye_hot, 0.26, 2.2)
            if style == 'open':
                cv.ellipse(P(cx - 4.2), P(ey - 0.9), P(1.3), P(0.9),
                           (255, 252, 240), 0.55)
        if style == 'scan':
            ph = (tick % 24) / 24.0
            k = ph if ph < 0.5 else 1.0 - ph
            sx = -6.6 + 13.2 * k
            for base in (-11.5, 11.5):
                cv.rrect(P(50 + base + sx - 1.1), P(ey - 1.7),
                         P(50 + base + sx + 1.1), P(ey + 1.7),
                         P(1.1), (255, 252, 236), 0.45)
    elif style in ('happy', 'sleep'):
        cv.glow(P(50), P(ey), P(29), P(11), eye_hot, 0.12, 2.4)
        happy = (style == 'happy')
        # 環形描邊 + 用面罩底色切掉一半 → 小尺寸（104 px）也不會淡成看不見
        cy = ey + (0.6 if happy else -0.4)
        for sx in (-1, 1):
            cx = 50 + sx * 11.5
            cv.ellipse(P(cx), P(cy), P(4.9), P(4.9), None, 1.0,
                       grad=_amber, inner=0.58)
            if happy:      # 保留上半弧 ∩
                _visor_cut(P(cx - 6.0), P(cy + 0.15), P(cx + 6.0), P(cy + 6.0))
            else:          # 保留下半弧 ∪
                _visor_cut(P(cx - 6.0), P(cy - 6.0), P(cx + 6.0), P(cy - 0.15))
            cv.glow(P(cx), P(cy), P(9), P(7), eye_hot, 0.16, 2.2)
    elif style == 'wide':
        cv.glow(P(50), P(ey), P(32), P(13), eye_hot, 0.18, 2.2)
        for sx in (-1, 1):
            cx = 50 + sx * 11.8
            cv.ellipse(P(cx), P(ey), P(6.2), P(6.0), None, 1.0,
                       grad=lambda t: _grad([(0.0, (255, 236, 206)),
                                             (0.40, eye_rgb), (1.0, eye_hot)], t))
            cv.ellipse(P(cx), P(ey + 0.6), P(2.9), P(3.1), (26, 14, 8), 0.92)
            cv.ellipse(P(cx - 2.0), P(ey - 2.4), P(1.9), P(1.6),
                       (255, 255, 255), 0.60)

    # 腮紅（極淡柔光）
    for sx in (-1, 1):
        cv.glow(P(50 + sx * 23.5), P(55.0), P(5.4), P(2.8), (255, 156, 118), 0.08, 1.6)

    # ---- 嘴（只在懸停等互動時出現；面罩下緣）
    if mouth:
        my = 57.0
        if mouth == 'smile':
            # ∪ 弧：環形描邊後切掉上半，與笑眼同一手法（小尺寸也清楚）
            cv.ellipse(P(50), P(my - 3.0), P(4.6), P(4.6), None, 1.0,
                       grad=_amber, inner=0.56)
            _visor_cut(P(42), P(my - 8.4), P(58), P(my - 2.86))
            cv.glow(P(50), P(my - 0.8), P(7.0), P(4.0), eye_hot, 0.18, 2.0)
        elif mouth == 'talk':
            # 開合：高度隨 tick 起伏，做出「說話」感
            k = 0.5 + 0.5 * math.sin(tick * 1.15)
            hgt = 1.5 + 2.6 * k
            wid = 4.4 + 1.1 * k
            cv.ellipse(P(50), P(my), P(wid), P(hgt), None, 1.0,
                       grad=lambda t: _grad([(0.0, AMBER), (0.55, AMBER_HOT),
                                             (1.0, (150, 62, 20))], t))
            cv.glow(P(50), P(my), P(wid + 2.0), P(hgt + 1.4), AMBER_HOT, 0.22, 2.0)
        elif mouth == 'o':
            cv.ellipse(P(50), P(my), P(2.6), P(2.6), None, 1.0,
                       grad=lambda t: _grad([(0.0, AMBER), (1.0, AMBER_HOT)], t))

    # ---- 頸部陰影（頭與身體的接觸暗面）
    cv.ellipse(P(50), P(69.5), P(20), P(4.2), (0, 0, 0), 0.45)

    # ---- 身體（外套）：肩寬、下擺略收，正面帶金拉鍊
    cv.rrect(P(24.5), P(66.0), P(75.5), P(91.0), P(13.0), None, 1.0,
             grad=lambda t: _grad([(0.0, (74, 81, 94)), (0.38, (46, 51, 61)),
                                   (1.0, (23, 26, 32))], t))
    # 肩部金屬反光
    for sx in (-1, 1):
        cv.ellipse(P(50 + sx * 24.5), P(70.5), P(5.2), P(3.4),
                   (190, 200, 215), 0.10)
    # 衣領（V 形金邊）
    cv.poly([(P(37.5), P(66.0)), (P(50), P(74.0)), (P(62.5), P(66.0)),
             (P(62.5), P(69.0)), (P(50), P(77.0)), (P(37.5), P(69.0))],
            None, 1.0, grad=lambda t: _grad([(0.0, GOLD_HI), (1.0, GOLD_LO)], t))
    # 內襯（領口深色）
    cv.poly([(P(41.0), P(66.0)), (P(50), P(72.0)), (P(59.0), P(66.0))],
            (14, 16, 20), 0.9)
    # 拉鍊
    cv.rrect(P(49.1), P(74.5), P(50.9), P(88.0), P(0.9), None, 0.85,
             grad=lambda t: _grad([(0.0, GOLD_HI), (1.0, GOLD)], t))
    # 胸口徽章
    cv.ellipse(P(61.5), P(80.0), P(3.2), P(3.2), None, 1.0,
               grad=lambda t: _grad([(0.0, GOLD_HI), (1.0, GOLD_LO)], t))
    cv.ellipse(P(61.5), P(80.0), P(1.7), P(1.7), (32, 26, 16), 0.95)
    # 手臂（在身側外緣，露出手臂輪廓）；抓起時雙手略抬、外張。
    for sx in (-1, 1):
        cx = 50 + sx * (32.0 if grabbed else 30.2)
        ay0, ay1, hy = (65.8, 83.4, 83.8) if grabbed else (69.6, 87.2, 87.6)
        cv.rrect(P(cx - 4.8), P(ay0), P(cx + 4.8), P(ay1), P(4.8), None, 1.0,
                 grad=lambda t: _grad([(0.0, (78, 86, 100)), (0.5, (48, 54, 64)),
                                       (1.0, (24, 27, 33))], t))
        cv.rrect(P(cx - 4.8), P(ay0), P(cx + 4.8), P(ay1), P(4.8), GOLD, 0.22)
        # 手掌
        cv.ellipse(P(cx), P(hy), P(4.0), P(3.4), (30, 33, 39), 0.98)
        cv.ellipse(P(cx), P(hy), P(4.0), P(3.4), GOLD, 0.26, inner=0.58)
    # 腳（與身體連在一起）
    for sx in (-1, 1):
        cx = 50 + sx * 10.5
        cv.rrect(P(cx - 8.4), P(88.5), P(cx + 8.4), P(95.2), P(3.6), None, 1.0,
                 grad=lambda t: _grad([(0.0, (42, 46, 54)), (1.0, (17, 19, 23))], t))
        cv.rrect(P(cx - 8.4), P(92.8), P(cx + 8.4), P(95.2), P(2.4), GOLD, 0.26)

    # 註：整體右緣輪光同於 09:30 移除（見上）。

    if big == size:
        return cv.out_bgra()
    return _fit(cv.out_bgra(), big, size)


def _fit(src, frm, to):
    """把 frm×frm 的 BGRA 置中裁切（frm>to）或補透明邊（frm<to）成 to×to。"""
    out = bytearray(to * to * 4)
    if frm >= to:
        skip = (frm - to) // 2
        n = to
        for y in range(to):
            so = ((y + skip) * frm + skip) * 4
            out[y * to * 4:(y + 1) * to * 4] = src[so:so + n * 4]
    else:
        pad = (to - frm) // 2
        n = frm
        for y in range(frm):
            so = y * frm * 4
            dst = ((y + pad) * to + pad) * 4
            out[dst:dst + n * 4] = src[so:so + n * 4]
    return bytes(out)


def render_dib(frame, size, tick, bits_ptr):
    """把渲染結果直接寫進 ctypes DIB 記憶體（給 pet.py 用）。"""
    import ctypes
    data = render(frame, size, tick)
    ctypes.memmove(bits_ptr, data, len(data))
