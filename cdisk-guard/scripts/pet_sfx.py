# -*- coding: utf-8 -*-
r"""pet_sfx.py — DiskGuard 桌寵音效引擎（純 stdlib，零外部音檔／零網路）

用 wave + math 即時合成 16-bit mono WAV，寫入 assets/sfx/ 快取；
播放用 winsound.PlaySound(SND_ASYNC | SND_FILENAME | SND_NODEFAULT)。

設計來源：prototypes/diskguard-pet-live/index.html 的 window.SFX（Web Audio 版）。
兩者共用同一組「動作 → 音色」對照表，確保原型與正式版聽感一致。

對照表（12 動作）：
  idle      低頻正弦緩慢起伏      blink     高頻短 blip 雙音
  peek      三音 ascending        walk      方波腳步聲
  alert     三連鋸齒警報＋低音    scan      300→1400 Hz 掃頻
  happy     大調琶音              sleep     長音下滑
  drag      三角波摩擦下滑        paused    音高下降
  degraded  方波＋噪音抖動        serve     雙音提示

事件：panel_open / panel_close / menu_open / menu_hit / alert_enter /
      scan_start / scan_done / page_open / check / select_all / only_a /
      clear_sel / confirm / delete_exec / delete_done / boot / exit / degrade

邊界：不依賴 winsound 以外的套件；winsound 不可用時所有函式靜默降級（不 crash）。
"""
import os
import math
import time
import wave
import struct
import random
import tempfile
import threading

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SFX_DIR = os.path.join(ROOT, 'assets', 'sfx')
RATE = 22050
AMP = 0.22  # 保守音量，避免干擾日常
_GENERATE_LOCK = threading.Lock()

# name -> (kind, [freq...], duration_sec)
TABLE = {
    # ---- 12 動作 ----
    'idle':     ('sine_fade', [196], 0.55),
    'blink':    ('blip2', [1180, 1560], 0.10),
    'peek':     ('arp', [523, 659, 784], 0.30),
    'walk':     ('steps', [220, 260], 0.34),
    'alert':    ('siren', [740, 620], 0.90),
    'scan':     ('sweep', [300, 1400], 0.75),
    'happy':    ('arp', [523, 659, 784, 1047], 0.62),
    'sleep':    ('slide', [440, 150], 0.85),
    'drag':     ('tri_slide', [300, 120], 0.42),
    'paused':   ('slide', [620, 300], 0.40),
    'degraded': ('noise_square', [180], 0.55),
    'serve':    ('blip2', [784, 1047], 0.30),
    # ---- 特别事件 ----
    'panel_open':   ('blip1', [660], 0.12),
    'panel_close':  ('slide', [660, 440], 0.16),
    'menu_open':    ('blip1', [520], 0.10),
    'menu_hit':     ('blip1', [880], 0.09),
    'alert_enter':  ('siren', [820, 640], 0.75),
    'scan_start':   ('sweep', [400, 900], 0.35),
    'scan_done':    ('arp', [587, 784, 1047], 0.48),
    'page_open':    ('blip2', [784, 1047], 0.30),
    'check':        ('blip2', [980, 1240], 0.09),
    'select_all':   ('arp', [440, 554, 659], 0.20),
    'only_a':       ('arp', [659, 784], 0.18),
    'clear_sel':    ('slide', [700, 420], 0.18),
    'confirm':      ('blip2', [700, 940], 0.18),
    'delete_exec':  ('siren', [560, 420], 0.55),
    'delete_done':  ('arp', [523, 659, 784, 1047], 0.70),
    'boot':         ('arp', [392, 523, 659], 0.45),
    'exit':         ('slide', [523, 262], 0.35),
    'degrade':      ('noise_square', [150], 0.50),
}


def _samples(kind, freqs, dur):
    """回傳 float 序列（-1..1），純數學合成。"""
    n = max(1, int(RATE * dur))
    a = freqs[0]
    b = freqs[1] if len(freqs) > 1 else a
    out = []
    if kind == 'sine_fade':
        for i in range(n):
            t = i / RATE
            env = (0.5 - 0.5 * math.cos(2 * math.pi * t / dur))
            out.append(math.sin(2 * math.pi * a * t) * env)
    elif kind == 'blip1':
        # 單一短音（乾淨的「嘀」）。舊的 blip2 是兩個音，
        # 兩個動作接連觸發時聽起來像「突突」的機槍聲 → 點擊類改用單音。
        for i in range(n):
            t = i / RATE
            env = min(1.0, i / (RATE * 0.006))
            env *= min(1.0, (n - i) / (RATE * 0.03))
            out.append(math.sin(2 * math.pi * a * t) * env)
    elif kind == 'blip2':
        half = n // 2
        for i in range(n):
            t = i / RATE
            f = a if i < half else b
            env = min(1.0, (i % max(1, half)) / (RATE * 0.008))
            env *= min(1.0, (n - i) / (RATE * 0.02))
            out.append(math.sin(2 * math.pi * f * t) * env)
    elif kind == 'arp':
        step = max(1, n // len(freqs))
        for i in range(n):
            f = freqs[min(len(freqs) - 1, i // step)]
            env = min(1.0, (i % step) / (RATE * 0.006))
            env *= min(1.0, (n - i) / (RATE * 0.03))
            out.append(math.sin(2 * math.pi * f * (i / RATE)) * env)
    elif kind == 'steps':
        step = max(1, n // 4)
        for i in range(n):
            f = a if (i // step) % 2 == 0 else b
            env = math.exp(-6.0 * ((i % step) / RATE))
            out.append((1 if math.sin(2 * math.pi * f * (i / RATE)) >= 0 else -1) * env * 0.7)
    elif kind == 'siren':
        for i in range(n):
            t = i / RATE
            phase = (t / dur) * 6.0
            f = a if (phase % 2.0) < 1.0 else b
            env = 0.6 + 0.4 * math.sin(math.pi * t / dur)
            out.append((2.0 / math.pi * math.asin(math.sin(2 * math.pi * f * t))) * env)
            if i > n * 0.8:
                out[-1] += math.sin(2 * math.pi * 90 * t) * 0.35
    elif kind == 'sweep':
        for i in range(n):
            t = i / RATE
            f = a + (b - a) * (t / dur)
            env = 0.45 + 0.55 * math.sin(math.pi * t / dur)
            out.append(math.sin(2 * math.pi * f * t) * env)
    elif kind == 'slide':
        for i in range(n):
            t = i / RATE
            f = a + (b - a) * (t / dur) ** 1.4
            env = math.sin(math.pi * t / dur)
            out.append(math.sin(2 * math.pi * f * t) * env)
    elif kind == 'tri_slide':
        for i in range(n):
            t = i / RATE
            f = a + (b - a) * (t / dur)
            x = (t * f) % 1.0
            tri = 4.0 * abs(x - 0.5) - 1.0
            out.append(tri * math.sin(math.pi * t / dur) * 0.8)
    elif kind == 'noise_square':
        rnd = random.Random(20261124)
        for i in range(n):
            t = i / RATE
            sq = 1 if math.sin(2 * math.pi * a * t) >= 0 else -1
            noise = rnd.uniform(-1, 1)
            env = math.sin(math.pi * t / dur)
            out.append((sq * 0.55 + noise * 0.45) * env)
    else:
        out = [0.0] * n
    return out


def wav_path(name):
    return os.path.join(SFX_DIR, name + '.wav')


def generate(name, force=False):
    """合成單一音效並原子寫入 assets/sfx/<name>.wav；失敗時靜默回傳 None。"""
    if name not in TABLE:
        return None
    tmp = None
    try:
        with _GENERATE_LOCK:
            p = wav_path(name)
            if os.path.exists(p) and not force:
                return p
            os.makedirs(SFX_DIR, exist_ok=True)
            kind, freqs, dur = TABLE[name]
            samples = _samples(kind, freqs, dur)
            frames = b''.join(struct.pack('<h', int(max(-1.0, min(1.0, s)) * AMP * 32767))
                              for s in samples)
            # 每次呼叫都使用獨立暫存檔，避免並發生成互相覆蓋或讀到半成品。
            fd, tmp = tempfile.mkstemp(prefix=name + '.', suffix='.tmp', dir=SFX_DIR)
            os.close(fd)
            with wave.open(tmp, 'wb') as w:
                w.setnchannels(1)
                w.setsampwidth(2)
                w.setframerate(RATE)
                w.writeframes(frames)
            os.replace(tmp, p)
            return p
    except Exception:
        return None
    finally:
        if tmp:
            try:
                os.remove(tmp)
            except OSError:
                pass


def generate_all(force=False):
    """生成全部對照表音效；回傳 {name: path}。"""
    return {k: generate(k, force=force) for k in TABLE}


# 播放節流：winsound 一次只播一個，重疊呼叫會互相切斷（聽感＝「突突」）
MIN_GAP = 0.12
PRIORITY = {'alert', 'alert_enter', 'scan', 'scan_done', 'happy',
            'serve', 'exit', 'paused', 'degraded', 'delete_done', 'boot'}
_LAST = {'name': None, 'ts': None, 'dur': 0.0}
_PLAY_LOCK = threading.Lock()


def play(name, enabled=True):
    """非同步播放；音效停用／名稱不存在／winsound 不可用時靜默返回。

    winsound 的 SND_ASYNC 同時間只能有一個音效——新的會**打斷**舊的。
    若兩個動作在極短時間內各叫一次（例如點一下 → 開面板），
    聽起來就是一串被切斷的「突突」聲。所以這裡加兩道節流：
      1) 全域最小間隔 MIN_GAP：上一個剛響就不疊加（重要音效可插隊）
      2) 同名音效在自身時長內不重播：防止懸停抖動／連點造成機關槍
    """
    global _LAST
    if not enabled or name not in TABLE:
        return False
    # 先在有鎖保護的狀態上做節流判斷，被略過的事件完全不碰檔案系統。
    with _PLAY_LOCK:
        now = time.monotonic()
        gap = now - _LAST['ts'] if _LAST['ts'] is not None else float('inf')
        if name == _LAST['name'] and gap < _LAST['dur'] * 0.9:
            return False
        if gap < MIN_GAP and name not in PRIORITY:
            return False
        try:
            p = wav_path(name)
            if not os.path.exists(p):
                p = generate(name)
            if not p:
                return False
            import winsound
            winsound.PlaySound(p, winsound.SND_ASYNC | winsound.SND_FILENAME |
                               winsound.SND_NODEFAULT)
            _LAST = {'name': name, 'ts': now, 'dur': TABLE[name][2]}
            return True
        except Exception:
            return False


def stop():
    with _PLAY_LOCK:
        try:
            import winsound
            winsound.PlaySound(None, winsound.SND_ASYNC | winsound.SND_PURGE)
        except Exception:
            pass


if __name__ == '__main__':
    made = generate_all(force=True)
    print('generated=%d dir=%s' % (len([x for x in made.values() if x]), SFX_DIR))
    for k in ('idle', 'alert', 'scan', 'happy', 'degraded'):
        print('  %-10s %s bytes' % (k, os.path.getsize(wav_path(k))))
