# -*- coding: utf-8 -*-
r"""pet.py — DiskGuard 桌寵常駐主程式（Phase 2，純 ctypes／零新套件）

    pythonw.exe scripts/pet.py            # 啟動托盤＋桌寵
    pythonw.exe scripts/pet.py --health   # 離線健康查詢（不啟動 UI）
    pythonw.exe scripts/pet.py --selftest # 離線自測

Phase 1（TC-01～TC-08）：
  F1 生命週期／單例、F3 托盤、F4 分層視窗＋拖曳＋位置記憶、
  F5 左鍵唯讀用量面板、F6 右鍵 TrackPopupMenu（三類危險動作排除）、
  F12 heartbeat＋events log、F13 校驗與降級、音效（動作＋事件，默認開啟）。

Phase 2（TC-09～TC-18、TC-21）：
  F7 監測與警示決策（含週一低 CPU 分析，接手 watch 的既有行為）、
  F8 警示演出（跑入動畫＋同時觸發背景分析）、
  F9 背景分析（工作者執行緒 do_scan/do_report，防重入）、
  F10 按需本機服務（GuardServer，127.0.0.1＋隨機埠＋閒置 600 s 自動關閉）。

明確不做：不改開機排程（Phase 3 另行處理）、桌寵控制選單沒有刪除／清回收站／改白名單；
分析結果產生的網頁沿用既有 token＋confirm 雙防護，pet 本身不呼叫 do_delete。

與 cdiskctl.py 的關係：只用既有 load_config/disk_info/log/read_state/write_state/
acquire_lock/out_dir/cmd_watch/do_scan/do_report/GuardServer/weekly_should_run/
run_weekly/decide_notify/write_notice，不修改其任何一行。
"""
import os
import sys
import json
import time
import math
import random
import ctypes
import threading
import datetime
from ctypes import wintypes

# Python 3.13 wintypes 缺若干 HANDLE 別名 → 自行補上（皆為 void*）
for _n in ('HCURSOR', 'HBITMAP', 'HFONT', 'HGDIOBJ', 'HINSTANCE', 'HICON',
           'HBRUSH', 'HDC', 'HMENU', 'HWND', '-ATOM'):
    if _n.startswith('-'):
        continue
    if not hasattr(wintypes, _n):
        setattr(wintypes, _n, ctypes.c_void_p)
if not hasattr(wintypes, 'ATOM'):
    wintypes.ATOM = wintypes.WORD

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPTS = os.path.join(ROOT, 'scripts')
sys.path.insert(0, SCRIPTS)
import cdiskctl as C  # noqa: E402
import pet_sfx  # noqa: E402
import pet_icon  # noqa: E402
try:                                   # 新造型（軟體渲染）；失敗則回退舊 GDI 小碟
    import pet_art  # noqa: E402
except Exception:                      # pragma: no cover
    pet_art = None

# ---------------------------------------------------------------- Win32 常數
WM_TIMER = 0x0113
WM_MEASUREITEM = 0x002C
WM_DRAWITEM = 0x002B
ODT_MENU = 1
ODS_SELECTED = 0x0001
ODS_GRAYED = 0x0002
ODS_CHECKED = 0x0008
MIM_BACKGROUND = 0x00000002
MF_OWNERDRAW = 0x0004
MF_GRAYED = 0x0001
MF_CHECKED = 0x0008
MF_SEPARATOR = 0x0800
VK_ESCAPE = 0x1B
VK_RETURN = 0x0D
VK_UP = 0x26
VK_DOWN = 0x28
WM_QUIT = 0x0012
WM_APP = 0x8000
WM_TRAY = WM_APP + 1
WM_ALERT = WM_APP + 2
WM_EXIT = WM_APP + 7
WM_MENU_DISMISS = WM_APP + 8       # 全域滑鼠鉤子通知選單關閉
WM_MOUSELEAVE = 0x02A3             # TrackMouseEvent 送出的離開通知
WM_TIMER_HOVER = 4                 # 懸停表情動畫計時器
WM_TIMER_BLINK = 5                 # 待機隨機眨眼（一次性 timer 鏈，不常駐輪詢）
# 待機眨眼：平均 10 s 一次（9–11 s 隨機，保留一點不規律感）；閉眼 110 ms；
# 12% 機率連眨兩下。間隔越長 → 喚醒次數越少（省 CPU）。
BLINK_GAP_SEC = (9.0, 11.0)
BLINK_CLOSED_SEC = 0.11
BLINK_DOUBLE_SEC = 0.15
BLINK_DOUBLE_P = 0.12
TME_LEAVE = 0x00000002
WH_MOUSE_LL = 14
HC_ACTION = 0

# 懸停縮放：靜止略小，滑鼠移入時放大（104 px 視窗內不會被裁到）
BASE_SCALE = 0.95
HOVER_SCALE = 1.04
WM_LBUTTONDOWN, WM_LBUTTONUP = 0x0201, 0x0202
WM_RBUTTONDOWN, WM_RBUTTONUP = 0x0204, 0x0205   # 0x0204 是「按下」不是放開
WM_TIMER_USAGE = 1
WM_TIMER_ANIM = 2
WM_TIMER_BEAT = 3

NIM_ADD, NIM_MODIFY, NIM_DELETE = 0, 1, 2
NIF_MESSAGE, NIF_ICON, NIF_TIP = 0x1, 0x2, 0x4
WS_POPUP = 0x80000000
WS_EX_LAYERED = 0x00080000
WS_EX_TOOLWINDOW = 0x00000080
WS_EX_NOACTIVATE = 0x08000000
CS_HREDRAW, CS_VREDRAW = 0x0002, 0x0001
AC_SRC_OVER, AC_SRC_ALPHA = 0x00, 0x01
ULW_ALPHA = 0x02
LWA_ALPHA = 0x02
TRANSPARENT = 1
FW_NORMAL = 400
DEFAULT_CHARSET = 1
CLEARTYPE_QUALITY = 5
SM_XVIRTUALSCREEN, SM_YVIRTUALSCREEN = 76, 77
SM_CXVIRTUALSCREEN, SM_CYVIRTUALSCREEN = 78, 79
IDI_APPLICATION, IDI_WARNING = 32512, 32515

user32 = ctypes.WinDLL('user32', use_last_error=True)
gdi32 = ctypes.WinDLL('gdi32', use_last_error=True)
shell32 = ctypes.WinDLL('shell32', use_last_error=True)
kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
LRESULT = ctypes.c_ssize_t
WNDPROC = ctypes.WINFUNCTYPE(LRESULT, wintypes.HWND, wintypes.UINT,
                             wintypes.WPARAM, wintypes.LPARAM)
HOOKPROC = ctypes.WINFUNCTYPE(LRESULT, ctypes.c_int,
                              wintypes.WPARAM, wintypes.LPARAM)


class WNDCLASSW(ctypes.Structure):
    _fields_ = [('style', wintypes.UINT), ('lpfnWndProc', WNDPROC),
                ('cbClsExtra', ctypes.c_int), ('cbWndExtra', ctypes.c_int),
                ('hInstance', wintypes.HINSTANCE), ('hIcon', wintypes.HICON),
                ('hCursor', wintypes.HCURSOR), ('hbrBackground', wintypes.HBRUSH),
                ('lpszMenuName', wintypes.LPCWSTR), ('lpszClassName', wintypes.LPCWSTR)]


class BITMAPINFOHEADER(ctypes.Structure):
    _fields_ = [('biSize', wintypes.DWORD), ('biWidth', ctypes.c_long),
                ('biHeight', ctypes.c_long), ('biPlanes', wintypes.WORD),
                ('biBitCount', wintypes.WORD), ('biCompression', wintypes.DWORD),
                ('biSizeImage', wintypes.DWORD), ('biXPelsPerMeter', ctypes.c_long),
                ('biYPelsPerMeter', ctypes.c_long), ('biClrUsed', wintypes.DWORD),
                ('biClrImportant', wintypes.DWORD)]


class BITMAPINFO(ctypes.Structure):
    _fields_ = [('bmiHeader', BITMAPINFOHEADER), ('bmiColors', wintypes.DWORD * 3)]


class BLENDFUNCTION(ctypes.Structure):
    _fields_ = [('BlendOp', ctypes.c_ubyte), ('BlendFlags', ctypes.c_ubyte),
                ('SourceConstantAlpha', ctypes.c_ubyte), ('AlphaFormat', ctypes.c_ubyte)]


class POINT(ctypes.Structure):
    _fields_ = [('x', ctypes.c_long), ('y', ctypes.c_long)]


class TRACKMOUSEEVENT(ctypes.Structure):
    _fields_ = [('cbSize', wintypes.DWORD), ('dwFlags', wintypes.DWORD),
                ('hwndTrack', wintypes.HWND), ('dwHoverTime', wintypes.DWORD)]


class MSLLHOOKSTRUCT(ctypes.Structure):
    _fields_ = [('pt', POINT), ('mouseData', wintypes.DWORD),
                ('flags', wintypes.DWORD), ('time', wintypes.DWORD),
                ('dwExtraInfo', ctypes.c_size_t)]


class SIZE(ctypes.Structure):
    _fields_ = [('cx', ctypes.c_long), ('cy', ctypes.c_long)]


class RECT(ctypes.Structure):
    _fields_ = [('left', ctypes.c_long), ('top', ctypes.c_long),
                ('right', ctypes.c_long), ('bottom', ctypes.c_long)]


class MEASUREITEMSTRUCT(ctypes.Structure):
    _fields_ = [('CtlType', wintypes.UINT), ('CtlID', wintypes.UINT),
                ('itemID', wintypes.UINT), ('itemWidth', wintypes.UINT),
                ('itemHeight', wintypes.UINT), ('itemData', ctypes.c_size_t)]


class DRAWITEMSTRUCT(ctypes.Structure):
    _fields_ = [('CtlType', wintypes.UINT), ('CtlID', wintypes.UINT),
                ('itemID', wintypes.UINT), ('itemAction', wintypes.UINT),
                ('itemState', wintypes.UINT), ('hwndItem', wintypes.HWND),
                ('hDC', wintypes.HDC), ('rcItem', RECT),
                ('itemData', ctypes.c_size_t)]


class MENUINFO(ctypes.Structure):
    _fields_ = [('cbSize', wintypes.DWORD), ('fMask', wintypes.DWORD),
                ('dwStyle', wintypes.DWORD), ('cyMax', wintypes.UINT),
                ('hbrBack', wintypes.HBRUSH), ('dwContextHelpID', wintypes.DWORD),
                ('dwMenuData', ctypes.c_size_t)]


class NOTIFYICONDATAW(ctypes.Structure):
    _fields_ = [('cbSize', wintypes.DWORD), ('hWnd', wintypes.HWND),
                ('uID', wintypes.UINT), ('uFlags', wintypes.UINT),
                ('uCallbackMessage', wintypes.UINT), ('hIcon', wintypes.HICON),
                ('szTip', wintypes.WCHAR * 128), ('dwState', wintypes.DWORD),
                ('dwStateMask', wintypes.DWORD), ('szInfo', wintypes.WCHAR * 256),
                ('uTimeout', wintypes.UINT), ('szInfoTitle', wintypes.WCHAR * 64),
                ('dwInfoFlags', wintypes.DWORD), ('guidItem', ctypes.c_byte * 16),
                ('hBalloonIcon', wintypes.HICON)]


for _fn, _arg, _ret in [
    (user32.RegisterClassW, [ctypes.POINTER(WNDCLASSW)], wintypes.ATOM),
    (user32.CreateWindowExW, [wintypes.DWORD, wintypes.LPCWSTR, wintypes.LPCWSTR,
                              wintypes.DWORD, ctypes.c_int, ctypes.c_int,
                              ctypes.c_int, ctypes.c_int, wintypes.HWND,
                              wintypes.HMENU, wintypes.HINSTANCE, wintypes.LPVOID], wintypes.HWND),
    (user32.CreatePopupMenu, [], wintypes.HMENU),
    (user32.AppendMenuW, [wintypes.HMENU, wintypes.UINT, ctypes.c_size_t, wintypes.LPCWSTR], wintypes.BOOL),
    (user32.TrackPopupMenu, [wintypes.HMENU, wintypes.UINT, ctypes.c_int, ctypes.c_int,
                             ctypes.c_int, wintypes.HWND, ctypes.c_void_p], wintypes.BOOL),
    (user32.DestroyMenu, [wintypes.HMENU], wintypes.BOOL),
    (user32.SetMenuInfo, [wintypes.HMENU, ctypes.POINTER(MENUINFO)], wintypes.BOOL),
    (user32.SetForegroundWindow, [wintypes.HWND], wintypes.BOOL),
    (user32.SetCapture, [wintypes.HWND], wintypes.HWND),
    (user32.ReleaseCapture, [], wintypes.BOOL),
    (user32.ShowWindow, [wintypes.HWND, ctypes.c_int], wintypes.BOOL),
    (user32.SetWindowsHookExW, [ctypes.c_int, HOOKPROC, wintypes.HINSTANCE,
                                wintypes.DWORD], ctypes.c_void_p),
    (user32.CallNextHookEx, [ctypes.c_void_p, ctypes.c_int,
                             wintypes.WPARAM, wintypes.LPARAM], LRESULT),
    (user32.UnhookWindowsHookEx, [ctypes.c_void_p], wintypes.BOOL),
    (user32.PeekMessageW, [ctypes.POINTER(wintypes.MSG), wintypes.HWND,
                           wintypes.UINT, wintypes.UINT, wintypes.UINT], wintypes.BOOL),
    (gdi32.CreateRoundRectRgn, [ctypes.c_int, ctypes.c_int, ctypes.c_int,
                                ctypes.c_int, ctypes.c_int, ctypes.c_int], ctypes.c_void_p),
    (user32.SetWindowRgn, [wintypes.HWND, ctypes.c_void_p, wintypes.BOOL], ctypes.c_int),
    (user32.GetCursorPos, [ctypes.POINTER(POINT)], wintypes.BOOL),
    (user32.SetCursorPos, [ctypes.c_int, ctypes.c_int], wintypes.BOOL),
    (user32.GetWindowRect, [wintypes.HWND, ctypes.POINTER(RECT)], wintypes.BOOL),
    (user32.FindWindowW, [wintypes.LPCWSTR, wintypes.LPCWSTR], wintypes.HWND),
    (user32.UpdateLayeredWindow, [wintypes.HWND, wintypes.HDC, ctypes.POINTER(POINT),
                                  ctypes.POINTER(SIZE), wintypes.HDC, ctypes.POINTER(POINT),
                                  wintypes.DWORD, ctypes.POINTER(BLENDFUNCTION), wintypes.DWORD], wintypes.BOOL),
    (user32.GetDC, [wintypes.HWND], wintypes.HDC),
    (user32.ReleaseDC, [wintypes.HWND, wintypes.HDC], ctypes.c_int),
    (user32.SetTimer, [wintypes.HWND, ctypes.c_size_t, wintypes.UINT, ctypes.c_void_p], ctypes.c_size_t),
    (user32.TrackMouseEvent, [ctypes.POINTER(TRACKMOUSEEVENT)], wintypes.BOOL),
    (user32.KillTimer, [wintypes.HWND, ctypes.c_size_t], wintypes.BOOL),
    (user32.InvalidateRect, [wintypes.HWND, ctypes.c_void_p, wintypes.BOOL], wintypes.BOOL),
    (user32.MoveWindow, [wintypes.HWND, ctypes.c_int, ctypes.c_int, ctypes.c_int,
                         ctypes.c_int, wintypes.BOOL], wintypes.BOOL),
    (user32.GetSystemMetrics, [ctypes.c_int], ctypes.c_int),
    (user32.MessageBoxW, [wintypes.HWND, wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.UINT], ctypes.c_int),
    (gdi32.CreateCompatibleDC, [wintypes.HDC], wintypes.HDC),
    (gdi32.DeleteDC, [wintypes.HDC], wintypes.BOOL),
    (gdi32.CreateDIBSection, [wintypes.HDC, ctypes.POINTER(BITMAPINFO), wintypes.UINT,
                              ctypes.POINTER(ctypes.c_void_p), wintypes.HANDLE, wintypes.DWORD], wintypes.HBITMAP),
    (gdi32.SelectObject, [wintypes.HDC, wintypes.HGDIOBJ], wintypes.HGDIOBJ),
    (gdi32.DeleteObject, [wintypes.HGDIOBJ], wintypes.BOOL),
    (gdi32.SetTextColor, [wintypes.HDC, wintypes.COLORREF], wintypes.COLORREF),
    (gdi32.SetBkMode, [wintypes.HDC, ctypes.c_int], ctypes.c_int),
    (gdi32.CreateFontW, [ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_int,
                         ctypes.c_int, wintypes.BOOL, wintypes.BOOL, wintypes.BOOL,
                         wintypes.BYTE, wintypes.BYTE, wintypes.BYTE, wintypes.BYTE,
                         wintypes.BYTE, wintypes.LPCWSTR], wintypes.HFONT),
    (gdi32.TextOutW, [wintypes.HDC, ctypes.c_int, ctypes.c_int, wintypes.LPCWSTR, ctypes.c_int], wintypes.BOOL),
    (gdi32.RoundRect, [wintypes.HDC, ctypes.c_int, ctypes.c_int, ctypes.c_int,
                       ctypes.c_int, ctypes.c_int, ctypes.c_int], wintypes.BOOL),
    (gdi32.Ellipse, [wintypes.HDC, ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_int], wintypes.BOOL),
    (gdi32.Rectangle, [wintypes.HDC, ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_int], wintypes.BOOL),
    (gdi32.MoveToEx, [wintypes.HDC, ctypes.c_int, ctypes.c_int, ctypes.c_void_p], wintypes.BOOL),
    (gdi32.LineTo, [wintypes.HDC, ctypes.c_int, ctypes.c_int], wintypes.BOOL),
    (shell32.Shell_NotifyIconW, [wintypes.DWORD, ctypes.POINTER(NOTIFYICONDATAW)], wintypes.BOOL),
    (shell32.ShellExecuteW, [wintypes.HWND, wintypes.LPCWSTR, wintypes.LPCWSTR,
                             wintypes.LPCWSTR, wintypes.LPCWSTR, ctypes.c_int], ctypes.c_void_p),
]:
    _fn.argtypes, _fn.restype = _arg, _ret

user32.GetMessageW.argtypes = [ctypes.POINTER(wintypes.MSG), wintypes.HWND,
                               wintypes.UINT, wintypes.UINT]
user32.GetMessageW.restype = LRESULT
user32.TranslateMessage.argtypes = [ctypes.POINTER(wintypes.MSG)]
user32.DispatchMessageW.argtypes = [ctypes.POINTER(wintypes.MSG)]
user32.DefWindowProcW.argtypes = [wintypes.HWND, wintypes.UINT,
                                  wintypes.WPARAM, wintypes.LPARAM]
user32.DefWindowProcW.restype = LRESULT
user32.PostQuitMessage.argtypes = [ctypes.c_int]
user32.PostMessageW.argtypes = [wintypes.HWND, wintypes.UINT,
                                wintypes.WPARAM, wintypes.LPARAM]
user32.PostMessageW.restype = wintypes.BOOL
user32.LoadIconW.argtypes = [wintypes.HINSTANCE, wintypes.LPCWSTR]
user32.LoadIconW.restype = wintypes.HICON
user32.LoadCursorW.argtypes = [wintypes.HINSTANCE, wintypes.LPCWSTR]
user32.LoadCursorW.restype = wintypes.HCURSOR
gdi32.CreateSolidBrush.argtypes = [wintypes.COLORREF]
gdi32.CreateSolidBrush.restype = wintypes.HBRUSH
user32.IsWindowVisible.argtypes = [wintypes.HWND]
user32.IsWindowVisible.restype = wintypes.BOOL
kernel32.GetModuleHandleW.argtypes = [wintypes.LPCWSTR]
kernel32.GetModuleHandleW.restype = wintypes.HINSTANCE
kernel32.GetCurrentProcessId.argtypes = []
kernel32.GetCurrentProcessId.restype = wintypes.DWORD


# ---------------------------------------------------------------- pet 設定
PET_DEFAULTS = {
    'enabled': True,
    'size': 104,               # 新造型細節較多，64→104（可在 config.json.pet.size 覆寫）
    'idle_hidden': False,
    'idle_corner': 'bottom-right',
    'sounds_enabled': True,
    'sfx_volume_note': 'winsound 無音量 API；振幅固定 0.22',
    'usage_timeout_sec': 12,
    'alert_anim_sec': 4,
    'alert_fps': 30,
    'alert_entry_edge': 'auto-nearest-tray',
    'heartbeat_sec': 60,
    'check_interval_sec': 300,
    # Phase 2（D7／D8 採計劃書建議值）：分析完自動開頁；閒置 600 s 關服務
    'auto_open_page_after_scan': True,
    'serve_idle_close_sec': 600,
    # 介面字級：1.0=標準、1.15=大（預設，左鍵面板比原版大一號）、1.3=特大
    'font_scale': 1.15,
    # 造型：'robot' 新機械人（軟體渲染）／'classic' 舊小碟（GDI）
    'art': 'robot',
    # 待機隨機眨眼（平均 10 s 一次，偶爾連眨兩下）
    'idle_blink': True,
}
FONT_SCALES = (1.0, 1.15, 1.3)
FONT_SCALE_NAMES = {1.0: '標準', 1.15: '大', 1.3: '特大'}


def load_pet_config(cfg):
    """讀可選 config.json['pet'] 並校驗；非法值拋 ValueError（F13 快速失敗）。

    刻意不改動 config.json：沒有 pet 區塊時用上述的預設值。這是為了
    「明確執行 pet 子命令＝明確選擇桌寵」；既有 watch 完全不讀 pet 區塊，
    因此回退只需把啟動命令改回 watch，不需動任何設定檔。
    """
    raw = cfg.get('pet') or {}
    if not isinstance(raw, dict):
        raise ValueError('pet section must be an object')
    out = dict(PET_DEFAULTS)
    out.update(raw)
    for k in ('size', 'usage_timeout_sec', 'alert_anim_sec', 'alert_fps',
              'heartbeat_sec', 'check_interval_sec', 'serve_idle_close_sec'):
        v = out[k]
        if not isinstance(v, (int, float)) or isinstance(v, bool) or v <= 0:
            raise ValueError('%s must be positive number' % k)
    if int(out['serve_idle_close_sec']) < 30:
        raise ValueError('serve_idle_close_sec out of range (>=30)')
    if int(out['size']) < 32 or int(out['size']) > 256:
        raise ValueError('size out of 32..256')
    if int(out['alert_fps']) > 60:
        raise ValueError('alert_fps out of 1..60')
    if out['idle_corner'] not in ('bottom-right', 'bottom-left', 'top-right', 'top-left'):
        raise ValueError('invalid idle_corner')
    if out['alert_entry_edge'] not in ('auto-nearest-tray', 'bottom', 'right', 'top', 'left'):
        raise ValueError('invalid alert_entry_edge')
    for k in ('enabled', 'idle_hidden', 'sounds_enabled',
              'auto_open_page_after_scan'):
        if not isinstance(out[k], bool):
            raise ValueError('%s must be bool' % k)
    return out


# ---------------------------------------------------------------- 事件 log
def event(cfg, name, **kw):
    d = {'ts': datetime.datetime.now().isoformat(timespec='seconds'),
         'event': name, 'state': kw.pop('state', ''),
         'request_id': kw.pop('request_id', '-'),
         'elapsed_ms': kw.pop('elapsed_ms', 0), 'ok': kw.pop('ok', True)}
    d.update(kw)  # 禁止呼叫端傳入 token / path；這裡只寫列舉值與數值
    try:
        p = os.path.join(C.out_dir(cfg), 'pet-events.jsonl')
        with open(p, 'a', encoding='utf-8') as f:
            f.write(json.dumps(d, ensure_ascii=False) + '\n')
    except Exception:
        pass
    return d


# ---------------------------------------------------------------- 繪圖工具
def _brush(hdc, color, fn):
    br = gdi32.CreateSolidBrush(color)
    try:
        old = gdi32.SelectObject(hdc, br)
        try:
            fn()
        finally:
            gdi32.SelectObject(hdc, old)
    finally:
        gdi32.DeleteObject(br)


def _fill_dib(win, x0, y0, x1, y1, color):
    """直接寫入 32bpp top-down DIB（BGRA, A=255）。

    本機 GDI CreateSolidBrush 回傳高位句柄，Rectangle 填色無效；
    自繪選單的背景／高亮改走這條確定可用的路徑。
    """
    if not getattr(win, 'bits', None) or not getattr(win, 'bits', None).value:
        return
    w, h = win.w, win.h
    x0, y0 = max(0, int(x0)), max(0, int(y0))
    x1, y1 = min(w, int(x1)), min(h, int(y1))
    if x1 <= x0 or y1 <= y0:
        return
    r, g, b = color & 0xFF, (color >> 8) & 0xFF, (color >> 16) & 0xFF
    row = bytes((b, g, r, 255)) * (x1 - x0)
    buf = (ctypes.c_ubyte * (w * h * 4)).from_address(win.bits.value)
    for y in range(y0, y1):
        off = (y * w + x0) * 4
        ctypes.memmove(ctypes.byref(buf, off), row, len(row))


def _font(hdc, size, bold=False, name='Microsoft YaHei'):
    f = gdi32.CreateFontW(size, 0, 0, 0, 700 if bold else FW_NORMAL,
                         0, 0, 0, DEFAULT_CHARSET, 0, 0,
                         CLEARTYPE_QUALITY, 0, name)
    old = gdi32.SelectObject(hdc, f)
    return f, old


def _text(hdc, x, y, s, size=14, color=0xE8EEF5, bold=False):
    f, old = _font(hdc, size, bold)
    try:
        gdi32.SetTextColor(hdc, color)          # COLORREF = 0x00BBGGRR
        gdi32.TextOutW(hdc, x, y, s, len(s))
    finally:
        gdi32.SelectObject(hdc, old)
        gdi32.DeleteObject(f)


def _text_icon(hdc, x, y, s, size, color, name='Segoe UI Symbol'):
    """用符號字型畫選單圖示；失敗時靜默略過（圖示為裝飾性）。"""
    f, old = _font(hdc, size, False, name)
    try:
        gdi32.SetTextColor(hdc, color)
        gdi32.TextOutW(hdc, x, y, s, len(s))
    finally:
        gdi32.SelectObject(hdc, old)
        gdi32.DeleteObject(f)


def BGR(r, g, b):
    """回傳 COLORREF（0x00BBGGRR）。"""
    return (b << 16) | (g << 8) | r


# ---------------------------------------------------------------- 小碟幀
def draw_pet(hdc, size, frame, tick):
    """在 32bpp DIB 上畫 64×64 小碟（BGRA 已清零 → 透明背景）。"""
    s = size
    k = s / 64.0

    def R(x0, y0, x1, y1):
        return (int(x0 * k), int(y0 * k), int(x1 * k), int(y1 * k))

    alert = frame in ('alert', 'degraded')
    shell = BGR(196, 118, 62) if alert else BGR(58, 72, 92)
    shell_edge = BGR(120, 60, 40) if alert else BGR(38, 48, 64)
    face = BGR(246, 248, 252)
    led = BGR(168, 92, 250)
    if alert:
        led = BGR(64, 64, 238)
    if frame == 'sleep':
        led = BGR(110, 120, 140)

    # 天線
    _brush(hdc, shell_edge, lambda: gdi32.Rectangle(hdc, *R(30, 3, 34, 13)))
    _brush(hdc, led, lambda: gdi32.Ellipse(hdc, *R(28, 0, 36, 8)))
    # 腳
    _brush(hdc, shell_edge, lambda: (gdi32.Rectangle(hdc, *R(16, 50, 25, 57)),
                                     gdi32.Rectangle(hdc, *R(39, 50, 48, 57))))
    # 外殼
    _brush(hdc, shell_edge, lambda: gdi32.RoundRect(hdc, *R(5, 10, 59, 53), 12, 12))
    _brush(hdc, shell, lambda: gdi32.RoundRect(hdc, *R(7, 12, 57, 51), 10, 10))
    # 面板
    _brush(hdc, face, lambda: gdi32.RoundRect(hdc, *R(11, 17, 53, 46), 8, 8))
    # 碟片（旋轉指示）
    cx, cy = 32, 31
    _brush(hdc, BGR(70, 78, 92), lambda: gdi32.Ellipse(hdc, *R(cx - 9, cy - 7, cx + 9, cy + 7)))
    _brush(hdc, BGR(150, 158, 172), lambda: gdi32.Ellipse(hdc, *R(cx - 6, cy - 5, cx + 6, cy + 5)))
    _brush(hdc, face, lambda: gdi32.Ellipse(hdc, *R(cx - 2, cy - 2, cx + 2, cy + 2)))
    if frame == 'scan':
        a = (tick % 12) * 0.52
        x2 = int(cx + 7 * __import__('math').cos(a))
        y2 = int(cy + 5 * __import__('math').sin(a))
        _brush(hdc, led, lambda: gdi32.Ellipse(hdc, *R(x2 - 2, y2 - 2, x2 + 2, y2 + 2)))
    # 眼睛
    if frame in ('blink', 'sleep'):
        _brush(hdc, led, lambda: (gdi32.Rectangle(hdc, *R(16, 25, 24, 27)),
                                  gdi32.Rectangle(hdc, *R(40, 25, 48, 27))))
    elif frame == 'degraded':
        _brush(hdc, led, lambda: (gdi32.Rectangle(hdc, *R(16, 25, 24, 26)),
                                  gdi32.Rectangle(hdc, *R(40, 25, 48, 26))))
    else:
        _brush(hdc, led, lambda: (gdi32.Ellipse(hdc, *R(16, 23, 24, 31)),
                                  gdi32.Ellipse(hdc, *R(40, 23, 48, 31))))
        _brush(hdc, face, lambda: (gdi32.Ellipse(hdc, *R(18, 24, 20, 26)),
                                   gdi32.Ellipse(hdc, *R(42, 24, 44, 26))))
    # 腮紅
    _brush(hdc, BGR(160, 170, 248), lambda: (gdi32.Ellipse(hdc, *R(11, 33, 17, 38)),
                                             gdi32.Ellipse(hdc, *R(47, 33, 53, 38))))
    # 嘴
    _brush(hdc, shell_edge, lambda: gdi32.Rectangle(hdc, *R(29, 39, 35, 41)))
    if frame == 'happy':
        _brush(hdc, shell_edge, lambda: gdi32.Rectangle(hdc, *R(27, 37, 37, 39)))
    if frame == 'paused':
        gdi32.SetTextColor(hdc, BGR(90, 90, 100))
        _text(hdc, 22, 40, 'II', 12, BGR(90, 90, 100), True)


class Layered:
    """一個 32bpp 分層視窗（UpdateLayeredWindow），供桌寵與用量面板共用。

    opaque=True 時關掉 AC_SRC_ALPHA：GDI 畫進 DIB 的 alpha 通常是 0，
    若照樣用 source-alpha 混合，整塊面板會被透掉、與桌面文字重疊。
    用量面板改用「全域不透明度 255」，Pet 本體則維持 source-alpha 以保留透明輪廓。
    """

    def __init__(self, w, h, point=(0, 0), topmost=False, opaque=False):
        self.w, self.h = w, h
        ex = WS_EX_LAYERED | WS_EX_TOOLWINDOW | WS_EX_NOACTIVATE
        if topmost:
            ex |= 0x8  # WS_EX_TOPMOST
        self.hwnd = user32.CreateWindowExW(
            ex, 'DiskGuardPetClass', '', WS_POPUP,
            int(point[0]), int(point[1]), w, h, 0, 0,
            kernel32.GetModuleHandleW(None), None)
        if not self.hwnd:
            raise ctypes.WinError(ctypes.get_last_error())
        self.hdc_screen = user32.GetDC(0)
        self.hdc_mem = gdi32.CreateCompatibleDC(self.hdc_screen)
        bi = BITMAPINFO()
        bi.bmiHeader.biSize = ctypes.sizeof(BITMAPINFOHEADER)
        bi.bmiHeader.biWidth = w
        bi.bmiHeader.biHeight = -h          # top-down
        bi.bmiHeader.biPlanes = 1
        bi.bmiHeader.biBitCount = 32
        bi.bmiHeader.biCompression = 0      # BI_RGB
        bits = ctypes.c_void_p()
        self.bmp = gdi32.CreateDIBSection(self.hdc_screen, ctypes.byref(bi), 0,
                                          ctypes.byref(bits), None, 0)
        if not self.bmp:
            raise ctypes.WinError(ctypes.get_last_error())
        self.old = gdi32.SelectObject(self.hdc_mem, self.bmp)
        self.bits = bits
        self.opaque = bool(opaque)
        # opaque=True：忽略 DIB 的 alpha 通道，整塊以 SourceConstantAlpha=255 輸出
        self._blend = BLENDFUNCTION(AC_SRC_OVER, 0, 255,
                                    0 if self.opaque else AC_SRC_ALPHA)

    def paint(self, draw_fn):
        ctypes.memset(self.bits, 0, self.w * self.h * 4)
        gdi32.SetBkMode(self.hdc_mem, TRANSPARENT)
        draw_fn(self.hdc_mem)
        pt = POINT(0, 0)
        sz = SIZE(self.w, self.h)
        src = POINT(0, 0)
        user32.UpdateLayeredWindow(self.hwnd, self.hdc_screen, None, ctypes.byref(sz),
                                   self.hdc_mem, ctypes.byref(src), 0,
                                   ctypes.byref(self._blend), ULW_ALPHA)

    def paint_buffer(self, data):
        """直接把整塊 BGRA bytes 貼上（軟體渲染用，免 GDI 繪製）。"""
        need = self.w * self.h * 4
        if len(data) != need:
            raise ValueError('buffer size mismatch: %d != %d' % (len(data), need))
        ctypes.memmove(self.bits, data, need)
        sz = SIZE(self.w, self.h)
        src = POINT(0, 0)
        user32.UpdateLayeredWindow(self.hwnd, self.hdc_screen, None, ctypes.byref(sz),
                                   self.hdc_mem, ctypes.byref(src), 0,
                                   ctypes.byref(self._blend), ULW_ALPHA)

    def move(self, x, y):
        user32.MoveWindow(self.hwnd, int(x), int(y), self.w, self.h, True)

    def show(self, yes=True):
        # UpdateLayeredWindow 會一並設定可見性；這裡用 SW_SHOW/SW_HIDE
        user32.ShowWindow(self.hwnd, 5 if yes else 0)

    def close(self):
        try:
            gdi32.SelectObject(self.hdc_mem, self.old)
            gdi32.DeleteObject(self.bmp)
            gdi32.DeleteDC(self.hdc_mem)
            user32.ReleaseDC(0, self.hdc_screen)
            user32.DestroyWindow(self.hwnd)
        except Exception:
            pass

    def rect(self):
        r = RECT()
        user32.GetWindowRect(self.hwnd, ctypes.byref(r))
        return r.left, r.top, r.right, r.bottom


user32.ShowWindow.argtypes = [wintypes.HWND, ctypes.c_int]
user32.ShowWindow.restype = wintypes.BOOL
user32.DestroyWindow.argtypes = [wintypes.HWND]
user32.DestroyWindow.restype = wintypes.BOOL


# ---------------------------------------------------------------- 主程式
class PetApp:
    def __init__(self, cfg, pcfg, config_path=None):
        self.cfg, self.p = cfg, pcfg
        self.config_path = config_path
        self.state = C.read_state(cfg) or {}
        self.pet_state = self.state.setdefault('pet', {})
        # 字級：狀態檔優先（可在右鍵選單即時調整並記住），其次 config.json.pet
        try:
            fs = float(self.pet_state.get('font_scale') or
                       pcfg.get('font_scale') or 1.15)
        except (TypeError, ValueError):
            fs = 1.15
        self.font_scale = min(1.3, max(1.0, fs))
        # 造型：pet.art = 'robot'（新機械人）／'classic'（舊小碟）；無 pet_art 模組則強制回退
        art = str((pcfg or {}).get('art', 'robot') or 'robot').lower()
        self.use_new_art = bool(pet_art) and art != 'classic'
        self._sprite_cache = {}
        self.sound = bool(pcfg['sounds_enabled'])
        self.frame = 'idle'
        self.tick = 0
        # 滑鼠懸停表情：靜止 0.95 → 移入放大到 1.04，並換笑眼／說話嘴／眨眼
        self.hover = False
        self.hover_t0 = 0.0
        self.hover_scale = BASE_SCALE
        self.hover_eye = None
        self.hover_mouth = None
        self.blink_next = 0.0
        self.blink_until = 0.0
        # 待機眨眼（與懸停表情分開）：idle_eye='blink' 期間眼睛閉上
        self.idle_eye = None
        self.blink_repeat = 0
        self.idle_blink = bool(pcfg.get('idle_blink', True))
        self.paused_until = 0.0
        self.last_alert = float(self.pet_state.get('last_alert', 0) or 0)
        self.stop_evt = threading.Event()
        self.drag = None
        self.alive = False
        self.hwnd = None
        self.nid = None
        self.pet_win = None
        self.usage_win = None
        self.usage_until = 0.0
        # 自繪右鍵選單（本機 WM_MEASUREITEM／WM_DRAWITEM 未送達，不能用系統 owner-draw）
        self.menu_win = None
        self.menu_rows = []
        self.menu_hover = -1
        self.menu_press = -1          # 左鍵按下落在哪一列（按放同一列才執行）
        self.menu_open_ts = 0.0       # 開啟時刻：擋掉開選單那一次右鍵的餘波
        self.menu_result = None
        self.menu_done = False
        self.menu_x = self.menu_y = 0
        self.anim = None
        # Phase 2：所有耗時／會開埠的動作都在工作者執行緒，UI 只設旗標
        self.state_lock = threading.RLock()
        self.scan_busy = threading.Lock()
        self.serve_busy = threading.Lock()
        self.scan_req = threading.Event()
        self.page_req = threading.Event()
        self.scan_reason = 'manual'
        self.page_reason = 'manual'
        self.server = None
        self.server_last_active = 0.0
        self.auto_open = bool(pcfg.get('auto_open_page_after_scan', True))
        self.idle_close = int(pcfg.get('serve_idle_close_sec', 600))
        self.last_scan_ts = 0.0

    # ---------- 狀態 ----------
    def save_state(self):
        with self.state_lock:
            self.pet_state.update({
                'last_heartbeat': datetime.datetime.now().isoformat(timespec='seconds'),
                'ui_state': self.frame, 'sounds_enabled': self.sound,
                'position': list(self.pet_state.get('position') or [self._idle_pos()]),
                'last_alert': self.last_alert,
                'pid': os.getpid(),
                'last_scan_ts': self.last_scan_ts,
                'auto_open_page_after_scan': self.auto_open,
                'serve_idle_close_sec': self.idle_close,
            })
            st = C.read_state(self.cfg) or {}   # 合併背景掃描寫入的欄位，避免互相覆蓋
            st['pet'] = self.pet_state
            C.write_state(self.cfg, st)
            self.state = st

    def _idle_pos(self):
        sw = user32.GetSystemMetrics(SM_XVIRTUALSCREEN)
        sh = user32.GetSystemMetrics(SM_YVIRTUALSCREEN)
        cw = user32.GetSystemMetrics(SM_CXVIRTUALSCREEN)
        ch = user32.GetSystemMetrics(SM_CYVIRTUALSCREEN)
        n = int(self.p['size'])
        p = self.p['idle_corner']
        x = sw + (cw - n - 24 if 'right' in p else 24)
        y = sh + (ch - n - 48 if 'bottom' in p else 24)
        return x, y

    def clamp_pos(self, x, y):
        sw = user32.GetSystemMetrics(SM_XVIRTUALSCREEN)
        sh = user32.GetSystemMetrics(SM_YVIRTUALSCREEN)
        cw = user32.GetSystemMetrics(SM_CXVIRTUALSCREEN)
        ch = user32.GetSystemMetrics(SM_CYVIRTUALSCREEN)
        n = int(self.p['size'])
        x = max(sw, min(int(x), sw + cw - n))
        y = max(sh, min(int(y), sh + ch - n))
        return x, y

    # ---------- 音效 ----------
    def sfx(self, name):
        pet_sfx.play(name, self.sound)

    # ---------- 托盤 ----------
    def tray(self, action=None, tip=None, icon=None):
        """action=None → NIM_MODIFY；首次用 action=NIM_ADD，結束 NIM_DELETE。"""
        if self.nid is None:
            n = NOTIFYICONDATAW()
            n.cbSize = ctypes.sizeof(NOTIFYICONDATAW)
            n.hWnd = self.hwnd
            n.uID = 1
            n.uFlags = NIF_MESSAGE | NIF_ICON | NIF_TIP
            n.uCallbackMessage = WM_TRAY
            self.nid = n
        n = self.nid
        if icon is not None:
            n.hIcon = icon
        if tip is not None:
            n.szTip = tip
        return shell32.Shell_NotifyIconW(
            NIM_MODIFY if action is None else action, ctypes.byref(n))

    def tip_text(self):
        d = C.disk_info(self.cfg['drive'])
        return ('DiskGuard · C: %.2f%% 可用 · 桌寵%s' %
                (d['free_pct'], '暫停' if time.time() < self.paused_until else '守護中'))

    def tray_icon(self, alert=False):
        # 與桌寵主角「小碟」同造型的專屬 ICO；缺失時才降級回系統圖示
        h = pet_icon.load_handle(alert)
        if h:
            return h
        return user32.LoadIconW(0, ctypes.cast(
            IDI_WARNING if alert else IDI_APPLICATION, wintypes.LPCWSTR))

    # ---------- 視窗程序 ----------
    def wndproc(self, hwnd, msg, wparam, lparam):
        try:
            if self.menu_win and hwnd == self.menu_win.hwnd:
                self._menu_wndproc(msg, wparam)
                return 0
            if msg == WM_TRAY:
                ev = lparam & 0xFFFF
                if ev == 0x0201:      # WM_LBUTTONUP
                    self.toggle_usage(self._tray_left_anchor())
                elif ev == 0x0204:    # WM_RBUTTONUP
                    pt = POINT()
                    user32.GetCursorPos(ctypes.byref(pt))
                    self.open_menu(pt.x, pt.y)
                return 0
            if msg == WM_ALERT:
                self.on_alert()
                return 0
            if msg == WM_MEASUREITEM:
                mi = ctypes.cast(lparam, ctypes.POINTER(MEASUREITEMSTRUCT)).contents
                if mi.CtlType == ODT_MENU:
                    mi.itemWidth = 260
                    mi.itemHeight = 30
                return 0
            if msg == WM_DRAWITEM:
                dis = ctypes.cast(lparam, ctypes.POINTER(DRAWITEMSTRUCT)).contents
                if dis.CtlType == ODT_MENU:
                    self.draw_menu_item(dis)
                return 0
            if msg == WM_EXIT:
                user32.PostQuitMessage(0)
                return 0
            if msg == WM_TIMER:
                if wparam == WM_TIMER_USAGE:
                    if time.time() >= self.usage_until:
                        self.hide_usage()
                        user32.KillTimer(hwnd, WM_TIMER_USAGE)
                elif wparam == WM_TIMER_ANIM:
                    self.anim_tick()
                elif wparam == WM_TIMER_BEAT:
                    self.save_state()
                elif wparam == WM_TIMER_HOVER:
                    self.hover_tick()
                elif wparam == WM_TIMER_BLINK:
                    self.blink_tick()
                return 0
            if msg == 0x0100:         # WM_KEYDOWN -- 不處理，避免干擾
                return 0
            if msg == 0x0201:         # WM_LBUTTONDOWN（桌寵）
                if self.pet_win:
                    self.hover_reset()            # 開始拖曳／點擊前先收掉懸停表情
                    r = self.pet_win.rect()
                    pt = POINT()
                    user32.GetCursorPos(ctypes.byref(pt))
                    # [抓取偏移x, y, 是否已拖動, 按下點x, 按下點y]
                    self.drag = [pt.x - r[0], pt.y - r[1], False, pt.x, pt.y]
                    user32.SetCapture(hwnd)   # 關鍵：沒有 capture，滑出視窗就收不到 MOUSEMOVE
                    self.sfx('menu_hit')
                return 0
            if msg == 0x0202:         # WM_LBUTTONUP
                moving = bool(self.drag and self.drag[2])
                user32.ReleaseCapture()
                if self.anim and self.stop_anim():
                    self.drag = None
                    return 0          # 點氣泡只停動畫；背景分析不受影響
                if moving:
                    self.save_state()
                    self.sfx('drag')
                    self.drag = None
                    self.frame = 'idle'      # 放手後恢復待機表情（否則會停在 wide 眼）
                    self.repaint_pet()
                    return 0
                self.drag = None
                self.toggle_usage(None)
                return 0
            if msg == 0x0200:         # WM_MOUSEMOVE
                if self.drag and self.pet_win:
                    pt = POINT()
                    user32.GetCursorPos(ctypes.byref(pt))
                    if not self.drag[2]:
                        if (abs(pt.x - self.drag[3]) < 3 and
                                abs(pt.y - self.drag[4]) < 3):
                            return 0      # 未超過 3 px 門檻 → 仍當作點擊，不誤拖
                    self.drag[2] = True
                    x, y = self.clamp_pos(pt.x - self.drag[0], pt.y - self.drag[1])
                    self.pet_win.move(x, y)
                    self.pet_state['position'] = [x, y]
                    self.frame = 'drag'
                    self.repaint_pet()
                else:
                    # 滑鼠移到機械人身上：表情互動（放大＋笑眼＋說話＋眨眼）
                    if not self.hover:
                        self.hover_enter()
                    self._track_leave()
                return 0
            if msg == WM_MOUSELEAVE:
                self.hover_leave()
                return 0
            if msg == 0x0215:         # WM_CAPTURECHANGED
                if self.drag and not self.drag[2]:
                    self.drag = None
                return 0
            if msg == 0x0204:         # WM_RBUTTONDOWN（桌寵，按下即開選單）
                self.hover_reset()            # 選單期間不要有懸停表情
                pt = POINT()
                user32.GetCursorPos(ctypes.byref(pt))
                self.open_menu(pt.x, pt.y)
                return 0
            if msg in (0x0010, 0x0002):  # WM_CLOSE / WM_DESTROY
                user32.PostQuitMessage(0)
                return 0
            if msg == 0x0111:         # WM_COMMAND（選單）
                self.on_command(wparam & 0xFFFF)
                return 0
        except Exception as ex:
            C.log(self.cfg, 'pet wndproc error: %s' % ex)
            event(self.cfg, 'wndproc_error', ok=False)
        return user32.DefWindowProcW(hwnd, msg, wparam, lparam)

    # ---------- 面板 ----------
    def _panel_size(self):
        return self._fs(340), self._fs(264)

    def _tray_left_anchor(self):
        r = RECT()
        if user32.GetWindowRect(user32.FindWindowW('Shell_TrayWnd', None), ctypes.byref(r)):
            h = self._panel_size()[1]
            return (r.left, r.top - h - 8 if r.top > 290 else r.bottom)
        return self._idle_pos()

    def toggle_usage(self, anchor):
        if self.usage_win and user32.IsWindowVisible(self.usage_win.hwnd):
            self.hide_usage()
            return
        self.show_usage(anchor)

    def show_usage(self, anchor):
        self.sfx('panel_open')
        W, H = self._panel_size()
        if self.usage_win and (self.usage_win.w != W or self.usage_win.h != H):
            self.usage_win.close()          # 字級變更 → 重建為新尺寸
            self.usage_win = None
        if not self.usage_win:
            self.usage_win = Layered(W, H, anchor or self._idle_pos(),
                                     topmost=True, opaque=True)
        sx = user32.GetSystemMetrics(SM_XVIRTUALSCREEN)
        sy = user32.GetSystemMetrics(SM_YVIRTUALSCREEN)
        sw = user32.GetSystemMetrics(SM_CXVIRTUALSCREEN)
        sh = user32.GetSystemMetrics(SM_CYVIRTUALSCREEN)
        ax, ay = anchor or self._idle_pos()
        x = max(sx, min(int(ax), sx + sw - W))
        y = max(sy, min(int(ay), sy + sh - H))
        self.usage_win.move(x, y)
        d = C.disk_info(self.cfg['drive'])
        scanp = os.path.join(C.out_dir(self.cfg), 'scan.json')
        try:
            scan_t = datetime.datetime.fromtimestamp(
                os.path.getmtime(scanp)).strftime('%Y-%m-%d %H:%M')
        except Exception:
            scan_t = '無'
        threshold = float(self.cfg['alert']['threshold_pct'])
        limit_gb = d['total_gb'] * threshold / 100.0
        nxt = (datetime.datetime.now() +
               datetime.timedelta(seconds=int(self.p['check_interval_sec']))
               ).strftime('%H:%M:%S')
        st = ('暫停守護' if time.time() < self.paused_until else
              '分析中' if self.frame == 'scan' else '監測中')
        low = d['free_pct'] < threshold

        S = self._fs

        def draw(hdc):
            # 整塊先填滿：opaque 模式下未被填到的像素會變成黑塊
            _brush(hdc, BGR(16, 22, 32), lambda: gdi32.Rectangle(hdc, 0, 0, W, H))
            _brush(hdc, BGR(120, 92, 240), lambda: gdi32.Rectangle(hdc, 0, 0, W, S(3)))
            _brush(hdc, BGR(28, 37, 52), lambda: gdi32.Rectangle(hdc, 0, S(3), W, S(48)))
            _brush(hdc, BGR(58, 72, 94), lambda: gdi32.Rectangle(hdc, 0, S(48), W, S(49)))
            _text(hdc, S(18), S(15), 'DiskGuard · 磁碟用量', S(18), BGR(240, 245, 252), True)
            _text(hdc, S(292), S(18), 'C:', S(14), BGR(160, 176, 198), True)
            rows = [
                ('總容量', '%.2f GB' % d['total_gb'], BGR(232, 238, 246)),
                ('已用', '%.2f GB' % d['used_gb'], BGR(232, 238, 246)),
                ('剩餘', '%.2f GB' % d['free_gb'],
                 BGR(255, 128, 128) if low else BGR(126, 224, 168)),
                ('可用比例', '%.2f%%' % d['free_pct'],
                 BGR(255, 128, 128) if low else BGR(126, 224, 168)),
                ('門檻線', '%.2f%%（約 %.2f GB）' % (threshold, limit_gb),
                 BGR(200, 186, 255)),
                ('上次分析', scan_t, BGR(232, 238, 246)),
                ('下次檢查', nxt, BGR(232, 238, 246)),
                ('狀態', st, BGR(200, 214, 232)),
            ]
            y = S(62)
            for k, v, color in rows:
                _text(hdc, S(18), y, k, S(14), BGR(152, 168, 190))
                _text(hdc, S(132), y, v, S(14), color)
                y += S(22)
            _text(hdc, S(18), S(246), '左鍵關閉 · 唯讀面板', S(11), BGR(120, 138, 160))
            _brush(hdc, BGR(48, 58, 74),
                   lambda: gdi32.Rectangle(hdc, S(18), S(236), S(322), S(242)))
            used = max(0.0, min(1.0, 1.0 - d['free_pct'] / 100.0))
            _brush(hdc, BGR(255, 128, 128) if low else BGR(126, 142, 246),
                   lambda: gdi32.Rectangle(hdc, S(18), S(236),
                                           S(18) + int(S(304) * used), S(242)))

        self.usage_win.paint(draw)
        self.usage_win.show(True)
        self.usage_until = time.time() + int(self.p['usage_timeout_sec'])
        user32.SetTimer(self.hwnd, WM_TIMER_USAGE,
                        int(self.p['usage_timeout_sec'] * 1000), None)
        event(self.cfg, 'panel_open', disk_pct=d['free_pct'])

    def hide_usage(self):
        if self.usage_win:
            self.usage_win.show(False)
        self.sfx('panel_close')
        event(self.cfg, 'panel_close')

    # ---------- 右鍵選單（F11：三類危險動作不存在） ----------
    MENU = [
        (1001, '開啟分析網頁（本機服務）'),
        (1002, '立即背景分析一次'),
        (1009, '分析後自動開頁 開／關'),
        (1010, '離線唯讀報告（API=false）'),
        (0, None),
        (1003, '查看日誌'),
        (1004, '查看通知'),
        (0, None),
        (1005, '暫停守護 1 小時'),
        (1006, '隱藏／顯示桌寵'),
        (1007, '音效 開／關'),
        (1011, '字體大小：大'),
        (0, None),
        (1008, '結束程式'),
    ]
    # 圖示字形（Segoe UI Symbol，與參考範例的「圖示＋文字」排列一致）
    MENU_ICON = {
        1001: '◉', 1002: '⟳', 1009: '◐', 1010: '▤',
        1003: '☰', 1004: '♧', 1005: '⏸', 1006: '◉',
        1007: '♪', 1011: 'A', 1008: '⏻',
    }
    MENU_RADIUS = 10
    MENU_ICON_FONT = 'Segoe UI Symbol'

    def _fs(self, n):
        """依目前字級比例換算像素（座標與字級共用，確保版面等比）。"""
        return max(9, int(round(n * self.font_scale)))

    def menu_items(self):
        """選單項目（字體大小一項顯示目前級別）。"""
        name = FONT_SCALE_NAMES.get(round(self.font_scale, 2), '大')
        out = []
        for cid, label in self.MENU:
            if cid == 1011:
                label = '字體大小：%s' % name
            out.append((cid, label))
        return out

    def _menu_layout(self):
        """回傳 (rows, height)；row=(cid, label, checked, grayed, y0, y1)。"""
        rows, y = [], self._fs(8)
        row_h, sep_h = self._fs(40), self._fs(12)
        for cid, label in self.menu_items():
            if cid == 0:
                rows.append((0, None, False, False, y, y + sep_h))
                y += sep_h
                continue
            checked = ((cid == 1007 and not self.sound) or
                       (cid == 1006 and bool(self.p['idle_hidden'])) or
                       (cid == 1005 and time.time() < self.paused_until) or
                       (cid == 1009 and self.auto_open))
            grayed = (cid == 1002 and self.scan_busy.locked())
            rows.append((cid, label, checked, grayed, y, y + row_h))
            y += row_h
        return rows, y + self._fs(8)

    def _menu_paint(self):
        win = self.menu_win
        if not win:
            return

        def draw(hdc):
            W, H = win.w, win.h
            # 深灰扁平背景（貼近參考範例）；圓角由 SetWindowRgn 裁切
            for yy in range(H):
                t = yy / float(max(1, H - 1))
                _fill_dib(win, 0, yy, W, yy + 1,
                          BGR(int(48 - 8 * t), int(50 - 8 * t), int(54 - 9 * t)))
            # 細灰邊框（圓角處被 region 裁掉）
            _fill_dib(win, 0, 0, W, 1, BGR(84, 88, 94))
            _fill_dib(win, 0, 0, 1, H, BGR(84, 88, 94))
            _fill_dib(win, 0, H - 1, W, H, BGR(30, 32, 36))
            _fill_dib(win, W - 1, 0, W, H, BGR(30, 32, 36))
            for i, (cid, label, checked, grayed, y0, y1) in enumerate(self.menu_rows):
                if cid == 0:
                    mid = y0 + (y1 - y0) // 2
                    _fill_dib(win, self._fs(18), mid, W - self._fs(18), mid + 1,
                              BGR(74, 77, 82))
                    continue
                sel = (i == self.menu_hover and not grayed)
                if sel:
                    _fill_dib(win, 2, y0, W - 2, y1, BGR(66, 70, 78))
                if cid == 1008:                       # 結束程式：紅色（與參考一致）
                    color = BGR(255, 120, 120) if sel else BGR(236, 96, 96)
                else:
                    color = (BGR(150, 154, 162) if grayed else
                             BGR(255, 255, 255) if sel else BGR(226, 229, 234))
                icon = self.MENU_ICON.get(cid, '')
                if checked:
                    icon = '✓'
                if icon:
                    _text_icon(hdc, self._fs(20), y0 + self._fs(7), icon, self._fs(19),
                               BGR(126, 224, 168) if checked else color)
                _text(hdc, self._fs(54), y0 + self._fs(7), label or '', self._fs(20),
                      color, sel)
        win.paint(draw)

    def _menu_hit(self, mx, my):
        if not self.menu_win or not (0 <= mx < self.menu_win.w):
            return -1
        for i, (cid, label, checked, grayed, y0, y1) in enumerate(self.menu_rows):
            if y0 <= my < y1:
                return i if (cid and not grayed) else -1
        return -1

    def _menu_cursor_row(self):
        pt = POINT()
        user32.GetCursorPos(ctypes.byref(pt))
        return self._menu_hit(pt.x - self.menu_x, pt.y - self.menu_y)

    def _menu_mouse_hook(self, ncode, wparam, lparam, state):
        """低階滑鼠鉤子：點在選單矩形外就 PostMessage 關閉訊息。"""
        try:
            if ncode >= HC_ACTION and wparam in (WM_LBUTTONDOWN, WM_RBUTTONDOWN):
                ms = ctypes.cast(lparam, ctypes.POINTER(MSLLHOOKSTRUCT)).contents
                px, py = ms.pt.x, ms.pt.y
                inside = (state['x'] <= px <= state['x'] + state['w'] and
                          state['y'] <= py <= state['y'] + state['h'])
                if not inside:
                    user32.PostMessageW(state['hwnd'], WM_MENU_DISMISS, 0, 0)
        except Exception:
            pass
        return user32.CallNextHookEx(None, ncode, wparam, lparam)

    def _menu_wndproc(self, msg, wparam):
        """自繪選單視窗的滑鼠／鍵盤訊息；本機系統 owner-draw 訊息未送達。

        選取規則（Boss 2026-11-25 要求）：**只有左鍵按下＋在同一列放開才算選取**。
        右鍵完全不會執行任何功能——0x0204 是右鍵「按下」，選單正是在那時打開的，
        隨後的 0x0205 放手若被當成選取，就會「一放手就執行游標那一列」。
        """
        if msg == WM_MENU_DISMISS:              # 全域鉤子：點選單外
            self.menu_done = True
            return
        if msg not in (0x0200, 0x0201, 0x0202, 0x0204, 0x0205, 0x0100):
            return
        # 剛開啟的 150 ms 內不吃按鍵：開選單那一次右鍵的餘波一律無效
        if msg != 0x0200 and self._now() - self.menu_open_ts < 0.15:
            return
        if msg == 0x0200:                       # WM_MOUSEMOVE
            idx = self._menu_cursor_row()
            if idx != self.menu_hover:
                self.menu_hover = idx
                self._menu_paint()
        elif msg == 0x0201:                     # 左鍵按下：只記錄落點，不執行
            self.menu_press = self._menu_cursor_row()
            if self.menu_press != self.menu_hover:
                self.menu_hover = self.menu_press
                self._menu_paint()
        elif msg == 0x0202:                     # 左鍵放開：按、放同一列才執行
            idx = self._menu_cursor_row()
            if idx >= 0 and idx == self.menu_press:
                row = self.menu_rows[idx]
                if row[0] and not row[3]:
                    self.menu_result = row[0]
            self.menu_done = True
        elif msg == 0x0204:                     # 右鍵再按一下：收起選單（不執行）
            self.menu_done = True
        elif msg == 0x0205:                     # 右鍵放開：完全忽略
            pass
        elif msg == 0x0100:                     # WM_KEYDOWN
            key = wparam & 0xFFFF
            if key == VK_ESCAPE:
                self.menu_done = True
            elif key in (VK_UP, VK_DOWN) and self.menu_rows:
                idx = self.menu_hover
                step = 1 if key == VK_DOWN else -1
                for _ in range(len(self.menu_rows)):
                    idx = (idx + step) % len(self.menu_rows)
                    if self.menu_rows[idx][0] and not self.menu_rows[idx][3]:
                        break
                self.menu_hover = idx
                self._menu_paint()
            elif key == VK_RETURN and 0 <= self.menu_hover < len(self.menu_rows):
                row = self.menu_rows[self.menu_hover]
                if row[0] and not row[3]:
                    self.menu_result = row[0]
                    self.menu_done = True

    def open_menu(self, x, y):
        """自繪分層選單：完全不依賴 TrackPopupMenu 的 owner-draw 回呼。"""
        self.sfx('menu_open')
        C.log(self.cfg, 'pet menu open at (%d,%d)' % (x, y))
        event(self.cfg, 'menu_open')
        rows, height = self._menu_layout()
        width = self._fs(340)
        sw = user32.GetSystemMetrics(0)
        sh = user32.GetSystemMetrics(1)
        x = max(0, min(int(x), sw - width - 4))
        y = max(0, min(int(y), sh - height - 4))
        win = Layered(width, height, (x, y), topmost=True, opaque=True)
        # 圓角裁切：讓分層視窗四角透明，避開「與其他程式一樣方」的邊框
        rgn = gdi32.CreateRoundRectRgn(0, 0, width + 1, height + 1,
                                       self.MENU_RADIUS, self.MENU_RADIUS)
        if rgn:
            user32.SetWindowRgn(win.hwnd, rgn, True)   # 所有權移交給視窗，不 DeleteObject
        self.menu_win = win
        self.menu_rows = rows
        self.menu_hover = -1
        self.menu_press = -1
        self.menu_open_ts = self._now()
        self.menu_result = None
        self.menu_done = False
        self.menu_x, self.menu_y = x, y
        self._menu_paint()
        win.show(True)
        user32.SetCapture(win.hwnd)   # 確保選單內點擊送到本視窗

        # 全域低階滑鼠鉤子：點選單外立即關閉（SetCapture 只在同一執行緒有效）
        self.menu_hook_state = {'hwnd': win.hwnd, 'x': x, 'y': y, 'w': width, 'h': height}

        @HOOKPROC
        def _mouse_hook(ncode, wparam, lparam):
            return self._menu_mouse_hook(ncode, wparam, lparam, self.menu_hook_state)

        hook = user32.SetWindowsHookExW(WH_MOUSE_LL, _mouse_hook,
                                        kernel32.GetModuleHandleW(None), 0)
        msg = wintypes.MSG()
        try:
            while self.menu_win and not self.menu_done:
                if user32.GetMessageW(ctypes.byref(msg), 0, 0, 0) <= 0:
                    break
                if msg.message == WM_QUIT:
                    user32.PostQuitMessage(msg.wParam)
                    break
                user32.TranslateMessage(ctypes.byref(msg))
                user32.DispatchMessageW(ctypes.byref(msg))
        finally:
            if hook:
                user32.UnhookWindowsHookEx(hook)
            try:
                user32.ReleaseCapture()
            except Exception:
                pass
            if self.menu_win:
                self.menu_win.close()
            cmd = self.menu_result
            self.menu_win = None
            self.menu_rows = []
            self.menu_hover = -1
        if cmd:
            self.sfx('menu_hit')
            self.on_command(cmd)

    def on_command(self, cid):
        self.sfx('menu_hit')
        if cid == 1001:
            self.sfx('page_open')
            self.request_page('manual')
            C.log(self.cfg, 'pet menu: request on-demand local page')
            event(self.cfg, 'menu_open_page')
        elif cid == 1002:
            self.sfx('scan')
            self.request_scan('manual')
            C.log(self.cfg, 'pet menu: request background scan')
            event(self.cfg, 'menu_scan')
        elif cid == 1009:
            self.auto_open = not self.auto_open
            self.p['auto_open_page_after_scan'] = self.auto_open
            if self.auto_open:
                self.sfx('happy')
            C.log(self.cfg, 'pet menu: auto_open_page_after_scan=%s' % self.auto_open)
            event(self.cfg, 'menu_auto_open', enabled=self.auto_open)
        elif cid == 1010:
            p = os.path.join(C.out_dir(self.cfg), 'C盘清理清单.html')
            if os.path.exists(p):
                shell32.ShellExecuteW(0, None, p, None, None, 1)
                self.sfx('page_open')
                C.log(self.cfg, 'pet menu: open offline report page (API=false)')
            else:
                C.log(self.cfg, 'pet menu: report page missing')
            event(self.cfg, 'menu_open_offline_page')
        elif cid == 1003:
            p = os.path.join(C.out_dir(self.cfg), self.cfg['paths']['log_filename'])
            if os.path.exists(p):
                shell32.ShellExecuteW(0, 'open', 'notepad.exe', p, None, 1)
            event(self.cfg, 'menu_view_log')
        elif cid == 1004:
            p = os.path.join(C.out_dir(self.cfg), 'notice.md')
            if os.path.exists(p):
                shell32.ShellExecuteW(0, 'open', 'notepad.exe', p, None, 1)
            else:
                user32.MessageBoxW(self.hwnd, '尚無通知（空間高於門檻）。', 'DiskGuard', 0x40)
            event(self.cfg, 'menu_view_notice')
        elif cid == 1005:
            if time.time() < self.paused_until:
                self.paused_until = 0
                self.tray_icon(False)
                C.log(self.cfg, 'pet menu: resume')
            else:
                self.paused_until = time.time() + 3600
                self.tray_icon(False)
                C.log(self.cfg, 'pet menu: pause 1h')
            self.sfx('paused')
            self.tray(tip=self.tip_text())
            event(self.cfg, 'menu_pause', until=int(self.paused_until))
        elif cid == 1006:
            self.p['idle_hidden'] = not self.p['idle_hidden']
            if self.pet_win:
                self.pet_win.show(not self.p['idle_hidden'])
            C.log(self.cfg, 'pet menu: idle_hidden=%s' % self.p['idle_hidden'])
            event(self.cfg, 'menu_hide', hidden=self.p['idle_hidden'])
        elif cid == 1007:
            self.sound = not self.sound
            self.pet_state['sounds_enabled'] = self.sound
            if self.sound:
                self.sfx('serve')
            else:
                pet_sfx.stop()
            C.log(self.cfg, 'pet menu: sounds_enabled=%s' % self.sound)
            event(self.cfg, 'menu_sound', enabled=self.sound)
        elif cid == 1011:
            cur = min(range(len(FONT_SCALES)),
                      key=lambda i: abs(FONT_SCALES[i] - self.font_scale))
            self.font_scale = FONT_SCALES[(cur + 1) % len(FONT_SCALES)]
            self.pet_state['font_scale'] = self.font_scale
            self.save_state()
            if self.usage_win and user32.IsWindowVisible(self.usage_win.hwnd):
                self.hide_usage()
                self.show_usage(self._tray_left_anchor())
            C.log(self.cfg, 'pet menu: font_scale=%.2f' % self.font_scale)
            event(self.cfg, 'menu_font_scale', scale=self.font_scale)
        elif cid == 1008:
            r = user32.MessageBoxW(self.hwnd, '確定結束 DiskGuard 桌寵？（守護亦會停止）',
                                   'DiskGuard', 0x0004 | 0x0020)  # MB_YESNO|MB_ICONQUESTION
            if r == 6:  # IDYES
                self.sfx('exit')
                user32.PostMessageW(self.hwnd, WM_EXIT, 0, 0)
                event(self.cfg, 'menu_exit')

    # ---------- Phase 2 請求（UI → worker，只用 Event，不阻塞訊息迴圈） ----------
    def request_scan(self, reason='manual'):
        self.scan_reason = reason
        self.scan_req.set()
        event(self.cfg, 'scan_requested', reason=reason)

    def request_page(self, reason='manual'):
        if not self.auto_open and reason != 'manual':
            return          # D7「只通知不開頁」開關；手動點選單永遠可用
        self.page_reason = reason
        self.page_req.set()
        event(self.cfg, 'page_requested', reason=reason)

    # ---------- 滑鼠懸停互動（放大＋笑眼／說話／眨眼） ----------
    def _track_leave(self):
        """要求系統在滑鼠離開視窗時送 WM_MOUSELEAVE（一次性，每次移入都要重設）。"""
        tme = TRACKMOUSEEVENT()
        tme.cbSize = ctypes.sizeof(TRACKMOUSEEVENT)
        tme.dwFlags = TME_LEAVE
        tme.hwndTrack = self.hwnd
        tme.dwHoverTime = 0
        try:
            user32.TrackMouseEvent(ctypes.byref(tme))
        except Exception:
            pass

    def _now(self):
        """可注入時鐘（測試腳本可覆寫，不動真實時間）。"""
        return time.time()

    def hover_enter(self):
        if self.hover or self.anim or self.drag or not self.pet_win:
            return
        if not self.use_new_art:
            return
        self.hover = True
        self.hover_t0 = self._now()
        self.blink_next = self.hover_t0 + random.uniform(2.0, 3.2)
        self.blink_until = 0.0
        self.sfx('peek')
        user32.SetTimer(self.hwnd, WM_TIMER_HOVER, 110, None)
        self.hover_tick()

    def hover_leave(self):
        if not self.hover:
            return
        self.hover = False
        self.hover_t0 = self._now()      # 這一刻起算「縮回」
        self.hover_eye = None
        self.hover_mouth = None

    def hover_reset(self, repaint=True):
        """硬性收掉（拖曳、開選單、警示動畫時用）。"""
        user32.KillTimer(self.hwnd, WM_TIMER_HOVER)
        self.hover = False
        self.hover_scale = BASE_SCALE
        self.hover_eye = None
        self.hover_mouth = None
        if repaint:
            self.repaint_pet()

    def hover_tick(self):
        if not self.pet_win or not self.use_new_art:
            user32.KillTimer(self.hwnd, WM_TIMER_HOVER)
            return
        if self.drag or self.anim:
            return                        # 拖曳／警示動畫優先，先不覆蓋畫面
        now = self._now()
        if not self.hover:
            # 離開：0.13 s 內縮回原尺寸，然後停 timer
            k = (now - self.hover_t0) / 0.13
            if k >= 1.0:
                self.hover_scale = BASE_SCALE
                self.repaint_pet()
                user32.KillTimer(self.hwnd, WM_TIMER_HOVER)
                return
            self.hover_scale = HOVER_SCALE - (HOVER_SCALE - BASE_SCALE) * k
            self.repaint_pet()
            return
        e = now - self.hover_t0
        if e < 0.16:                             # 彈一下放大（ease-out）
            s = e / 0.16
            self.hover_scale = BASE_SCALE + (HOVER_SCALE - BASE_SCALE) * (1 - (1 - s) ** 3)
            self.hover_eye = 'happy'
            self.hover_mouth = 'smile'
        elif e < 0.72:                           # 打招呼：笑眼＋嘴巴開合
            self.hover_scale = HOVER_SCALE
            self.hover_eye = 'happy'
            self.hover_mouth = 'talk'
        else:                                    # 安靜下來：微笑＋偶爾眨眼
            self.hover_scale = HOVER_SCALE
            self.hover_mouth = 'smile'
            if now >= self.blink_next:
                self.blink_until = now + 0.13
                self.blink_next = now + random.uniform(2.2, 4.4)
            self.hover_eye = 'blink' if now < self.blink_until else 'open'
        self.repaint_pet()

    # ---------- 待機眨眼 ----------
    def blink_arm(self, delay=None):
        """排下一次待機眨眼（一次性 timer 鏈：每眨一次只喚醒兩次，
        不做 110 ms 常駐輪詢，避免整天燒 CPU）。"""
        if not (self.use_new_art and self.idle_blink and self.hwnd):
            return
        if delay is None:
            delay = random.uniform(*BLINK_GAP_SEC)
        user32.SetTimer(self.hwnd, WM_TIMER_BLINK, max(60, int(delay * 1000)), None)

    def blink_disarm(self):
        if self.hwnd:
            user32.KillTimer(self.hwnd, WM_TIMER_BLINK)
        self.idle_eye = None

    def blink_tick(self):
        if not (self.pet_win and self.use_new_art and self.idle_blink):
            self.blink_disarm()
            return
        if self.idle_eye == 'blink':              # 閉眼時間到 → 睜眼
            self.idle_eye = None
            self.repaint_pet()
            if self.blink_repeat > 0:             # 偶爾連眨第二下
                self.blink_repeat -= 1
                user32.SetTimer(self.hwnd, WM_TIMER_BLINK,
                                int(BLINK_DOUBLE_SEC * 1000), None)
            else:
                self.blink_arm()
            return
        if self.hover or self.anim or self.drag or self.frame != 'idle':
            self.blink_arm()                      # 懸停／拖曳／警示／分析中讓位，稍後再眨
            return
        self.idle_eye = 'blink'
        self.blink_repeat = 1 if random.random() < BLINK_DOUBLE_P else 0
        self.repaint_pet()
        user32.SetTimer(self.hwnd, WM_TIMER_BLINK,
                        int(BLINK_CLOSED_SEC * 1000), None)

    def stop_anim(self):
        if not self.anim:
            return False
        user32.KillTimer(self.hwnd, WM_TIMER_ANIM)
        end = self.anim['end']
        self.anim = None
        self.frame = 'idle'
        if self.pet_win:
            self.pet_win.move(*end)
        self.repaint_pet()
        event(self.cfg, 'alert_anim_stopped_by_user')
        return True

    def repaint_pet(self):
        if not self.pet_win:
            return
        f, t = self.frame, self.tick
        size = self.pet_win.w
        if not self.use_new_art:
            def draw(hdc):
                draw_pet(hdc, size, f, t)

            self.pet_win.paint(draw)
            return
        # 軟體渲染約 30–40 ms／幀 → 依 (狀態, 尺寸, 相位, 縮放, 表情, 嘴) 快取
        phase = (t // 3) if f == 'scan' else 0
        scale = round(self.hover_scale, 2)
        eye, mouth = self.hover_eye, self.hover_mouth
        # 待機眨眼只在「待機中且沒有懸停／拖曳／警示」時生效，避免卡在閉眼狀態
        if eye is None and self.idle_eye and f == 'idle' \
                and not self.hover and not self.drag and not self.anim:
            eye = self.idle_eye
        mframe = (int(time.time() * 7) % 8) if mouth == 'talk' else 0
        key = (f, size, phase, scale, eye, mouth, mframe)
        buf = self._sprite_cache.get(key)
        if buf is None:
            buf = pet_art.render(f, size, t, scale=scale, eye=eye, mouth=mouth)
            if len(self._sprite_cache) > 48:      # 懸停／字級／尺寸變更後避免無限長大
                self._sprite_cache.clear()
            self._sprite_cache[key] = buf
        self.pet_win.paint_buffer(buf)

    def on_alert(self):
        if time.time() < self.paused_until:
            return
        cd = float(self.cfg['alert'].get('cooldown_sec', 21600))
        if time.time() - self.last_alert < cd:
            event(self.cfg, 'alert_cooldown')
            return
        self.last_alert = time.time()
        d = C.disk_info(self.cfg['drive'])
        self.sfx('alert_enter')
        self.tray(icon=self.tray_icon(True),
                  tip='DiskGuard · 警告 C: %.2f%% 可用' % d['free_pct'])
        # 最近的托盤邊緣：用工作列 rect 作為托盤代理位置
        tr = RECT()
        user32.GetWindowRect(user32.FindWindowW('Shell_TrayWnd', None), ctypes.byref(tr))
        tx = (tr.left + tr.right) // 2
        ty = (tr.top + tr.bottom) // 2
        sx = user32.GetSystemMetrics(SM_XVIRTUALSCREEN)
        sy = user32.GetSystemMetrics(SM_YVIRTUALSCREEN)
        sw = user32.GetSystemMetrics(SM_CXVIRTUALSCREEN)
        sh = user32.GetSystemMetrics(SM_CYVIRTUALSCREEN)
        edges = [('bottom', abs(ty - (sy + sh)), sy + sh),
                 ('right', abs(tx - (sx + sw)), sx + sw),
                 ('top', abs(ty - sy), sy),
                 ('left', abs(tx - sx), sx)]
        edges.sort(key=lambda e: e[1])   # 等距時順序 下→右→上→左（穩定排序）
        edge = self.p['alert_entry_edge']
        if edge == 'auto-nearest-tray':
            edge, _, coord = edges[0]
        else:
            coord = dict((e[0], e[2]) for e in edges)[edge]
        tx0, ty0 = self._idle_pos()
        if edge in ('bottom', 'top'):
            start = (tx0, coord - int(self.p['size']))
        else:
            start = (coord - int(self.p['size']), ty0)
        self.anim = {'start': start, 'end': (tx0, ty0), 't0': time.time(),
                     'dur': float(self.p['alert_anim_sec']), 'edge': edge}
        if self.pet_win:
            self.pet_win.show(True)
            self.pet_win.move(*start)
        self.hover_reset(repaint=False)   # 警示動畫優先，先收掉懸停表情
        self.frame = 'alert'
        self.repaint_pet()
        user32.SetTimer(self.hwnd, WM_TIMER_ANIM,
                        max(1, int(1000 / int(self.p['alert_fps']))), None)
        C.log(self.cfg, 'pet alert pct=%.2f free=%.2fGB edge=%s' %
              (d['free_pct'], d['free_gb'], edge))
        event(self.cfg, 'alert', pct=d['free_pct'], edge=edge)
        # F8 與 F9 並行：動畫在 UI 執行緒跑，分析交給 worker
        self.request_scan('alert')

    def anim_tick(self):
        a = self.anim
        if not a:
            return
        e = (time.time() - a['t0']) / a['dur']
        if e >= 1.0:
            user32.KillTimer(self.hwnd, WM_TIMER_ANIM)
            self.anim = None
            self.frame = 'idle'
            if self.pet_win:
                self.pet_win.move(*a['end'])
            self.repaint_pet()
            event(self.cfg, 'alert_anim_done')
            return
        move = min(1.0, e * 3.0)
        ease = 1 - (1 - move) ** 3
        x = a['start'][0] + (a['end'][0] - a['start'][0]) * ease
        y = a['start'][1] + (a['end'][1] - a['start'][1]) * ease
        self.tick += 1
        if self.pet_win:
            self.pet_win.move(x, y)
        self.repaint_pet()

    # ---------- 背景 worker（F7/F9/F10） ----------
    def _run_scan_flow(self, cfg, kind):
        """背景分析；kind ∈ alert / manual / weekly。不阻塞 UI 訊息迴圈。"""
        if not self.scan_busy.acquire(blocking=False):
            event(self.cfg, 'scan_busy_skipped', reason=kind)
            return
        t0 = time.time()
        disk = C.disk_info(cfg['drive'])
        try:
            event(self.cfg, 'scan_start', state='SCANNING', reason=kind)
            C.log(self.cfg, 'pet scan start reason=%s' % kind)
            if kind == 'weekly':
                with self.state_lock:
                    st = C.read_state(cfg) or {}
                    level, scan = C.run_weekly(cfg, st, disk, 'pet weekly monitor')
            else:
                scan = C.do_scan(cfg)
                C.do_report(cfg, scan)
                with self.state_lock:
                    st = C.read_state(cfg) or {}
                    st['last_scan_ts'] = time.time()
                    C.write_state(cfg, st)
                level = C.decide_notify(cfg, disk)
                if level == 'alert':
                    C.write_notice(cfg, disk, '桌寵背景分析後仍低於 2%')
            self.last_scan_ts = time.time()
            self.sfx('happy')
            C.log(self.cfg,
                  'pet scan done reason=%s files=%d elapsed=%.1fs truncated=%s level=%s'
                  % (kind, scan.get('files_seen', 0), scan.get('elapsed_sec', 0),
                     scan.get('truncated'), level))
            event(self.cfg, 'scan_done', reason=kind, level=level,
                  files=scan.get('files_seen', 0),
                  truncated=bool(scan.get('truncated')),
                  elapsed_ms=int((time.time() - t0) * 1000))
            # F10：警示／手動分析完成後開頁；週一僅在仍低於門檻時開頁
            if kind in ('alert', 'manual') or level == 'alert':
                self.request_page(kind)
            elif level == 'warn' and cfg['alert'].get('notify_on_warn_pct'):
                C.write_notice(cfg, disk, '桌寵背景分析後介於 2%~10%')
        except Exception as ex:
            C.log(self.cfg, 'pet scan failed reason=%s: %s' % (kind, ex))
            event(self.cfg, 'scan_failed', reason=kind, ok=False)
        finally:
            self.scan_busy.release()

    def _browser_open(self, url):
        if not self.cfg['server'].get('app_browser', True):
            C.log(self.cfg, 'pet serve: app_browser=false, skip browser launch')
            return
        try:
            shell32.ShellExecuteW(0, 'open', url, None, None, 1)
        except Exception:
            srv = self.server
            if srv:
                try:
                    srv._launch_browser()
                except Exception:
                    pass

    def _track_requests(self, srv):
        """只包裹這個 server 實例的 handler，記錄最後活躍時間以判斷真閒置。"""
        rh = srv.httpd.RequestHandlerClass
        for name in ('do_GET', 'do_POST'):
            orig = getattr(rh, name, None)
            if not orig:
                continue

            def wrapped(handler, _orig=orig, _app=self):
                _app.server_last_active = time.time()
                return _orig(handler)

            setattr(rh, name, wrapped)

    def _serve_open(self, cfg, reason='manual'):
        """F10：按需 GuardServer；只有這裡會開監聽埠，閒置後自動關。"""
        if not self.serve_busy.acquire(blocking=False):
            return
        try:
            srv = self.server
            if srv and not getattr(srv, '_stop', None).is_set():
                self.server_last_active = time.time()
                self._browser_open(srv.url)
                C.log(self.cfg, 'pet serve reuse %s reason=%s' % (srv.url, reason))
                event(self.cfg, 'serve_reuse', reason=reason)
                return
            srv = C.GuardServer(cfg, open_browser=False)
            url = srv.start()
            self._track_requests(srv)
            C._ACTIVE_SERVER = srv
            self.server = srv
            self.server_last_active = time.time()
            self._browser_open(url)
            C.log(self.cfg, 'pet serve on demand %s reason=%s port=%d'
                  % (url, reason, srv.port))
            event(self.cfg, 'serve_open', reason=reason, port=srv.port)
            self.sfx('serve')
        except Exception as ex:
            C.log(self.cfg, 'pet serve failed reason=%s: %s' % (reason, ex))
            event(self.cfg, 'serve_failed', reason=reason, ok=False)
        finally:
            self.serve_busy.release()

    def _serve_close(self, cfg, why='idle'):
        srv = self.server
        if not srv:
            return
        self.server = None
        try:
            srv.close()
        except Exception:
            pass
        try:
            if C._ACTIVE_SERVER is srv:
                C._ACTIVE_SERVER = None
        except Exception:
            pass
        C.log(self.cfg, 'pet serve closed why=%s' % why)
        event(self.cfg, 'serve_close', why=why)

    def _serve_idle_check(self, cfg):
        srv = self.server
        if not srv:
            return
        if getattr(srv, '_stop', None) and srv._stop.is_set():
            self._serve_close(cfg, 'remote')
            return
        if self.server_last_active and \
                time.time() - self.server_last_active > self.idle_close:
            self._serve_close(cfg, 'idle')

    def worker(self):
        next_check = 0.0
        next_beat = 0.0
        while not self.stop_evt.wait(1.0):
            now = time.time()
            try:
                cfg = C.load_config(self.config_path) if self.config_path else C.load_config()
                if self.page_req.is_set():
                    self.page_req.clear()
                    self._serve_open(cfg, self.page_reason)
                if self.scan_req.is_set():
                    self.scan_req.clear()
                    self._run_scan_flow(cfg, self.scan_reason)
                if now >= next_check:
                    d = C.disk_info(cfg['drive'])
                    C.log(cfg, 'pet check pct=%.2f free=%.2fGB' %
                          (d['free_pct'], d['free_gb']))
                    if (d['free_pct'] < cfg['alert']['threshold_pct']
                            and now >= self.paused_until):
                        user32.PostMessageW(self.hwnd, WM_ALERT, 0, 0)
                    else:
                        self.tray_icon(False)
                        self.tray(tip=self.tip_text())
                        if now >= self.paused_until:
                            with self.state_lock:
                                st = C.read_state(cfg) or {}
                            ok, why = C.weekly_should_run(cfg, st, d)
                            if ok:
                                self._run_scan_flow(cfg, 'weekly')
                    next_check = now + int(self.p.get('check_interval_sec', 300))
                if now >= next_beat:
                    self.save_state()
                    next_beat = now + int(self.p['heartbeat_sec'])
                self._serve_idle_check(cfg)
            except Exception as ex:
                C.log(self.cfg, 'pet worker error: %s' % ex)
                event(self.cfg, 'worker_error', ok=False)

    # ---------- 生命週期 ----------
    def run(self):
        lock = C.acquire_lock(self.cfg)
        if not lock:
            C.log(self.cfg, 'pet: another instance is already running, exit')
            event(self.cfg, 'lock_busy', ok=False)
            return 2
        try:
            self.alive = True
            wc = WNDCLASSW()
            wc.style = CS_HREDRAW | CS_VREDRAW
            wc.lpfnWndProc = WNDPROC(self.wndproc)
            wc.hInstance = kernel32.GetModuleHandleW(None)
            wc.hCursor = user32.LoadCursorW(0, ctypes.cast(32512, wintypes.LPCWSTR))
            wc.lpszClassName = 'DiskGuardPetClass'
            if not user32.RegisterClassW(ctypes.byref(wc)):
                err = ctypes.get_last_error()
                if err != 1410:   # ERROR_CLASS_ALREADY_EXISTS
                    raise ctypes.WinError(err)
            self.hwnd = user32.CreateWindowExW(
                WS_EX_NOACTIVATE, 'DiskGuardPetClass', 'DiskGuard', 0,
                0, 0, 1, 1, 0, 0, wc.hInstance, None)
            if not self.hwnd:
                raise ctypes.WinError(ctypes.get_last_error())
            pos = self.pet_state.get('position') or self._idle_pos()
            x, y = self.clamp_pos(pos[0] if isinstance(pos, (list, tuple)) else pos[0][0],
                                  pos[1] if isinstance(pos, (list, tuple)) else pos[0][1])
            self.pet_state['position'] = [x, y]
            self.pet_win = Layered(int(self.p['size']), int(self.p['size']), (x, y), topmost=True)
            self.repaint_pet()
            self.pet_win.show(not self.p['idle_hidden'])
            self.tray(NIM_ADD, tip=self.tip_text(), icon=self.tray_icon(False))
            self.blink_arm(random.uniform(2.5, 5.0))   # 開場先眨一次，讓牠看起來是活的
            user32.SetTimer(self.hwnd, WM_TIMER_BEAT,
                            int(self.p['heartbeat_sec']) * 1000, None)
            t = threading.Thread(target=self.worker, daemon=True)
            t.start()
            self.sfx('boot')
            C.log(self.cfg, 'pet started size=%d sound=%s pos=%s' %
                  (self.p['size'], self.sound, (x, y)))
            event(self.cfg, 'boot', sound=self.sound, size=int(self.p['size']))
            msg = wintypes.MSG()
            while user32.GetMessageW(ctypes.byref(msg), 0, 0, 0) > 0:
                user32.TranslateMessage(ctypes.byref(msg))
                user32.DispatchMessageW(ctypes.byref(msg))
        finally:
            self.stop_evt.set()
            try:
                self._serve_close(self.cfg, 'app_exit')
            except Exception:
                pass
            try:
                if self.nid:
                    shell32.Shell_NotifyIconW(NIM_DELETE, ctypes.byref(self.nid))
            except Exception:
                pass
            for w in (self.menu_win, self.usage_win, self.pet_win):
                if w:
                    w.close()
            pet_sfx.stop()
            try:
                self.save_state()
            except Exception:
                pass
            C.log(self.cfg, 'pet stopped')
            event(self.cfg, 'exit')
            lock.close()
        return 0


# ---------------------------------------------------------------- CLI
def cmd_health(cfg):
    st = C.read_state(cfg) or {}
    pst = st.get('pet') or {}
    ev = []
    try:
        with open(os.path.join(C.out_dir(cfg), 'pet-events.jsonl'),
                  'r', encoding='utf-8') as f:
            ev = [json.loads(x) for x in f if x.strip()][-5:]
    except Exception:
        pass
    pid = pst.get('pid')
    alive = False
    if pid:
        try:
            kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
            kernel32.OpenProcess.restype = wintypes.HANDLE
            kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
            h = kernel32.OpenProcess(0x1000, False, int(pid))
            alive = bool(h)
            if h:
                kernel32.CloseHandle(h)
        except Exception:
            alive = False
    out = {
        'alive': alive, 'pid': pid,
        'last_heartbeat': pst.get('last_heartbeat'),
        'ui_state': pst.get('ui_state'),
        'sounds_enabled': pst.get('sounds_enabled'),
        'last_scan_ts': pst.get('last_scan_ts'),
        'auto_open_page_after_scan': pst.get('auto_open_page_after_scan'),
        'serve_idle_close_sec': pst.get('serve_idle_close_sec'),
        'serve_listening': bool(C._ACTIVE_SERVER),
        'events': ev,
    }
    print(json.dumps(out, ensure_ascii=False, indent=2))
    return 0


def cmd_selftest(cfg):
    ok = []
    try:
        p = load_pet_config(cfg)
        ok.append(('load_pet_config', True, 'size=%d sound=%s' % (p['size'], p['sounds_enabled'])))
    except Exception as ex:
        ok.append(('load_pet_config', False, str(ex)))
        p = dict(PET_DEFAULTS)
    d = C.disk_info(cfg['drive'])
    ok.append(('disk_info', d['total_gb'] > 0, '%.2f%%' % d['free_pct']))
    # 用隔離檔案測鎖，避免與正在運行的正式 watch 守護搶 watch.lock
    try:
        import msvcrt
        import tempfile
        tf = tempfile.NamedTemporaryFile(prefix='dg-pet-lock-', delete=False)
        tf.write(b'0')
        tf.flush()
        tf.close()
        with open(tf.name, 'a+b') as lk:
            lk.seek(0)
            msvcrt.locking(lk.fileno(), msvcrt.LK_NBLCK, 1)
            msvcrt.locking(lk.fileno(), msvcrt.LK_UNLCK, 1)
        os.unlink(tf.name)
        ok.append(('lock mechanism', True, 'isolated temp file'))
    except Exception as ex:
        ok.append(('lock mechanism', False, str(ex)))
    sf = [pet_sfx.wav_path(k) for k in pet_sfx.TABLE]
    ok.append(('sfx_table', len(pet_sfx.TABLE) >= 30, '%d sounds' % len(pet_sfx.TABLE)))
    ok.append(('sfx_files', all(os.path.exists(x) for x in sf),
               '%d/%d wav' % (sum(os.path.exists(x) for x in sf), len(sf))))
    icos = [pet_icon.load_handle(False), pet_icon.load_handle(True)]
    ok.append(('tray icons', all(icos), '%d/2 ico' % sum(bool(x) for x in icos)))
    labels = ' '.join(x[1] or '' for x in PetApp.MENU)
    ok.append(('F11 no dangerous menu',
               all(k not in labels for k in ('刪除', '回收站', '白名單')),
               '%d menu entries' % len([x for x in PetApp.MENU if x[1]])))
    ok.append(('F9 scan API', all(hasattr(C, k) for k in
                                  ('do_scan', 'do_report', 'weekly_should_run',
                                   'run_weekly', 'decide_notify', 'write_notice')), ''))
    ok.append(('F10 serve API', all(hasattr(C, k) for k in
                                    ('GuardServer', '_ACTIVE_SERVER'))
               and all(hasattr(C.GuardServer, k) for k in ('start', 'close')), ''))
    ok.append(('F10 config',
               isinstance(p.get('auto_open_page_after_scan'), bool)
               and int(p['serve_idle_close_sec']) >= 30,
               'auto_open=%s idle=%ss'
               % (p.get('auto_open_page_after_scan'), p.get('serve_idle_close_sec'))))
    for name, good, note in ok:
        print('%-18s %s %s' % (name, 'OK' if good else 'FAIL', note))
    return 0 if all(g for _, g, _ in ok) else 1


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    cfg_path = None
    if '--config' in argv:
        i = argv.index('--config')
        cfg_path = argv[i + 1] if i + 1 < len(argv) else None
        del argv[i:i + 2]
    cfg = C.load_config(cfg_path)
    if '--health' in argv:
        return cmd_health(cfg)
    if '--selftest' in argv:
        return cmd_selftest(cfg)
    try:
        p = load_pet_config(cfg)
    except Exception as ex:
        C.log(cfg, 'pet config_invalid: %s -> degrade to watch' % ex)
        event(cfg, 'config_invalid', ok=False)
        return C.cmd_watch(cfg)
    if not p['enabled']:
        C.log(cfg, 'pet disabled -> degrade to watch')
        return C.cmd_watch(cfg)
    # Session 0 檢查：互動 session 才可見 UI
    try:
        sid = kernel32.GetCurrentProcessId()
        kernel32.ProcessIdToSessionId.argtypes = [wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
        session = wintypes.DWORD()
        kernel32.ProcessIdToSessionId(sid, ctypes.byref(session))
        if session.value == 0:
            C.log(cfg, 'pet session=0 -> degrade to watch')
            event(cfg, 'degrade', reason='session0')
            return C.cmd_watch(cfg)
    except Exception:
        pass
    app = PetApp(cfg, p, cfg_path)
    return app.run()


if __name__ == '__main__':
    sys.exit(main())
