# -*- coding: utf-8 -*-
r"""cdisk-guard 原生警示框。

只用 ctypes + Win32 API，不依賴 tkinter（本機 WorkBuddy Python 沒有）、
不依賴 .NET / Add-Type / COM（會被安全鉤子攔截）。

    from win_dialog import show_alert
    choice = show_alert(free_gb=8.7, total_gb=475.8, pct=1.83)
    # -> 'A' | 'B'

按 A = 去清理磁盤；按 B = 人工處理。視窗標題固定為「磁盤剩餘空間」。
"""
import ctypes
from ctypes import wintypes

user32 = ctypes.WinDLL('user32', use_last_error=True)
gdi32 = ctypes.WinDLL('gdi32', use_last_error=True)
kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)

LRESULT = ctypes.c_ssize_t
WNDPROC = ctypes.WINFUNCTYPE(LRESULT, wintypes.HWND, wintypes.UINT,
                             wintypes.WPARAM, wintypes.LPARAM)

WM_DESTROY = 0x0002
WM_CLOSE = 0x0010
WM_COMMAND = 0x0111
WM_TIMER = 0x0113
WM_SETFONT = 0x0030
WS_CHILD = 0x40000000
WS_VISIBLE = 0x10000000
WS_TABSTOP = 0x00010000
WS_OVERLAPPED = 0x00000000
WS_CAPTION = 0x00C00000
WS_SYSMENU = 0x00080000
WS_MINIMIZEBOX = 0x00020000
BS_DEFPUSHBUTTON = 0x00000001
SS_LEFT = 0x00000000
WS_EX_TOPMOST = 0x00000008
WS_EX_DLGMODALFRAME = 0x00000001
SW_SHOW = 5
COLOR_BTNFACE = 15
DEFAULT_GUI_FONT = 17
IDC_ARROW = 32512
IDI_WARNING = 32514
ID_BTN_A = 1001
ID_BTN_B = 1002
ID_TIMER = 99
ID_CLICK_TIMER = 100


class WNDCLASSW(ctypes.Structure):
    _fields_ = [
        ('style', wintypes.UINT),
        ('lpfnWndProc', WNDPROC),
        ('cbClsExtra', ctypes.c_int),
        ('cbWndExtra', ctypes.c_int),
        ('hInstance', wintypes.HINSTANCE),
        ('hIcon', wintypes.HANDLE),
        ('hCursor', wintypes.HANDLE),
        ('hbrBackground', wintypes.HANDLE),
        ('lpszMenuName', wintypes.LPCWSTR),
        ('lpszClassName', wintypes.LPCWSTR),
    ]


class POINT(ctypes.Structure):
    _fields_ = [('x', ctypes.c_long), ('y', ctypes.c_long)]


class MSG(ctypes.Structure):
    _fields_ = [
        ('hwnd', wintypes.HWND),
        ('message', wintypes.UINT),
        ('wParam', wintypes.WPARAM),
        ('lParam', wintypes.LPARAM),
        ('time', wintypes.DWORD),
        ('pt', POINT),
        ('lPrivate', wintypes.DWORD),
    ]


def _bind():
    user32.RegisterClassW.argtypes = [ctypes.POINTER(WNDCLASSW)]
    user32.RegisterClassW.restype = ctypes.c_ushort
    user32.CreateWindowExW.argtypes = [
        wintypes.DWORD, wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.DWORD,
        ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_int,
        wintypes.HWND, wintypes.HMENU, wintypes.HINSTANCE, wintypes.LPVOID,
    ]
    user32.CreateWindowExW.restype = wintypes.HWND
    user32.DefWindowProcW.argtypes = [wintypes.HWND, wintypes.UINT,
                                      wintypes.WPARAM, wintypes.LPARAM]
    user32.DefWindowProcW.restype = LRESULT
    user32.SendMessageW.argtypes = [wintypes.HWND, wintypes.UINT,
                                    wintypes.WPARAM, wintypes.LPARAM]
    user32.SendMessageW.restype = LRESULT
    user32.GetMessageW.argtypes = [ctypes.POINTER(MSG), wintypes.HWND,
                                   wintypes.UINT, wintypes.UINT]
    user32.GetMessageW.restype = ctypes.c_int
    user32.TranslateMessage.argtypes = [ctypes.POINTER(MSG)]
    user32.DispatchMessageW.argtypes = [ctypes.POINTER(MSG)]
    user32.DispatchMessageW.restype = LRESULT
    user32.PostQuitMessage.argtypes = [ctypes.c_int]
    user32.SetTimer.argtypes = [wintypes.HWND, ctypes.c_size_t,
                                wintypes.UINT, ctypes.c_void_p]
    user32.SetTimer.restype = ctypes.c_size_t
    user32.PostMessageW.argtypes = [wintypes.HWND, wintypes.UINT,
                                    wintypes.WPARAM, wintypes.LPARAM]
    user32.PostMessageW.restype = wintypes.BOOL
    user32.LoadCursorW.argtypes = [wintypes.HINSTANCE, wintypes.LPCWSTR]
    user32.LoadCursorW.restype = wintypes.HANDLE
    user32.LoadIconW.argtypes = [wintypes.HINSTANCE, wintypes.LPCWSTR]
    user32.LoadIconW.restype = wintypes.HANDLE
    user32.GetSysColorBrush.argtypes = [ctypes.c_int]
    user32.GetSysColorBrush.restype = wintypes.HANDLE
    user32.GetSystemMetrics.argtypes = [ctypes.c_int]
    user32.GetSystemMetrics.restype = ctypes.c_int
    user32.ShowWindow.argtypes = [wintypes.HWND, ctypes.c_int]
    user32.SetForegroundWindow.argtypes = [wintypes.HWND]
    user32.SetWindowPos.argtypes = [wintypes.HWND, wintypes.HWND,
                                    ctypes.c_int, ctypes.c_int,
                                    ctypes.c_int, ctypes.c_int, wintypes.UINT]
    user32.DestroyWindow.argtypes = [wintypes.HWND]
    user32.UnregisterClassW.argtypes = [wintypes.LPCWSTR, wintypes.HINSTANCE]
    gdi32.GetStockObject.argtypes = [ctypes.c_int]
    gdi32.GetStockObject.restype = wintypes.HANDLE
    kernel32.GetModuleHandleW.argtypes = [wintypes.LPCWSTR]
    kernel32.GetModuleHandleW.restype = wintypes.HMODULE


_STATE = {'choice': None}
_PROC_REF = None          # 防止 WNDPROC callback 被 GC
_CLASS_NAME = 'cdisk_guard_alert_class_v1'


def _wndproc(hwnd, msg, wparam, lparam):
    if msg == WM_COMMAND:
        cid = int(wparam) & 0xFFFF
        if cid == ID_BTN_A:
            _STATE['choice'] = 'A'
            user32.PostQuitMessage(0)
        elif cid == ID_BTN_B:
            _STATE['choice'] = 'B'
            user32.PostQuitMessage(0)
    elif msg in (WM_DESTROY, WM_CLOSE):
        if _STATE['choice'] is None:
            _STATE['choice'] = 'B'
        user32.PostQuitMessage(0)
    elif msg == WM_TIMER and int(wparam) == ID_TIMER:
        if _STATE['choice'] is None:
            _STATE['choice'] = 'TIMEOUT'
        user32.PostQuitMessage(0)
    elif msg == WM_TIMER and int(wparam) == ID_CLICK_TIMER:
        # 僅供 selftest：送出與實際點擊完全相同的 WM_COMMAND
        cid = ID_BTN_A if _STATE.get('auto_click') == 'A' else ID_BTN_B
        user32.PostMessageW(hwnd, WM_COMMAND, cid, 0)
    return user32.DefWindowProcW(hwnd, msg, wparam, lparam)


def _child(parent, cls, text, x, y, w, h, style, cid, font):
    hwnd = user32.CreateWindowExW(
        0, cls, text, WS_CHILD | WS_VISIBLE | style,
        x, y, w, h, parent, ctypes.c_void_p(cid), None, None)
    if hwnd and font:
        user32.SendMessageW(hwnd, WM_SETFONT, font, 1)
    return hwnd


def _fallback_messagebox(title, body):
    """自訂視窗失敗時的保底：標準 MessageBox（是=A / 否=B）。"""
    text = body + '\n\n【是(Y)】= A. 去清理磁盤\n【否(N)】= B. 人工處理'
    user32.MessageBoxW.argtypes = [wintypes.HWND, wintypes.LPCWSTR,
                                   wintypes.LPCWSTR, wintypes.UINT]
    user32.MessageBoxW.restype = ctypes.c_int
    # MB_YESNO | MB_ICONWARNING | MB_TOPMOST | MB_SETFOREGROUND
    r = user32.MessageBoxW(None, text, title, 0x04 | 0x30 | 0x40000 | 0x10000)
    return 'A' if r == 6 else 'B'


def show_alert(free_gb, total_gb, pct, title='磁盤剩餘空間',
               auto_close_sec=None, extra_line='', auto_click=None):
    """顯示雙按鈕警示框，回傳 'A' / 'B' / 'TIMEOUT'。

    auto_click / auto_close_sec 僅供 selftest 使用，正式執行時不傳。
    """
    global _PROC_REF
    body = ('磁盤剩餘空間：{:.2f} GB / {:.2f} GB（{:.2f}%）\n'
            '已低於安全門檻 2%，建議立即清理，以免系統或應用程式寫入失敗。'
            .format(free_gb, total_gb, pct))
    if extra_line:
        body += '\n' + extra_line
    try:
        _bind()
        hinst = kernel32.GetModuleHandleW(None)
        _PROC_REF = WNDPROC(_wndproc)
        wc = WNDCLASSW()
        wc.style = 0
        wc.lpfnWndProc = _PROC_REF
        wc.cbClsExtra = 0
        wc.cbWndExtra = 0
        wc.hInstance = hinst
        wc.hIcon = user32.LoadIconW(None, ctypes.c_wchar_p(IDI_WARNING))
        wc.hCursor = user32.LoadCursorW(None, ctypes.c_wchar_p(IDC_ARROW))
        wc.hbrBackground = user32.GetSysColorBrush(COLOR_BTNFACE)
        wc.lpszMenuName = None
        wc.lpszClassName = _CLASS_NAME
        atom = user32.RegisterClassW(ctypes.byref(wc))
        if not atom:
            # 類別已註冊（同行程重複呼叫）也視為可用
            if ctypes.get_last_error() != 1410:
                return _fallback_messagebox(title, body)

        W, H = 560, 268
        sx, sy = user32.GetSystemMetrics(0), user32.GetSystemMetrics(1)
        x, y = max(0, (sx - W) // 2), max(0, (sy - H) // 2)
        style = WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX | WS_VISIBLE
        main = user32.CreateWindowExW(
            WS_EX_TOPMOST | WS_EX_DLGMODALFRAME, _CLASS_NAME, title, style,
            x, y, W, H, None, None, hinst, None)
        if not main:
            return _fallback_messagebox(title, body)

        font = gdi32.GetStockObject(DEFAULT_GUI_FONT)
        f = int(font) if font else 0
        _child(main, 'Static', '⚠  磁盤剩餘空間不足', 22, 18, 500, 26, SS_LEFT, 0, f)
        lines = body.split('\n')
        for i, ln in enumerate(lines):
            _child(main, 'Static', ln, 22, 54 + i * 24, 512, 22, SS_LEFT, 0, f)
        _child(main, 'Static', '請選擇處理方式：', 22, 128, 500, 22, SS_LEFT, 0, f)
        _child(main, 'Button', 'A.  去清理磁盤', 22, 170, 240, 42,
               WS_TABSTOP | BS_DEFPUSHBUTTON, ID_BTN_A, f)
        _child(main, 'Button', 'B.  人工處理', 282, 170, 240, 42,
               WS_TABSTOP, ID_BTN_B, f)

        _STATE['choice'] = None
        _STATE['auto_click'] = auto_click
        if auto_click:
            user32.SetTimer(main, ID_CLICK_TIMER, 600, None)
        if auto_close_sec:
            user32.SetTimer(main, ID_TIMER, int(auto_close_sec * 1000), None)
        user32.ShowWindow(main, SW_SHOW)
        user32.SetForegroundWindow(main)
        # HWND_TOPMOST = -1；SWP_NOSIZE|SWP_NOMOVE|SWP_SHOWWINDOW = 0x43
        user32.SetWindowPos(main, ctypes.c_void_p(-1), 0, 0, 0, 0, 0x43)

        msg = MSG()
        while True:
            r = user32.GetMessageW(ctypes.byref(msg), None, 0, 0)
            if r <= 0:
                break
            user32.TranslateMessage(ctypes.byref(msg))
            user32.DispatchMessageW(ctypes.byref(msg))
        user32.DestroyWindow(main)
        user32.UnregisterClassW(_CLASS_NAME, hinst)
        return _STATE['choice'] or 'B'
    except Exception:
        try:
            return _fallback_messagebox(title, body)
        except Exception:
            return 'B'


if __name__ == '__main__':
    import sys
    secs = float(sys.argv[1]) if len(sys.argv) > 1 else 0
    click = sys.argv[2] if len(sys.argv) > 2 else None
    print('dialog_test_choice=' + str(show_alert(
        8.7, 475.8, 1.83, auto_close_sec=secs or None, auto_click=click)))
