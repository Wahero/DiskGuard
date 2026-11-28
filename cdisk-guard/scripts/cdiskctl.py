# -*- coding: utf-8 -*-
r"""cdisk-guard · C 盤空間守護 CLI（純 stdlib，運行期零 LLM 呼叫）

    status / scan / report / serve / alert / watch / delete / selftest

設計與取捨詳見 references/evaluation.md、references/rules.md。
"""
import os
import sys
import json
import copy
import time
import math
from urllib.parse import parse_qs
from collections import deque
import heapq
import shutil
import zipfile
import secrets
import argparse
import datetime
import tempfile
import threading
import subprocess
import ctypes
from ctypes import wintypes
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPTS = os.path.join(ROOT, 'scripts')
sys.path.insert(0, SCRIPTS)


def version_string():
    """版本號以 cdisk-guard/VERSION 為單一來源；讀不到回 0.0.0，不阻斷任何功能。"""
    try:
        with open(os.path.join(ROOT, 'VERSION'), encoding='utf-8') as f:
            return f.read().strip() or '0.0.0'
    except OSError:
        return '0.0.0'


from win_dialog import show_alert  # noqa: E402

MB = 1024.0 * 1024.0
GB = 1024.0 * MB
DEFAULT_CONFIG = os.path.join(ROOT, 'config.json')

# ---------------------------------------------------------------- 分級規則
C_ROOT = {
    'windows', 'program files', 'program files (x86)', 'programdata',
    'system volume information', 'recovery', '$winreagent', 'perflogs',
    'documents and settings', 'config.msi', 'inetpub', 'boot',
    'intel', 'drivers', 'driver', 'krecycle', 'onedrivetemp',
    'bundle', 'msocache', '$windows.~ws', '$windows.~bt',
}
C_USER = {'default', 'public', 'desktop.ini', 'all users', 'default user'}
C_USERITEM = {
    'desktop', 'documents', 'pictures', 'videos', 'music', 'favorites',
    'contacts', 'links', 'searches', 'saved games', 'onedrive', 'appdata',
    '.ssh', '.workbuddy', '.openclaw', '.claude', '.codex', '.hermes',
    '.git-credentials', '.aws', '.gnupg', '.kube',
}
A_JUNK = {
    'windowstemp', 'usertemp', 'windowsupdatecache', 'prefetch',
    'chromecache', 'edgecache', 'inetcache', 'thumbnailcache',
    'crashdumps', 'nvidiadownloader', 'thunderupdate', 'wer',
    'windowsold', 'recyclebin', 'ctmp',
}
C_JUNK = {'windowsinstaller', 'packagecache'}
NOTE = {
    'A': '臨時檔／快取／安裝包殘留，刪除後程式會自動重建，不影響使用。',
    'B': '軟體資料、模型快取或自建目錄，刪不刪取決於你是否還在用；可能需要重新下載。',
    'C': '系統元件／個人資料／憑證，手動刪除會導致系統異常或不可回復的資料丟失，禁止勾選。',
}
PROFILE_ALLOWED = {'users', 'windows', 'programdata', 'tmp', 'temp', '$recycle.bin'}


def path_scope_ok(drive, path):
    """路徑是否落在「可刪範圍」內——報告端與刪除端共用同一套規則。

    回傳 (ok, reason)。這條規則若兩邊各寫一份，遲早漂移成「報告顯示可勾、
    按下去卻被拒」，使用者只會覺得壞了；所以只留在這裡一份。
    """
    low = str(path or '').rstrip('\\').lower()
    d = norm_drive(drive).lower().rstrip('\\')
    if not low or '..' in low or not low.startswith(d + '\\'):
        return False, '路徑超出允許範圍'
    parts = low[len(d) + 1:].split('\\')
    if not parts or not parts[0]:
        return False, '磁碟根目錄本身不可刪'
    if parts[0] not in PROFILE_ALLOWED:
        return False, '根目錄下的整層目錄不提供刪除（安全邊界）'
    if parts[0] == 'users' and len(parts) == 2:
        return False, '使用者設定檔總目錄不可整刪'
    return True, ''


def is_profile_file(name):
    n = name.lower()
    return (n.startswith('ntuser.dat') or n.startswith('ntuser.ini')
            or n == 'desktop.ini' or n.endswith('.regtrans-ms')
            or n.endswith('.tm.blf'))


def classify(kind, name, path):
    """回傳 (tier, note)。沿用 2026-11-23 的三檔規則表。"""
    n = name.lower().strip()
    p = path.lower().replace('/', '\\')

    if kind == 'root':
        if n in C_ROOT or n.startswith('$recycle'):
            if n == '$recycle.bin':
                return 'A', '回收站內容，應透過「清空回收站」釋放，不要刪目錄本身。'
            return 'C', NOTE['C']
        if n in ('tmp', 'temp'):
            return 'A', NOTE['A']
        if n == 'users':
            return 'C', '使用者設定檔總目錄，不可整刪；請展開下方明細逐項判斷。'
        return 'B', '自建／第三方目錄，需你確認是否仍在使用。'
    if kind == 'user':
        if n in C_USER or is_profile_file(n):
            return 'C', '系統預設設定檔或使用者設定單元，禁止刪除。'
        return 'B', '使用者設定檔總目錄，不可整刪；請展開下方明細逐項判斷。'
    if kind == 'useritem':
        if n in C_USERITEM or is_profile_file(n):
            return 'C', NOTE['C']
        if n in ('.pytest_cache', 'crashdumps') or 'temp' in n or n.endswith('.crdownload') or n.endswith('.part'):
            return 'A', NOTE['A']
        if n == 'downloads':
            return 'B', '個人下載目錄，可能含不可回復的檔案，刪除前請逐項查看。'
        return 'B', NOTE['B']
    if kind == 'junk':
        if n in C_JUNK:
            return 'C', 'MSI 安裝包快取，刪除後軟體無法卸載或修復，必須保留。'
        if n in A_JUNK:
            if n == 'recyclebin':
                return 'A', '回收站內容，應透過「清空回收站」釋放，不要刪目錄本身。'
            if n == 'thumbnailcache':
                return 'A', '僅刪除 thumbcache_*.db，保留目錄本體。'
            if n in ('windowsupdatecache', 'prefetch', 'windowsold', 'windowstemp'):
                return 'A', '系統級快取，可能需要管理員權限；使用中檔案會自動略過。'
            return 'A', NOTE['A']
        return 'B', NOTE['B']
    if kind == 'temp':
        return 'A', NOTE['A']
    if kind in ('localapp', 'roaming'):
        if 'tencent' in n or 'kingsoft' in n or 'wechat' in n:
            return 'C', '含聊天記錄／文件備份，絕不能整目錄刪除；請在軟體內清理快取。'
        if any(k in n for k in ('cache', 'update', 'logs', 'crash', 'gpu')):
            return 'A', NOTE['A']
        return 'B', NOTE['B']
    if kind == 'big':
        # 看「磁碟:\ 之後的第一段」而不是寫死 c:\ ——大檔也可能在 D:\Windows（雙系統）。
        seg = p.split('\\')
        top = seg[1] if len(seg) > 1 else ''
        if top in ('windows', 'program files', 'program files (x86)', 'programdata'):
            return 'C', NOTE['C']
        if any(p.endswith(x) for x in ('.exe', '.msi', '.zip', '.7z', '.rar', '.iso')):
            return 'B', '疑似安裝包／壓縮檔，確認不再需要後才可刪除。'
        return 'B', NOTE['B']
    return 'B', NOTE['B']


# ---------------------------------------------------------------- 基礎工具
def now_str():
    return datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')


def load_config(path=None):
    with open(path or DEFAULT_CONFIG, 'r', encoding='utf-8') as f:
        return json.load(f)


def out_dir(cfg):
    d = cfg['paths']['output_dir']
    if not os.path.isabs(d):
        d = os.path.join(ROOT, d)
    os.makedirs(d, exist_ok=True)
    return d


# ---------------------------------------------------------------- 磁碟選擇
# v1.0.6 起三個概念要分清楚，混在一起就會出現「只想監控 C 盤，卻被 D 盤的警示吵」：
#   cfg['drives']  掃描／清理範圍。"auto"＝本機所有固定碟（預設）。
#   cfg['monitor'] 只監控剩餘空間的碟。預設只有系統碟 C:。
#   cfg['drive']   本次操作的「主碟」。既有逐碟函式（do_scan / disk_info /
#                  validate_targets / build_items）全都讀它，所以只要這個欄位正確，
#                  單碟邏輯自動正確；多碟只是「對每顆碟各跑一次，再合併」。
# 報告只有一份：所有掃描範圍內的碟放進同一頁，用碟別標籤區分。
def norm_drive(d):
    """'c' / 'C:' / 'c:\\' 一律正規化成 'C:\\'。"""
    s = str(d or '').strip().upper().replace('/', '\\').rstrip('\\')
    if not s:
        return ''
    if not s.endswith(':'):
        s += ':'
    return s + '\\'


def system_drive():
    return norm_drive(os.environ.get('SystemDrive', 'C:'))


def drive_key(drive):
    """'C:\\' -> 'C'（用在檔名）。"""
    n = norm_drive(drive)
    return n[0] if n else 'C'


def drive_of(path):
    """從絕對路徑取碟代號字母（大寫）；不是絕對路徑回空字串。"""
    p = str(path or '')
    return p[0].upper() if len(p) >= 2 and p[1] == ':' else ''


_kd = ctypes.WinDLL('kernel32', use_last_error=True)
_kd.GetDriveTypeW.argtypes = [wintypes.LPCWSTR]
_kd.GetDriveTypeW.restype = wintypes.UINT
_kd.GetDiskFreeSpaceExW.argtypes = [
    wintypes.LPCWSTR, ctypes.POINTER(ctypes.c_ulonglong),
    ctypes.POINTER(ctypes.c_ulonglong), ctypes.POINTER(ctypes.c_ulonglong)]
_kd.GetDiskFreeSpaceExW.restype = wintypes.BOOL


def drive_exists(drive):
    """碟是否真的可讀。光碟機空槽、已拔掉的外接碟都會回 False。

    只看「代號在不在」不夠——Windows 會為拔掉的外接碟保留代號，
    這時 disk_info 會拋 OSError，整個掃描流程就中斷了。
    """
    d = norm_drive(drive)
    if len(d) < 3:
        return False
    avail, total, free = (ctypes.c_ulonglong(0) for _ in range(3))
    try:
        ok = _kd.GetDiskFreeSpaceExW(d, ctypes.byref(avail),
                                    ctypes.byref(total), ctypes.byref(free))
    except Exception:
        return False
    return bool(ok) and total.value > 0


def all_drives():
    """本機可處理的磁碟：固定碟＋可移動碟，排除光碟機與網路碟。

    DRIVE_REMOVABLE=2、DRIVE_FIXED=3；光碟(5)與網路(4)掃描既慢又沒意義。
    """
    out = []
    for ch in 'ABCDEFGHIJKLMNOPQRSTUVWXYZ':
        d = ch + ':\\'
        try:
            t = _kd.GetDriveTypeW(d)
        except Exception:
            t = 0
        if t in (2, 3) and drive_exists(d):
            out.append(d)
    return out


def drive_list(cfg):
    """掃描／清理範圍。

    "auto"（預設）＝本機所有固定碟；給清單就照清單（保留使用者刻意的取捨）。
    這與 monitor_drives 是兩件事：可以「掃全部、只監控 C」。
    """
    raw = cfg.get('drives')
    if isinstance(raw, str):
        if raw.strip().lower() in ('auto', 'all', '*', ''):
            return all_drives() or [system_drive()]
        raw = [raw]
    if not isinstance(raw, list) or not raw:
        return all_drives() or [system_drive()]
    out = []
    for d in raw:
        n = norm_drive(d)
        if n and n not in out:
            out.append(n)
    return out or [system_drive()]


def monitor_drives(cfg):
    """只監控剩餘空間的碟（警示／托盤／用量面板）。預設系統碟一顆。"""
    raw = (cfg.get('monitor') or {}).get('drives')
    if isinstance(raw, str):
        raw = [raw]
    if not isinstance(raw, list) or not raw:
        raw = [cfg.get('drive') or system_drive()]
    out = []
    for d in raw:
        n = norm_drive(d)
        if n and n not in out:
            out.append(n)
    return out or [system_drive()]


def scan_scope(cfg):
    """本次執行實際要處理的碟：--drive／本次請求指定優先，否則用設定範圍。"""
    raw = cfg.get('_scope')
    if raw:
        out = []
        for d in raw:
            n = norm_drive(d)
            if n and n not in out:
                out.append(n)
        if out:
            return out
    return drive_list(cfg)


def normalize_config(cfg, drive=None, scope=None):
    """整理 cfg['drive']（主碟）、cfg['drives']（可處理範圍）、cfg['_scope']（本次範圍）。

    --drive 指定某顆碟時，本次就只處理它——「我只是想看 D」，不該連帶重掃 C。
    """
    ds = drive_list(cfg)
    cur = norm_drive(drive) or norm_drive(cfg.get('drive')) or ds[0]
    if cur not in ds:
        ds.append(cur)
    cfg['drives'] = ds
    cfg['drive'] = cur
    if scope:
        cfg['_scope'] = [norm_drive(x) for x in scope if norm_drive(x)]
    elif drive:
        cfg['_scope'] = [cur]
    else:
        cfg.pop('_scope', None)
    return cfg


def cfg_on(cfg, drive):
    """取某顆碟的設定副本：cfg['drive'] 換成它，其餘（含掃描範圍）不變。

    用副本而不是改共用物件，請求之間才不會互相污染。
    """
    d = norm_drive(drive)
    if not d or d == norm_drive(cfg.get('drive')):
        return cfg
    c = copy.deepcopy(cfg)
    c['drive'] = d
    return c


def last_scope(cfg):
    """上一次實際分析過的磁碟範圍。開網頁時要顯示「這份報告實際包含什麼」。"""
    raw = (read_state(cfg) or {}).get('last_scope')
    if not isinstance(raw, list) or not raw:
        return []
    out = []
    for d in raw:
        n = norm_drive(d)
        if n and n not in out:
            out.append(n)
    return out


def remember_scope(cfg, drives, stamp=None):
    """記下這次分析了哪些碟（給網頁與下次開頁用）。"""
    try:
        st = read_state(cfg)
        st['last_scope'] = [norm_drive(d) for d in drives]
        st['last_scope_ts'] = time.time()
        st['last_scope_at'] = stamp or now_str()
        write_state(cfg, st)
    except Exception:
        pass


def scan_path(cfg, drive=None):
    return os.path.join(out_dir(cfg), 'scan_%s.json' % drive_key(drive or cfg['drive']))


def page_path(cfg, drive=None):
    """綜合報告的檔名（一份，不分碟）。

    舊設定可能還是 `{drive}盘清理清单.html`：升級後直接改成綜合報告檔名，
    否則每顆碟會各寫一份，等於回到「分開」的老行為。
    """
    fn = cfg['paths'].get('page_filename') or '磁碟清理清單.html'
    if '{drive}' in fn:
        fn = fn.replace('{drive}盘清理清单.html', '磁碟清理清單.html')
        fn = fn.replace('{drive}', '')
    return os.path.join(out_dir(cfg), fn)


def emit(msg):
    try:
        print(msg, flush=True)
    except Exception:
        pass


def log(cfg, msg):
    line = '[%s] %s' % (now_str(), msg)
    try:
        with open(os.path.join(out_dir(cfg), cfg['paths']['log_filename']),
                  'a', encoding='utf-8') as f:
            f.write(line + '\n')
    except Exception:
        pass
    return line


def read_state(cfg):
    p = os.path.join(out_dir(cfg), 'state.json')
    try:
        with open(p, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception:
        return {}


def write_state(cfg, st):
    p = os.path.join(out_dir(cfg), 'state.json')
    tmp = p + '.tmp'
    with open(tmp, 'w', encoding='utf-8') as f:
        json.dump(st, f, ensure_ascii=False, indent=2)
    os.replace(tmp, p)


def state_for(st, drive):
    """回傳某顆碟的狀態子字典（自動建立，寫回 st 本身）。

    警示冷卻、上次分析時間、週期分析日期都是「每顆碟各自算」——若共用一份，
    D 盤剛警示完會讓 C 盤的警示被靜默跳過，反之亦然。
    舊版把這些放在頂層，第一次使用時遷移給主碟，避免升級後遺失紀錄。
    """
    dr = st.setdefault('drives', {})
    key = drive_key(drive)
    sub = dr.setdefault(key, {})
    if not dr.get('_migrated'):
        for k in ('last_scan_ts', 'last_alert_ts', 'last_alert_pct',
                  'last_alert_choice', 'last_weekly_date', 'last_weekly_ts',
                  'last_weekly_status', 'last_weekly_reason'):
            if k in st and k not in sub:
                sub[k] = st[k]
        dr['_migrated'] = True
    return sub


# ---------------------------------------------------------------- Win32 量測
_kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
_kernel32.GetDiskFreeSpaceExW.argtypes = [
    wintypes.LPCWSTR, ctypes.POINTER(ctypes.c_ulonglong),
    ctypes.POINTER(ctypes.c_ulonglong), ctypes.POINTER(ctypes.c_ulonglong)]
_kernel32.GetDiskFreeSpaceExW.restype = wintypes.BOOL


class _FILETIME(ctypes.Structure):
    _fields_ = [('lo', wintypes.DWORD), ('hi', wintypes.DWORD)]


_kernel32.GetSystemTimes.argtypes = [
    ctypes.POINTER(_FILETIME), ctypes.POINTER(_FILETIME), ctypes.POINTER(_FILETIME)]
_kernel32.GetSystemTimes.restype = wintypes.BOOL


def disk_info(drive=None):
    drive = norm_drive(drive) or system_drive()
    free = ctypes.c_ulonglong(0)
    total = ctypes.c_ulonglong(0)
    avail = ctypes.c_ulonglong(0)
    if not _kernel32.GetDiskFreeSpaceExW(drive, ctypes.byref(avail),
                                        ctypes.byref(total), ctypes.byref(free)):
        raise OSError('GetDiskFreeSpaceExW failed: %s' % ctypes.get_last_error())
    t, f = float(total.value), float(free.value)
    return {
        'drive': drive,
        'total_bytes': total.value,
        'free_bytes': free.value,
        'total_gb': round(t / GB, 2),
        'free_gb': round(f / GB, 2),
        'used_gb': round((t - f) / GB, 2),
        'free_pct': round(f / t * 100, 2) if t else 0.0,
        'checked_at': now_str(),
    }


def drive_inventory(cfg, scans=None):
    """所有可處理磁碟的清單，標出哪幾顆「這次已分析」。

    網頁同時用兩份資訊：頁首只列已分析的碟（chips），「選擇磁碟」彈窗列全部
    （含未分析的），使用者才知道自己漏了哪顆。
    """
    scanned = {}
    for s in scans or []:
        scanned[norm_drive(s.get('drive'))] = s
    keys = list(drive_list(cfg))
    for d in scanned:
        if d and d not in keys:
            keys.append(d)
    rows = []
    for d in keys:
        row = {'drive': d, 'letter': drive_key(d),
               'scanned': d in scanned}
        try:
            di = disk_info(d)
            row.update({'ok': True, 'total_gb': di['total_gb'],
                        'free_gb': di['free_gb'], 'used_gb': di['used_gb'],
                        'free_pct': di['free_pct'], 'checked_at': di['checked_at']})
        except OSError:
            row.update({'ok': False, 'error': '無法讀取（碟可能已移除）'})
        s = scanned.get(d)
        if s:
            row['scan'] = {'created': s.get('created'),
                           'files_seen': s.get('files_seen', 0),
                           'elapsed_sec': s.get('elapsed_sec', 0),
                           'truncated': bool(s.get('truncated'))}
        rows.append(row)
    return rows


def drive_summary(cfg, drives=None):
    """每顆碟的容量摘要，給桌寵用量面板與托盤用。

    讀不到的碟（外接碟拔掉、光碟機空槽）不拋例外，標成 ok=False——
    一顆碟離線不該讓整個面板／報告渲染失敗。
    """
    cur = norm_drive(cfg.get('drive'))
    out = []
    for d in (drives or drive_list(cfg)):
        row = {'drive': d, 'letter': drive_key(d), 'current': d == cur}
        try:
            di = disk_info(d)
            row.update({'ok': True, 'total_gb': di['total_gb'],
                        'free_gb': di['free_gb'], 'used_gb': di['used_gb'],
                        'free_pct': di['free_pct']})
        except OSError:
            row.update({'ok': False, 'error': '無法讀取（碟可能已移除）'})
        out.append(row)
    return out


def worst_monitor(cfg):
    """監控範圍內最緊張的那顆碟；讀不到就跳過（外接碟拔掉不該讓守護崩）。

    回傳 (disk_info, drive)。監控範圍預設只有 C:，所以單碟使用者行為不變。
    """
    best = None
    for d in monitor_drives(cfg):
        try:
            di = disk_info(d)
        except OSError:
            continue
        if best is None or di['free_pct'] < best[0]['free_pct']:
            best = (di, d)
    if best:
        return best
    return disk_info(cfg['drive']), cfg['drive']


def _ft(v):
    return (v.hi << 32) | v.lo


def cpu_usage(sample_sec=1.0):
    """以 GetSystemTimes 取樣，回傳 0~100 的 CPU 使用率；不開 subprocess。"""
    def snap():
        i, k, u = _FILETIME(), _FILETIME(), _FILETIME()
        if not _kernel32.GetSystemTimes(ctypes.byref(i), ctypes.byref(k), ctypes.byref(u)):
            return None
        return _ft(i), _ft(k), _ft(u)
    a = snap()
    time.sleep(max(0.2, sample_sec))
    b = snap()
    if not a or not b:
        return 0.0
    idle = b[0] - a[0]
    kern = b[1] - a[1]
    user = b[2] - a[2]
    total = kern + user
    if total <= 0:
        return 0.0
    return max(0.0, min(100.0, (total - idle) / total * 100.0))


def empty_recycle_bin(drive=None):
    """清空「指定磁碟」的回收站；drive=None 才會清全部（多碟時絕不要用 None）。

    SHEmptyRecycleBinW 的第二個參數就是碟根——傳 None 是「所有磁碟」，
    過去就是這樣寫的：在只有 C 盤時看不出問題，多碟時會清掉報告沒列到的碟。
    """
    try:
        sh = ctypes.WinDLL('shell32', use_last_error=True)
        sh.SHEmptyRecycleBinW.argtypes = [wintypes.HWND, wintypes.LPCWSTR, wintypes.DWORD]
        sh.SHEmptyRecycleBinW.restype = ctypes.c_long
        root = norm_drive(drive) or None
        hr = sh.SHEmptyRecycleBinW(None, root, 0x01 | 0x02 | 0x04)
        detail = 'HRESULT=%s' % hr
        if root:
            detail += ' @%s' % root
        return (hr == 0), detail
    except Exception as e:
        return False, str(e)


def recycle_bin_residual(drive=None):
    """逐 SID 統計「本碟」回收站殘留（他人 SID 只回報、不清除）。"""
    base = os.path.join(norm_drive(drive) or system_drive(), '$Recycle.Bin')
    out = []
    try:
        for sid in os.scandir(base):
            if not sid.is_dir(follow_symlinks=False):
                continue
            n, sz = 0, 0
            for cur, dirs, files in os.walk(sid.path):
                for fn in files:
                    try:
                        sz += os.stat(os.path.join(cur, fn)).st_size
                        n += 1
                    except OSError:
                        pass
            out.append({'sid': sid.name, 'files': n, 'mb': round(sz / MB, 1)})
    except Exception:
        pass
    return out


# ---------------------------------------------------------------- 單次遍歷掃描
def _is_reparse(entry):
    try:
        return bool(entry.stat(follow_symlinks=False).st_file_attributes & 0x400)
    except Exception:
        return False


def _list_users(drive):
    root = os.path.join(drive, 'Users')
    names = []
    try:
        for e in os.scandir(root):
            if e.is_dir(follow_symlinks=False) and not _is_reparse(e):
                names.append(e.name)
    except Exception:
        pass
    return names


def _junk_specs(drive, user_names):
    """(label, 相對 drive 的路徑)。相對路徑全小寫比對。"""
    s = [
        ('WindowsTemp', r'Windows\Temp'),
        ('WindowsUpdateCache', r'Windows\SoftwareDistribution\Download'),
        ('Prefetch', r'Windows\Prefetch'),
        ('RecycleBin', r'$Recycle.Bin'),
        ('CTmp', r'tmp'),
        ('WER', r'ProgramData\Microsoft\Windows\WER'),
        ('WindowsOld', r'Windows.old'),
        ('NvidiaDownloader', r'ProgramData\NVIDIA Corporation\Downloader'),
        ('ThunderUpdate', r'ProgramData\Thunder Network\XLLiveUD\Download'),
        ('CTemp', r'Temp'),
    ]
    for u in user_names:
        s += [
            ('UserTemp', r'Users\%s\AppData\Local\Temp' % u),
            ('ChromeCache', r'Users\%s\AppData\Local\Google\Chrome\User Data\Default\Cache' % u),
            ('EdgeCache', r'Users\%s\AppData\Local\Microsoft\Edge\User Data\Default\Cache' % u),
            ('INetCache', r'Users\%s\AppData\Local\Microsoft\Windows\INetCache' % u),
            ('ThumbnailCache', r'Users\%s\AppData\Local\Microsoft\Windows\Explorer' % u),
            ('CrashDumps', r'Users\%s\AppData\Local\CrashDumps' % u),
        ]
    return [(lab, rel.lower()) for lab, rel in s]


def do_scan(cfg, budget_sec=None, verbose=False):
    """一次遍歷聚合六個維度；跳過 reparse point，避免 junction 自引用重複計算。"""
    drive = cfg['drive']
    sc = cfg['scan']
    budget = budget_sec or sc.get('budget_sec', 600)
    started = time.time()
    users = _list_users(drive)
    junk_map = {}
    for lab, rel in _junk_specs(drive, users):
        junk_map[rel] = lab

    agg = {'root': {}, 'user': {}, 'useritem': {}, 'junk': {},
           'appdata': {}, 'temp': {}, 'big': []}
    paths = {'junk': {}, 'appdata': {}, 'temp': {}}
    denied = set()
    files_seen, dirs_seen, truncated = 0, 0, False
    big_heap = []          # (size, path, mtime) 維持 top N
    big_min = float(sc.get('big_file_mb', 100)) * MB

    # 注意：'C:' 在 Windows 是「該磁碟的目前目錄」，必須用 'C:\' 才是根目錄
    root_path = drive if drive.endswith('\\') else drive + '\\'
    # 廣度優先：時間預算用盡時，六個維度都能保留均勻的覆蓋率；
    # 若用 LIFO 深搜，會整段卡在單一子樹，導致 Users / Windows 完全沒被統計。
    # (路徑, 相對 parts, 繼承的垃圾點 bucket keys)
    queue = deque([(root_path, [], ())])
    while queue:
        cur, parts, inherited_junk = queue.popleft()
        dirs_seen += 1
        if dirs_seen % 500 == 0 and time.time() - started > budget:
            truncated = True
            break
        low = '\\'.join(p.lower() for p in parts)
        # 這個目錄下所有檔案共同歸屬的 bucket keys（每層重算，僅 O(depth)）
        keys = []
        if parts:
            keys.append(('root', parts[0]))
            if parts[0].lower() == 'users' and len(parts) >= 2:
                keys.append(('user', parts[1]))
                if len(parts) >= 3:
                    keys.append(('useritem', parts[1], parts[2]))
                if len(parts) >= 5 and parts[2].lower() == 'appdata' \
                        and parts[3].lower() in ('local', 'roaming'):
                    keys.append(('appdata', parts[1], parts[3], parts[4]))
                if len(parts) >= 6 and parts[2].lower() == 'appdata' \
                        and parts[3].lower() == 'local' and parts[4].lower() == 'temp':
                    keys.append(('temp', parts[1], parts[5]))
        # 垃圾點標籤必須沿堆疊往下傳遞，子目錄內的檔案才會被計入
        junk_keys = inherited_junk
        if low in junk_map:
            jkey = ('junk', low)
            paths['junk'].setdefault(jkey, os.path.join(drive, *parts))
            junk_keys = inherited_junk + (jkey,)
        keys += list(junk_keys)

        try:
            it = os.scandir(cur)
        except OSError:
            if parts:
                denied.add(parts[0].lower())
            continue
        with it:
            for e in it:
                try:
                    if e.is_dir(follow_symlinks=False):
                        if sc.get('skip_reparse', True) and _is_reparse(e):
                            continue
                        queue.append((e.path, parts + [e.name], junk_keys))
                        continue
                    sz = e.stat(follow_symlinks=False).st_size
                except OSError:
                    continue
                files_seen += 1
                for k in keys:
                    agg[k[0]][k] = agg[k[0]].get(k, 0) + sz
                if not parts:
                    # C:\ 根目錄的檔案（pagefile.sys / hiberfil.sys 等）不屬於任何子目錄
                    agg['root'][('root', '__ROOT_FILES__')] = \
                        agg['root'].get(('root', '__ROOT_FILES__'), 0) + sz
                if sz >= big_min:
                    try:
                        mt = datetime.datetime.fromtimestamp(
                            e.stat().st_mtime).strftime('%Y-%m-%d')
                    except OSError:
                        mt = '?'
                    if len(big_heap) < sc.get('top_n', 40):
                        heapq.heappush(big_heap, (sz, e.path, mt))
                    elif sz > big_heap[0][0]:
                        heapq.heapreplace(big_heap, (sz, e.path, mt))

        # 為 appdata / temp bucket 補上真實路徑（目錄本身可能為空）
        for k in keys:
            if k[0] == 'appdata' and k not in paths['appdata'] and len(parts) >= 5:
                paths['appdata'][k] = os.path.join(drive, *parts[:5])
            elif k[0] == 'temp' and k not in paths['temp'] and len(parts) >= 6:
                paths['temp'][k] = os.path.join(drive, *parts[:6])

    disk = disk_info(drive)
    scan = {
        'created': now_str(),
        'drive': drive,
        'elapsed_sec': round(time.time() - started, 1),
        'truncated': truncated,
        'files_seen': files_seen,
        'dirs_seen': dirs_seen,
        'denied_roots': sorted(denied),
        'users_found': users,
        'disk': disk,
        'agg': {g: [{'key': list(k), 'mb': round(v / MB, 1)}
                    for k, v in d.items()] for g, d in agg.items() if g != 'big'},
        'big': [{'mb': round(s / MB, 1), 'path': p, 'mtime': m}
                for s, p, m in sorted(big_heap, reverse=True)],
        'junk_paths': {k[1]: v for k, v in paths['junk'].items()},
        'appdata_paths': {'|'.join(k[1:]): v for k, v in paths['appdata'].items()},
        'temp_paths': {'|'.join(k[1:]): v for k, v in paths['temp'].items()},
    }
    p = scan_path(cfg)
    # 不得以「截斷的快掃」覆蓋既有的完整掃描：截斷結果對所有 bucket 都是低估，
    # 會讓 A 檔清單與空間數字失真。完整掃描存在時直接沿用，並保留本次耗時紀錄。
    if truncated and os.path.exists(p):
        try:
            with open(p, 'r', encoding='utf-8') as f:
                old = json.load(f)
            if not old.get('truncated') and old.get('files_seen', 0) > files_seen:
                log(cfg, 'scan truncated at %d files; kept complete baseline (%d files)'
                    % (files_seen, old['files_seen']))
                old['kept_previous'] = True
                if verbose:
                    emit('scan: kept complete baseline (new was truncated)')
                return old
        except Exception:
            pass
    with open(p + '.tmp', 'w', encoding='utf-8') as f:
        json.dump(scan, f, ensure_ascii=False, indent=1)
    os.replace(p + '.tmp', p)
    if verbose:
        emit('scan: files=%d dirs=%d elapsed=%.1fs truncated=%s -> %s'
             % (files_seen, dirs_seen, scan['elapsed_sec'], truncated, p))
    return scan


def load_scan(cfg):
    """讀本碟的掃描快取。

    找不到 scan_<X>.json 時回退舊版單碟檔 scan.json——但僅限裡面的 drive 與本碟相同，
    否則會把 C 盤的清單當成 D 盤的結果（多碟最危險的錯誤）。
    """
    p = scan_path(cfg)
    if not os.path.exists(p):
        legacy = os.path.join(out_dir(cfg), 'scan.json')
        if os.path.exists(legacy):
            try:
                with open(legacy, 'r', encoding='utf-8') as f:
                    old = json.load(f)
                if norm_drive(old.get('drive')) == norm_drive(cfg['drive']):
                    return old
            except Exception:
                pass
        return None
    try:
        with open(p, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception:
        return None


def scan_is_stale(cfg, scan):
    if not scan:
        return True
    try:
        t = datetime.datetime.strptime(scan['created'], '%Y-%m-%d %H:%M:%S')
        return (datetime.datetime.now() - t).total_seconds() > \
            cfg['scan'].get('max_age_hours', 24) * 3600
    except Exception:
        return True


def scan_all(cfg, drives=None, budget_sec=None, verbose=False):
    """掃描範圍內每一顆碟，回傳 scan 清單。

    一顆碟失敗（拔掉、光碟空槽、權限）不該讓整份報告生不出來，
    所以逐碟 try，失敗就記日誌跳過——報告會少那顆碟，但不會整頁空白。
    """
    out = []
    for d in (drives or scan_scope(cfg)):
        c = cfg_on(cfg, d)
        try:
            out.append(do_scan(c, budget_sec=budget_sec, verbose=verbose))
        except OSError as ex:
            log(cfg, 'scan %s failed: %s' % (d, ex))
            emit('scan %s failed: %s' % (d, ex))
    if out:
        remember_scope(cfg, [s.get('drive') for s in out])
    return out


def load_scans(cfg, drives=None):
    """讀掃描快取；只回傳真的存在且屬於該碟的結果，缺的不補掃。"""
    out = []
    for d in (drives or scan_scope(cfg)):
        s = load_scan(cfg_on(cfg, d))
        if s:
            out.append(s)
    return out


def merge_scans(scans):
    """把多顆碟的 scan 併成一個「合計」摘要，給頁首 KPI 用。"""
    scans = scans or []
    out = {'count': len(scans), 'drives': [norm_drive(s.get('drive')) for s in scans],
           'created': '', 'elapsed_sec': 0.0, 'files_seen': 0, 'dirs_seen': 0,
           'truncated': False, 'total_gb': 0.0, 'free_gb': 0.0, 'used_gb': 0.0,
           'free_pct': 0.0, 'users_found': [], 'tightest': None}
    for s in scans:
        out['elapsed_sec'] += float(s.get('elapsed_sec') or 0)
        out['files_seen'] += int(s.get('files_seen') or 0)
        out['dirs_seen'] += int(s.get('dirs_seen') or 0)
        out['truncated'] = out['truncated'] or bool(s.get('truncated'))
        if (s.get('created') or '') > out['created']:
            out['created'] = s.get('created') or ''
        for u in s.get('users_found') or []:
            if u not in out['users_found']:
                out['users_found'].append(u)
    rows = [r for r in drive_summary_rows(scans)]
    for r in rows:
        if r.get('ok'):
            out['total_gb'] += r['total_gb']
            out['free_gb'] += r['free_gb']
            out['used_gb'] += r['used_gb']
    out['total_gb'] = round(out['total_gb'], 2)
    out['free_gb'] = round(out['free_gb'], 2)
    out['used_gb'] = round(out['used_gb'], 2)
    out['free_pct'] = round(out['free_gb'] / out['total_gb'] * 100, 2) \
        if out['total_gb'] else 0.0
    out['elapsed_sec'] = round(out['elapsed_sec'], 1)
    tight = [r for r in rows if r.get('ok')]
    if tight:
        t = min(tight, key=lambda r: r['free_pct'])
        out['tightest'] = {'letter': t['letter'], 'free_pct': t['free_pct']}
    return out


def drive_summary_rows(scans):
    """把 scan 清單轉成每碟容量列（現讀容量，不用掃描當時的快照）。"""
    rows = []
    for s in scans or []:
        d = norm_drive(s.get('drive'))
        row = {'drive': d, 'letter': drive_key(d)}
        try:
            di = disk_info(d)
            row.update({'ok': True, 'total_gb': di['total_gb'],
                        'free_gb': di['free_gb'], 'used_gb': di['used_gb'],
                        'free_pct': di['free_pct']})
        except OSError:
            row.update({'ok': False, 'error': '無法讀取（碟可能已移除）'})
        row['files_seen'] = s.get('files_seen', 0)
        row['elapsed_sec'] = s.get('elapsed_sec', 0)
        row['truncated'] = bool(s.get('truncated'))
        row['created'] = s.get('created')
        rows.append(row)
    return rows


# ---------------------------------------------------------------- 項目與分級
def build_items(cfg, scan):
    """把 scan.json 轉成網頁／刪除流程共用的 items。"""
    if not scan:
        return []
    dcfg = cfg['delete']
    exclusions = [x.lower() for x in dcfg.get('default_exclusions', [])]
    special = dcfg.get('special_actions', {})
    thumb = [x.lower() for x in special.get('thumbcache_only', [])]
    empty_rb = [x.lower() for x in special.get('empty_recycle_bin', [])]
    locked = [x.lower() for x in dcfg.get('locked_paths', ['$recycle.bin'])]
    drive = scan['drive']
    agg = scan['agg']
    jp = scan.get('junk_paths', {})
    ap = scan.get('appdata_paths', {})
    tp = scan.get('temp_paths', {})
    raw = []

    def push(group, kind, name, mb, path, denied=False):
        if not path or mb is None:
            return
        raw.append({'group': group, 'kind': kind, 'name': name,
                    'path': path, 'mb': round(float(mb), 1), 'denied': denied})

    for r in agg.get('root', []):
        k = r['key']
        push('root', 'root', k[1], r['mb'], os.path.join(drive, k[1]),
             k[1].lower() in scan.get('denied_roots', []))
    for r in agg.get('user', []):
        k = r['key']
        push('users', 'user', k[1], r['mb'], os.path.join(drive, 'Users', k[1]))
    for r in agg.get('useritem', []):
        k = r['key']
        push('useritem', 'useritem', k[2], r['mb'],
             os.path.join(drive, 'Users', k[1], k[2]))
    for r in agg.get('junk', []):
        k = r['key']
        lab = 'B'
        for _lab, rel in _junk_specs(drive, scan.get('users_found', [])):
            if rel == k[1]:
                lab = _lab
                break
        path = jp.get(k[1]) or os.path.join(drive, *k[1].split('\\'))
        push('junk', 'junk', lab, r['mb'], path)
    for r in agg.get('appdata', []):
        k = r['key']            # ('appdata', user, base, child)
        key = '|'.join(k[1:])
        path = ap.get(key) or os.path.join(drive, 'Users', k[1], 'AppData', k[2], k[3])
        push('appdata', 'localapp' if k[2].lower() == 'local' else 'roaming',
             k[3], r['mb'], path)
    for r in agg.get('temp', []):
        k = r['key']            # ('temp', user, child)
        key = '|'.join(k[1:])
        path = tp.get(key) or os.path.join(
            drive, 'Users', k[1], 'AppData', 'Local', 'Temp', k[2])
        push('appdata', 'temp', k[2], r['mb'], path)
    for r in scan.get('big', [])[:cfg['scan'].get('top_n', 40)]:
        push('big', 'big', os.path.basename(r['path']) or r['path'],
             r['mb'], r['path'])

    # 依完整路徑去重（同一路徑可能同時出現在 junk 與 appdata）
    seen, uniq = set(), []
    for x in raw:
        key = x['path'].rstrip('\\').lower()
        if key in seen:
            continue
        seen.add(key)
        uniq.append(x)

    items = []
    for i, x in enumerate(uniq):
        tier, note = classify(x['kind'], x['name'], x['path'])
        low = x['path'].lower()
        is_root_files = x['name'] == '__ROOT_FILES__'
        if is_root_files:
            tier = 'C'
            note = '%s 根目錄的系統檔案（pagefile.sys／hiberfil.sys 等），不可手動刪除，僅供對帳。' % drive
        is_locked = is_root_files or any(lk in low for lk in locked)
        if is_locked and not is_root_files:
            note = '⚠ 不提供勾選：請透過「清空回收站」釋放，不要刪除目錄本身。' + note
        if x['denied']:
            note = '⚠ 讀取權限不足，實際佔用可能高於此數值。' + note
        action = 'direct'
        if any(low.endswith(t) for t in thumb):
            action = 'thumbcache_only'
        if low in empty_rb or any(low.endswith(t) for t in empty_rb):
            action = 'empty_recycle_bin'
        excluded = any(ex in low for ex in exclusions)
        if excluded:
            note = '⚙ 依設定排除（' + dcfg.get('default_exclusions_note', '') + '）：' + note
        items.append({
            'id': 'i%03d' % (i + 1),
            'group': x['group'],
            'kind': x['kind'],
            'name': '(根目錄檔案)' if is_root_files else x['name'],
            'path': (scan['drive'] if is_root_files else x['path']),
            'mb': x['mb'],
            'tier': tier,
            'note': note,
            'denied': x['denied'],
            'locked': is_locked,
            'excluded': excluded,
            'nested_in': None,
            'action': action,
            'selectable': tier != 'C' and not is_locked,
            'default': False,
        })

    # 與後端同一套白名單：勾不到的項目不要顯示成可勾，否則按了才發現刪不掉。
    # 典型例子是資料盤根目錄下的自建目錄（D:\MyData）——掃得到、但不在允許刪除範圍。
    for x in items:
        if x['selectable']:
            okp, why = path_scope_ok(drive, x['path'])
            if not okp:
                x['selectable'] = False
                x['note'] = '🔒 %s：%s' % (why, x['note'])

    # 父子重疊：只在「同為 A 檔且可勾選」的項目之間判定。
    # 若把 C:\Users、C:\Windows 這種總目錄也算進來，所有路徑都會被誤判為子項，
    # 實際可釋放量會被算成 0；若把 B 檔父目錄也算進來，Chrome Cache 等 A 檔會被誤排除。
    cand = [(i, x['path'].rstrip('\\').lower()) for i, x in enumerate(items)
            if x['selectable'] and x['tier'] == 'A']
    for i, x in enumerate(items):
        p = x['path'].rstrip('\\').lower()
        best = None
        for j, pp in cand:
            if i != j and p.startswith(pp + '\\') and \
                    (best is None or len(pp) > len(best[0])):
                best = (pp, items[j]['path'])
        x['nested_in'] = best[1] if best else None
        if x['nested_in']:
            x['note'] = '⚠ 子目錄已包含於父項總量內，統計與刪除時會自動排除。' + x['note']
        x['default'] = (x['tier'] in dcfg.get('default_tiers', ['A'])
                        and x['selectable']
                        and not x['locked'] and not x['excluded']
                        and not x['nested_in'])
    return items


def build_all_items(cfg, scans):
    """多碟合併的項目清單：一份報告、一份勾選集合。

    id 前面加碟代號（C-i001／D-i001），否則兩顆碟的第 3 項會撞在一起，
    勾了 C 盤的項目會連 D 盤那項一起被選中。
    父子重疊（nested_in）與預設勾選都在各碟內部先算好，跨碟不會互相影響。
    """
    out = []
    for sc in scans or []:
        d = norm_drive(sc.get('drive'))
        for x in build_items(cfg_on(cfg, d), sc):
            x['drive'] = d
            x['letter'] = drive_key(d)
            x['id'] = '%s-%s' % (x['letter'], x['id'])
            out.append(x)
    return out


def effective_mb(sel):
    """扣除「父項也在選取集合內」的子項，避免父子重複計算。"""
    paths = [x['path'].rstrip('\\').lower() for x in sel]
    total = 0.0
    for i, x in enumerate(sel):
        if any(i != j and paths[i].startswith(paths[j] + '\\')
               for j in range(len(paths))):
            continue
        total += x['mb']
    return round(total, 1)


def _write_json_atomic(path, obj):
    """先寫 .tmp 再 os.replace，避免中斷時留下半截 JSON。

    manifest 是事後追查「那次到底刪了什麼」的唯一線索，寧可多寫一次也不能寫壞。
    """
    tmp = path + '.tmp'
    with open(tmp, 'w', encoding='utf-8') as f:
        json.dump(obj, f, ensure_ascii=False, indent=2)
        f.flush()
        try:
            os.fsync(f.fileno())
        except OSError:
            pass
    os.replace(tmp, path)


# ------------------------------------------------------- 進度／結果回寫
# 刪除可能跑幾分鐘（337 項、20+ GB）。這段時間網頁與桌寵都必須看得到進度，
# 結束後也要留下「上次清了多少」給桌寵提示、給網頁顯示。
def progress_path(cfg):
    return os.path.join(out_dir(cfg),
                        'delete_progress_%s.json' % drive_key(cfg['drive']))


def last_delete_path(cfg):
    return os.path.join(out_dir(cfg),
                        'last_delete_%s.json' % drive_key(cfg['drive']))


def global_progress_path(cfg):
    """跨碟清理的合計進度：一份，內容帶「目前在哪顆碟」。"""
    return os.path.join(out_dir(cfg), 'delete_progress.json')


def global_last_delete_path(cfg):
    """跨碟清理的合計結果：一份，內含每顆碟的細項。"""
    return os.path.join(out_dir(cfg), 'last_delete.json')


def read_json_quiet(path):
    try:
        with open(path, encoding='utf-8') as f:
            return json.load(f)
    except Exception:
        return None


def _newest(a, b):
    """兩個紀錄取較新的（依 ts）。清理可能只更新了其中一份，不能只看固定順序。"""
    if not a:
        return b
    if not b:
        return a
    try:
        return a if float(a.get('ts') or 0) >= float(b.get('ts') or 0) else b
    except (TypeError, ValueError, AttributeError):
        return a


def read_progress(cfg):
    """優先回傳較新的那份：跨碟合計（delete_progress.json）或單碟進度。"""
    return _newest(read_json_quiet(global_progress_path(cfg)),
                   read_json_quiet(progress_path(cfg)))


def read_last_delete(cfg):
    return _newest(read_json_quiet(global_last_delete_path(cfg)),
                   read_json_quiet(last_delete_path(cfg)))


def progress_running(cfg, max_age_sec=20):
    """進度檔是否代表「正在刪除」。超過 max_age_sec 沒更新就視為已中止。"""
    p = read_progress(cfg)
    if not p or p.get('status') != 'RUNNING':
        return None
    if time.time() - float(p.get('ts') or 0) > max_age_sec:
        return None
    return p


def _record_last_delete(cfg, result):
    """把這顆碟的執行摘要寫成 last_delete_<X>.json（seq 遞增）。"""
    prev = read_json_quiet(last_delete_path(cfg)) or {}
    try:
        seq = int(prev.get('seq') or 0) + 1
    except (TypeError, ValueError):
        seq = 1
    d = disk_info(cfg['drive'])
    summary = {
        'seq': seq,
        'ts': time.time(),
        'created': result.get('created'),
        'status': result.get('status'),
        'target_count': result.get('target_count'),
        'fully_removed': result.get('fully_removed'),
        'partial': result.get('partial'),
        'effective_mb': result.get('effective_mb'),
        'observed_gain_mb': result.get('observed_gain_mb'),
        'free_after_mb': result.get('free_after_mb'),
        'free_pct': d['free_pct'],
        'manifest': result.get('manifest'),
        'log_path': result.get('log_path'),
    }
    try:
        _write_json_atomic(last_delete_path(cfg), summary)
    except Exception:
        pass
    return summary


# ---------------------------------------------------------------- 網頁
def render_page(cfg, scans, items, api=False, token=''):
    """一份報告，包含掃描範圍內所有磁碟的項目。"""
    tpl_path = os.path.join(SCRIPTS, 'page.html')
    with open(tpl_path, 'r', encoding='utf-8') as f:
        tpl = f.read()
    inv = drive_inventory(cfg, scans)
    totals = merge_scans(scans)
    meta = {
        'drive': cfg['drive'],
        'drives': [r for r in inv if r['scanned']],
        'available': inv,
        'totals': totals,
        'created': totals['created'] or '—',
        'elapsed_sec': totals['elapsed_sec'],
        'truncated': totals['truncated'],
        'files_seen': totals['files_seen'],
        'users_found': totals['users_found'],
        'threshold_pct': cfg['alert']['threshold_pct'],
        'exclusions': cfg['delete'].get('default_exclusions', []),
        'default_tiers': cfg['delete'].get('default_tiers', ['A']),
        'monitor': monitor_drives(cfg),
        'last_delete': read_last_delete(cfg),
        'progress': read_progress(cfg),
    }

    def j(o):
        return json.dumps(o, ensure_ascii=False).replace('<', '\\u003c')

    scope_text = '、'.join(r['letter'] + ':' for r in meta['drives']) or '—'
    for k, v in (('__DATA__', j(items)), ('__DISK__', j(totals)),
                 ('__META__', j(meta)), ('__NOW__', now_str()),
                 ('__API__', 'true' if api else 'false'),
                 ('__TOKEN__', token),
                 ('__DRIVE__', j(cfg['drive'])),
                 ('__DRIVES__', j(meta['drives'])),
                 ('__SCOPE_TEXT__', scope_text.replace('&', '&amp;')
                  .replace('<', '&lt;').replace('>', '&gt;'))):
        tpl = tpl.replace(k, v)
    return tpl


def do_report(cfg, scans=None):
    """產生「一份」綜合報告。scans 省略時沿用既有快取，完全沒有才掃描。"""
    scans = scans if scans is not None else (load_scans(cfg) or scan_all(cfg))
    items = build_all_items(cfg, scans)
    html = render_page(cfg, scans, items, api=False)
    p = page_path(cfg)
    with open(p, 'w', encoding='utf-8') as f:
        f.write(html)
    emit('report: %d items from %s -> %s'
         % (len(items), '、'.join(drive_key(s.get('drive')) for s in scans), p))
    return p


# ---------------------------------------------------------------- 刪除流程
def rmtree_safe(path):
    removed, errors = 0, 0
    if not os.path.isdir(path):
        try:
            os.unlink(path)
            return 1, 0
        except OSError:
            return 0, 1
    for cur, dirs, files in os.walk(path, topdown=False):
        # 不碰 junction / reparse point，避免誤刪連結指向的目錄
        safe = []
        for d in dirs:
            try:
                if os.lstat(os.path.join(cur, d)).st_file_attributes & 0x400:
                    continue
            except OSError:
                continue
            safe.append(d)
        dirs[:] = safe
        for fn in files:
            try:
                os.unlink(os.path.join(cur, fn))
                removed += 1
            except OSError:
                errors += 1
        for d in dirs:
            try:
                os.rmdir(os.path.join(cur, d))
            except OSError:
                errors += 1
    try:
        os.rmdir(path)
    except OSError:
        pass
    return removed, errors


def backup_small(cfg, targets, stamp):
    """把 <limit 的小目錄打包備份。備份一定寫在「程式資料碟」（通常是 C）。

    多碟時這是個陷阱：清 D 盤卻把 ZIP 寫進 C 盤，本來只剩 2% 的 C 可能因此爆掉。
    所以先算需要的空間，不夠就跳過實體備份並如實回報——寧可少一層保險，
    也不要為了備份把系統碟推過門檻。
    """
    limit = cfg['delete'].get('small_backup_mb', 100)
    small = [t for t in targets if t['mb'] < limit and os.path.isdir(t['path'])
             and t['action'] == 'direct']
    if not small:
        return {'path': None, 'roots': 0, 'files': 0, 'bytes': 0, 'skipped': 0}
    need = sum(t['mb'] for t in small) * MB
    host = os.path.splitdrive(out_dir(cfg))[0] + '\\'
    try:
        du = disk_info(host)
        if du['free_bytes'] < need * 2 + 200 * MB:
            return {'path': None, 'roots': len(small), 'files': 0, 'bytes': 0,
                    'skipped': 0,
                    'skipped_reason': '備份碟 %s 僅剩 %.2f GB，不足以安全備份 %.1f MB，'
                                      '已跳過實體備份（本次刪除不可還原）'
                                      % (host, du['free_gb'], need / MB)}
    except OSError:
        pass
    bdir = os.path.join(out_dir(cfg), 'backups')
    try:
        os.makedirs(bdir, exist_ok=True)
    except OSError:
        bdir = out_dir(cfg)
    zp = os.path.join(bdir, 'backup_%s_%s.zip'
                      % (drive_key(cfg['drive']), stamp))
    n, skipped, total = 0, 0, 0
    with zipfile.ZipFile(zp, 'w', zipfile.ZIP_DEFLATED, compresslevel=1) as z:
        for t in small:
            for cur, dirs, files in os.walk(t['path']):
                dirs[:] = [d for d in dirs if not (
                    os.lstat(os.path.join(cur, d)).st_file_attributes & 0x400)]
                for fn in files:
                    fp = os.path.join(cur, fn)
                    try:
                        z.write(fp, os.path.relpath(fp, t['path']))
                        n += 1
                        total += os.path.getsize(fp)
                    except OSError:
                        skipped += 1
    return {'path': zp, 'roots': len(small), 'files': n,
            'bytes': total, 'skipped': skipped}


def validate_targets(cfg, paths, items):
    r"""回傳 (targets, rejected)。任何不合法路徑都會被拒絕，不是整批中止而是逐項剔除。

    每條路徑用它「自己那顆碟」的規則驗證，而不是 cfg['drive']——多碟時
    清單可能同時含 C:\ 與 D:\ 的項目，用主碟去比對會把另一顆碟的路徑全判成越界
    （或更糟：反過來放行）。允許範圍就是「本次掃描清單裡出現過的碟」。
    """
    by = {x['path'].rstrip('\\').lower(): x for x in items}
    allowed = set()
    for x in items:
        d = norm_drive(drive_of(x['path']))
        if d:
            allowed.add(d.lower().rstrip('\\'))
    targets, rejected = [], []
    for p in paths:
        low = p.rstrip('\\').lower()
        drv = norm_drive(drive_of(p))
        # 路徑安全檢查優先，不依賴掃描清單內容（與報告端的可勾狀態同一套規則）
        if not drv or drv.lower().rstrip('\\') not in allowed:
            rejected.append({'path': p, 'reason': '不在本次掃描範圍內（請先分析該磁碟）'})
            continue
        ok_scope, why = path_scope_ok(drv, p)
        if not ok_scope:
            rejected.append({'path': p, 'reason': why})
            continue
        x = by.get(low)
        if not x:
            rejected.append({'path': p, 'reason': '不在最新掃描清單內'})
            continue
        if x['tier'] == 'C' or not x['selectable'] or x['locked']:
            rejected.append({'path': p, 'reason': 'C 檔／鎖定項，禁止刪除'})
            continue
        if x['excluded']:
            rejected.append({'path': p, 'reason': '設定排除項'})
            continue
        d = dict(x)
        d['path'] = x['path']
        targets.append(d)
    # 去除重複
    seen, uniq = set(), []
    for t in targets:
        if t['path'].lower() in seen:
            continue
        seen.add(t['path'].lower())
        uniq.append(t)
    # 同一批內若有父子重疊，只保留父項（避免重複刪除與重複計算）
    norms = [t['path'].rstrip('\\').lower() for t in uniq]
    kept = []
    for i, t in enumerate(uniq):
        if any(i != j and norms[i].startswith(norms[j] + '\\')
               for j in range(len(norms))):
            rejected.append({'path': t['path'], 'reason': '子目錄已包含於同批父項'})
            continue
        kept.append(t)
    return kept, rejected


def _resume_paths(cfg, manifest_path, items):
    """讀中斷的 manifest，挑出「仍存在且仍可刪」的目標。

    已消失的（上次刪成功）直接略過；仍存在但已不可刪（清單過期、變成 C 檔、
    被設定排除）也略過並回報原因，避免續跑把不安全的路徑帶進來。
    回傳 (paths, dropped)，dropped 為 [(path, reason)]。
    """
    with open(manifest_path, encoding='utf-8') as f:
        man = json.load(f)
    by = {x['path'].rstrip('\\').lower(): x for x in items}
    paths, dropped = [], []
    for t in man.get('targets', []):
        p = t.get('path')
        if not p:
            continue
        if not os.path.exists(p):
            dropped.append((p, '已不存在（上次已刪除）'))
            continue
        x = by.get(p.rstrip('\\').lower())
        if not x:
            dropped.append((p, '不在最新掃描清單內，請先 rescan'))
            continue
        if x.get('tier') == 'C' or not x.get('selectable') or x.get('locked'):
            dropped.append((p, '目前不可刪（C 檔／鎖定）'))
            continue
        if x.get('excluded'):
            dropped.append((p, '目前不可刪（設定排除）'))
            continue
        paths.append(p)
    return paths, dropped


def do_delete(cfg, paths, dry_run=False, scan=None, progress=None):
    """依 2026-11-23 的流程：manifest → 小項備份 → 分批直接刪除 → 逐項複核 → 紀錄。

    progress：可選回呼 `fn(payload)`，每次進度更新時被呼叫（網頁用來推 SSE／輪詢）。
    進度同時以原子寫入 `delete_progress.json`，桌寵與其他行程都能讀到。
    """
    scan = scan or load_scan(cfg) or do_scan(cfg)
    items = build_items(cfg, scan)
    targets, rejected = validate_targets(cfg, paths, items)
    stamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
    free_before = disk_info(cfg['drive'])['free_bytes']
    result = {
        'created': now_str(),
        'started_at': now_str(),
        # 執行中先標 RUNNING；只有在整段跑完且逐項複核後才會改成
        # EXECUTED／PARTIAL／ABORTED。原本一開頭就寫 EXECUTED，一旦行程被
        # 中斷（逾時、被安全鉤子打斷、斷電），紀錄會說謊（2026-11-25 實測）。
        'status': 'DRY_RUN' if dry_run else 'RUNNING',
        'requested': len(paths),
        'target_count': len(targets),
        'target_mb': round(sum(t['mb'] for t in targets), 1),
        'effective_mb': effective_mb(targets),
        'rejected': rejected,
        'free_before_mb': round(free_before / MB, 1),
        'dry_run': dry_run,
    }
    if dry_run:
        result['targets'] = [{'path': t['path'], 'mb': t['mb'],
                              'action': t['action'], 'tier': t['tier']}
                             for t in targets]
        return result

    # 0) 進度上報：網頁輪詢 delete_progress.json，桌寵也讀同一份
    prog = {
        'status': 'RUNNING', 'phase': 'prepare', 'stamp': stamp,
        'done': 0, 'total': len(targets), 'removed': 0, 'remaining': 0,
        'current': '', 'target_mb': result['target_mb'],
        'effective_mb': result['effective_mb'],
        'started_at': result['started_at'], 'ts': time.time(),
        'pid': os.getpid(), 'free_pct': disk_info(cfg['drive'])['free_pct'],
    }
    last_pub = [0.0]

    def pub(force=False, **kw):
        prog.update(kw)
        prog['ts'] = time.time()
        if not force and prog['ts'] - last_pub[0] < 0.5:
            return                      # 逐項更新只在記憶體，落盤最多 2 次/秒
        last_pub[0] = prog['ts']
        try:
            _write_json_atomic(progress_path(cfg), prog)
        except Exception:
            pass
        if progress:
            try:
                progress(dict(prog))
            except Exception:
                pass

    pub(force=True)

    # 1) manifest
    manifest = dict(result)
    manifest['method'] = 'Python stdlib direct delete + SHEmptyRecycleBinW'
    manifest['backup_policy'] = ('<100 MB 項目做 ZIP 實體備份；其餘為可自動重建之快取，'
                                '以完整 manifest 取代位元備份。')
    manifest['targets'] = [{'path': t['path'], 'mb': t['mb'], 'action': t['action'],
                            'tier': t['tier'], 'nested_in': t['nested_in']}
                           for t in targets]
    manifest['progress'] = {'done': 0, 'total': len(targets),
                            'removed': 0, 'remaining': 0, 'updated_at': now_str()}
    manifest['outcomes'] = []
    mp = os.path.join(out_dir(cfg), 'execution_manifest_%s_%s.json'
                      % (drive_key(cfg['drive']), stamp))
    _write_json_atomic(mp, manifest)
    result['manifest'] = mp

    def checkpoint():
        """每批後落盤一次，中斷（逾時／被安全鉤子打斷／斷電）也追得回進度。"""
        manifest['progress'] = {
            'done': len(outcomes), 'total': len(targets),
            'removed': sum(1 for o in outcomes if not o['after']),
            'remaining': sum(1 for o in outcomes if o['after']),
            'updated_at': now_str()}
        manifest['outcomes'] = outcomes
        try:
            _write_json_atomic(mp, manifest)
        except Exception:
            pass                       # 落盤失敗不可拖垮刪除流程


    # 2) 小項備份
    try:
        result['backup'] = backup_small(cfg, targets, stamp)
    except Exception as e:
        result['backup'] = {'error': str(e)}

    # 3) 分批刪除
    bsize = max(1, cfg['delete'].get('batch_size', 10))
    outcomes = []
    aborted = None
    try:
        for bi in range(0, len(targets), bsize):
            batch = targets[bi:bi + bsize]
            for t in batch:
                p = t['path']
                act = t['action']
                rec = {'path': p, 'action': act, 'before': os.path.exists(p)}
                try:
                    if act == 'thumbcache_only':
                        n = 0
                        if os.path.isdir(p):
                            for fn in os.listdir(p):
                                if fn.lower().startswith('thumbcache_') and fn.lower().endswith('.db'):
                                    try:
                                        os.unlink(os.path.join(p, fn))
                                        n += 1
                                    except OSError:
                                        pass
                        rec['removed'] = n
                    elif act == 'empty_recycle_bin':
                        ok, detail = empty_recycle_bin(cfg['drive'])
                        rec['removed'] = 0
                        rec['detail'] = detail
                    else:
                        rm, er = rmtree_safe(p)
                        rec['removed'] = rm
                        rec['errors'] = er
                except Exception as e:
                    rec['error'] = str(e)
                rec['after'] = os.path.exists(p)
                if rec['after'] and os.path.isdir(p):
                    try:
                        rec['remaining'] = len(os.listdir(p))
                    except OSError:
                        rec['remaining'] = -1
                else:
                    rec['remaining'] = 0
                outcomes.append(rec)
                pub(phase='deleting', done=len(outcomes), current=p,
                    removed=sum(1 for o in outcomes if not o['after']),
                    remaining=sum(1 for o in outcomes if o['after']))
            # 每批後複核；若有非預期例外則記錄但不中斷（逐項容錯）
            log(cfg, 'delete batch %d/%d done' %
                (bi // bsize + 1, math.ceil(len(targets) / bsize)))
            pub(force=True)
            checkpoint()
    except BaseException as e:
        # 逾時、被外部安全鉤子中止、KeyboardInterrupt 等：保留已完成的成績，
        # 標記 ABORTED 並落盤，讓 `delete --resume` 能接手（2026-11-25 實測需求）。
        aborted = '%s: %s' % (type(e).__name__, str(e)[:300])
        log(cfg, 'delete ABORTED after %d/%d targets: %s' %
            (len(outcomes), len(targets), aborted))
    result['outcomes'] = outcomes
    result['fully_removed'] = sum(1 for o in outcomes if not o['after'])
    result['partial'] = sum(1 for o in outcomes if o['after'])
    if aborted:
        result['status'] = 'ABORTED'
        result['aborted_reason'] = aborted
        result['aborted_after'] = len(outcomes)
    elif result['partial']:
        result['status'] = 'PARTIAL'
    else:
        result['status'] = 'EXECUTED'
    result['finished_at'] = now_str()
    manifest['status'] = result['status']
    manifest['finished_at'] = result['finished_at']
    if aborted:
        manifest['aborted_reason'] = aborted
    checkpoint()
    pub(force=True, status=result['status'], phase='done', current='',
        done=len(outcomes), removed=result['fully_removed'],
        remaining=result['partial'],
        aborted_reason=result.get('aborted_reason'))

    # 4) 回收站：預設只回報殘留；啟用設定才清空（避免動到他人 SID 資料）
    if cfg['delete'].get('auto_empty_recycle_bin', False):
        ok, detail = empty_recycle_bin(cfg['drive'])
        result['recycle_bin_cleared'] = {'ok': ok, 'detail': detail}
    else:
        result['recycle_bin_cleared'] = {
            'ok': None,
            'detail': cfg['delete'].get('auto_empty_recycle_bin_note', '未啟用')}
    result['recycle_bin_residual'] = recycle_bin_residual(cfg['drive'])

    # 5) 空間對比（同一資料來源）
    free_after = disk_info(cfg['drive'])['free_bytes']
    result['free_after_mb'] = round(free_after / MB, 1)
    result['observed_gain_mb'] = round((free_after - free_before) / MB, 1)
    result['gain_note'] = ('觀測淨增受其他程式寫入影響，不等於精確歸因；'
                           '帳面目標值請見 effective_mb。')

    # 6) 寫紀錄
    rp = os.path.join(out_dir(cfg), 'execution_result_%s_%s.json'
                      % (drive_key(cfg['drive']), stamp))
    with open(rp, 'w', encoding='utf-8') as f:
        json.dump(result, f, ensure_ascii=False, indent=2)
    lp = os.path.join(out_dir(cfg), 'execution_log_%s.md' % drive_key(cfg['drive']))
    L = ['# cdisk-guard 執行紀錄 · %s · %s' % (drive_key(cfg['drive']), now_str()), '',
         '| 項目 | 數值 |', '|---|---|',
         '| 要求項目 | %d |' % result['requested'],
         '| 實際執行 | %d |' % result['target_count'],
         '| 剔除 | %d |' % len(rejected),
         '| 帳面目標 | %.1f MB |' % result['target_mb'],
         '| 實際可釋放（扣除重疊） | %.1f MB |' % result['effective_mb'],
         '| 完全移除 | %d |' % result['fully_removed'],
         '| 部分殘留 | %d |' % result['partial'],
         '| 刪除前剩餘 | %.1f MB |' % result['free_before_mb'],
         '| 刪除後剩餘 | %.1f MB |' % result['free_after_mb'],
         '| 觀測淨增 | %.1f MB |' % result['observed_gain_mb'], '',
         '> ⚠️ 此操作非常危險，可能導致不可逆的數據丟失！本工具不主動移入回收站，'
         '僅 <100 MB 小項 ZIP 備份可還原。注意：部分環境（非系統碟、裝有第三方'
         '檔案篩選程式）會把刪除導向該碟自己的回收站，實際殘留請見下一節。', '',
         '## 逐項結果', '',
         '| 動作 | 前 | 後 | 殘留 | 路徑 |', '|---|---|---|---|---|']
    for o in outcomes:
        L.append('| %s | %s | %s | %s | `%s` |' %
                 (o['action'], o['before'], o['after'],
                  o.get('remaining', 0), o['path']))
    if rejected:
        L += ['', '## 剔除項', '']
        for r in rejected:
            L.append('- `%s` — %s' % (r['path'], r['reason']))
    L += ['', '## 回收站殘留（依 SID）', '']
    for r in result['recycle_bin_residual']:
        L.append('- `%s`：%d 檔 / %.1f MB' % (r['sid'], r['files'], r['mb']))
    L += ['', '## 檔案', '',
          '- manifest：`%s`' % mp,
          '- 備份：`%s`' % result.get('backup', {}).get('path', '—'),
          '- 結果：`%s`' % rp, '']
    with open(lp, 'w', encoding='utf-8') as f:
        f.write('\n'.join(L))
    result['log_path'] = lp
    log(cfg, 'delete done: targets=%d fully=%d partial=%d gain=%.1f MB' %
        (len(targets), result['fully_removed'], result['partial'],
         result['observed_gain_mb']))
    # 回寫「上次執行」摘要：桌寵據此提示，網頁據此顯示，不用人去翻 execution_log.md
    try:
        result['last_delete'] = _record_last_delete(cfg, result)
    except Exception:
        pass
    return result


# ---------------------------------------------------------------- 多碟刪除
def _merge_status(statuses):
    """整批的狀態：有任何一顆被中斷就是 ABORTED，有殘留就是 PARTIAL。"""
    s = [x for x in statuses if x]
    for bad in ('ABORTED', 'PARTIAL'):
        if bad in s:
            return bad
    return 'EXECUTED' if s else 'DRY_RUN'


def do_delete_multi(cfg, paths, dry_run=False, scans=None, progress=None):
    """把勾選項目按磁碟分組，逐碟跑既有的 do_delete，再合併成一份結果。

    刻意不改 do_delete 的簽名與流程：它是「單碟刪除」這件事的唯一實作，
    多碟只是外層排程。這樣備份、manifest、回收站、空間對比全部維持原行為，
    只是每顆碟各一份——跨碟的合計另外寫在 delete_progress.json／last_delete.json。
    """
    scans = scans if scans is not None else load_scans(cfg)
    scan_by = {}
    for s in scans or []:
        scan_by[norm_drive(s.get('drive'))] = s
    order, groups, rejected = [], {}, []
    for p in paths:
        d = norm_drive(drive_of(p))
        if not d or d not in scan_by:
            rejected.append({'path': p,
                             'reason': '不在本次掃描範圍內（請先分析該磁碟）'})
            continue
        if d not in groups:
            groups[d] = []
            order.append(d)
        groups[d].append(p)

    if not groups:
        return {'created': now_str(), 'status': 'DRY_RUN' if dry_run else 'EXECUTED',
                'requested': len(paths), 'target_count': 0, 'target_mb': 0,
                'effective_mb': 0, 'rejected': rejected, 'per_drive': [],
                'dry_run': dry_run}

    # 先逐碟驗證一次：算出整批總數，進度條才不會每換一顆碟就從 0 重來
    pre = []
    grand_total = 0
    for d in order:
        c = cfg_on(cfg, d)
        items = build_items(c, scan_by[d])
        targets, rej = validate_targets(c, groups[d], items)
        rejected.extend(rej)
        pre.append((d, c, targets))
        grand_total += len(targets)

    if dry_run:
        merged = {'created': now_str(), 'status': 'DRY_RUN',
                  'requested': len(paths), 'target_count': 0, 'target_mb': 0.0,
                  'effective_mb': 0.0, 'rejected': list(rejected),
                  'per_drive': [], 'dry_run': True}
        for d, c, targets in pre:
            if not targets:
                continue
            r = do_delete(c, [t['path'] for t in targets],
                          dry_run=True, scan=scan_by[d])
            merged['target_count'] += r['target_count']
            merged['target_mb'] += r['target_mb']
            merged['effective_mb'] += r['effective_mb']
            merged['rejected'].extend(r.get('rejected') or [])
            merged['per_drive'].append({
                'drive': d, 'letter': drive_key(d), 'status': r['status'],
                'target_count': r['target_count'], 'target_mb': r['target_mb'],
                'effective_mb': r['effective_mb']})
        merged['target_mb'] = round(merged['target_mb'], 1)
        merged['effective_mb'] = round(merged['effective_mb'], 1)
        return merged

    stamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
    prog = {'status': 'RUNNING', 'phase': 'prepare', 'stamp': stamp,
            'done': 0, 'total': grand_total, 'removed': 0, 'remaining': 0,
            'current': '', 'drive': order[0], 'drive_index': 1,
            'drive_count': len(order), 'scope': [drive_key(x) for x in order],
            'started_at': now_str(), 'ts': time.time(), 'pid': os.getpid(),
            'target_mb': round(sum(t['mb'] for _d, _c, ts in pre for t in ts), 1)}
    try:
        _write_json_atomic(global_progress_path(cfg), prog)
    except Exception:
        pass

    base = [0, 0, 0]            # done / removed / remaining 的跨碟累計
    per, statuses = [], []
    for idx, (d, c, targets) in enumerate(pre):
        letter = drive_key(d)
        if not targets:
            per.append({'drive': d, 'letter': letter, 'status': 'SKIPPED',
                        'target_count': 0, 'reason': '驗證後沒有可刪項目'})
            continue

        def cb(p, _d=d, _letter=letter, _idx=idx):
            g = dict(p)
            g['drive'] = _d
            g['drive_index'] = _idx + 1
            g['drive_count'] = len(order)
            g['scope'] = [drive_key(x) for x in order]
            g['total'] = grand_total
            g['done'] = min(grand_total, base[0] + int(p.get('done') or 0))
            g['removed'] = base[1] + int(p.get('removed') or 0)
            g['remaining'] = base[2] + int(p.get('remaining') or 0)
            g['ts'] = time.time()
            try:
                _write_json_atomic(global_progress_path(cfg), g)
            except Exception:
                pass
            if progress:
                try:
                    progress(g)
                except Exception:
                    pass

        res = do_delete(c, [t['path'] for t in targets],
                        dry_run=False, scan=scan_by[d], progress=cb)
        base[0] += int(res.get('target_count') or 0)
        base[1] += int(res.get('fully_removed') or 0)
        base[2] += int(res.get('partial') or 0)
        statuses.append(res.get('status'))
        per.append({'drive': d, 'letter': letter, 'status': res.get('status'),
                    'target_count': res.get('target_count'),
                    'target_mb': res.get('target_mb'),
                    'effective_mb': res.get('effective_mb'),
                    'fully_removed': res.get('fully_removed'),
                    'partial': res.get('partial'),
                    'observed_gain_mb': res.get('observed_gain_mb'),
                    'free_before_mb': res.get('free_before_mb'),
                    'free_after_mb': res.get('free_after_mb'),
                    'manifest': res.get('manifest'),
                    'backup': res.get('backup'),
                    'log_path': res.get('log_path'),
                    'recycle_bin_residual': res.get('recycle_bin_residual'),
                    'recycle_bin_cleared': res.get('recycle_bin_cleared')})

    def num(k):
        return round(sum(float(p.get(k) or 0) for p in per), 1)

    merged = {
        'created': now_str(),
        'started_at': prog['started_at'],
        'finished_at': now_str(),
        'status': _merge_status(statuses),
        'requested': len(paths),
        'target_count': int(sum(p.get('target_count') or 0 for p in per)),
        'target_mb': num('target_mb'),
        'effective_mb': num('effective_mb'),
        'fully_removed': int(sum(p.get('fully_removed') or 0 for p in per)),
        'partial': int(sum(p.get('partial') or 0 for p in per)),
        'free_before_mb': num('free_before_mb'),
        'free_after_mb': num('free_after_mb'),
        'observed_gain_mb': num('observed_gain_mb'),
        'gain_note': ('觀測淨增是各碟合計，受其他程式寫入影響，不等於精確歸因；'
                      '帳面目標值請見 effective_mb。'),
        'rejected': rejected,
        'per_drive': per,
        'manifests': [p['manifest'] for p in per if p.get('manifest')],
        'logs': [p['log_path'] for p in per if p.get('log_path')],
        'backups': [p['backup'].get('path') for p in per
                    if isinstance(p.get('backup'), dict) and p['backup'].get('path')],
        'dry_run': False,
    }
    merged['manifest'] = merged['manifests'][0] if merged['manifests'] else ''
    merged['log_path'] = os.path.join(out_dir(cfg), 'execution_log.md')

    # 合計執行紀錄（各碟自己的 execution_log_<X>.md 仍保留逐項結果）
    L = ['# cdisk-guard 執行紀錄（合計）· %s' % now_str(), '',
         '| 磁碟 | 狀態 | 執行 | 完全移除 | 殘留 | 帳面 | 實際可釋放 | 觀測淨增 |',
         '|---|---|---|---|---|---|---|---|']
    for p in per:
        L.append('| %s: | %s | %s | %s | %s | %.1f MB | %.1f MB | %.1f MB |' % (
            p['letter'], p.get('status'), p.get('target_count') or 0,
            p.get('fully_removed') or 0, p.get('partial') or 0,
            float(p.get('target_mb') or 0), float(p.get('effective_mb') or 0),
            float(p.get('observed_gain_mb') or 0)))
    L += ['| **合計** | %s | %d | %d | %d | %.1f MB | %.1f MB | %.1f MB |' % (
        merged['status'], merged['target_count'], merged['fully_removed'],
        merged['partial'], merged['target_mb'], merged['effective_mb'],
        merged['observed_gain_mb']), '',
        '> ⚠️ 此操作非常危險，可能導致不可逆的數據丟失！本工具不主動移入回收站，'
        '僅 <100 MB 小項 ZIP 備份可還原。部分環境會把刪除導向該碟自己的回收站。',
        '', '## 逐碟紀錄', '']
    for p in per:
        L.append('- `%s:` 明細：`%s`' % (p['letter'], p.get('log_path') or '—'))
        L.append('  manifest：`%s`' % (p.get('manifest') or '—'))
    if rejected:
        L += ['', '## 剔除項', '']
        for r in rejected:
            L.append('- `%s` — %s' % (r['path'], r['reason']))
    try:
        with open(merged['log_path'], 'w', encoding='utf-8') as f:
            f.write('\n'.join(L))
    except Exception:
        pass

    prog.update({'status': 'DONE', 'phase': 'done', 'done': grand_total,
                 'removed': merged['fully_removed'],
                 'remaining': merged['partial'], 'current': '', 'ts': time.time()})
    try:
        _write_json_atomic(global_progress_path(cfg), prog)
    except Exception:
        pass

    # 合計 last_delete（桌寵／網頁讀這一份；逐碟的 last_delete_<X>.json 仍在）
    gprev = read_json_quiet(global_last_delete_path(cfg)) or {}
    try:
        gseq = int(gprev.get('seq') or 0) + 1
    except (TypeError, ValueError):
        gseq = 1
    try:
        pct = min(float(p.get('free_pct') or 100)
                  for p in (drive_summary_rows(scans) or [{'free_pct': 100}]))
    except Exception:
        pct = 100.0
    merged.update({'seq': gseq, 'ts': time.time(), 'free_pct': pct})
    try:
        _write_json_atomic(global_last_delete_path(cfg), merged)
    except Exception:
        pass
    log(cfg, 'delete done (multi): drives=%s targets=%d fully=%d partial=%d gain=%.1f MB'
        % (','.join(drive_key(d) for d in order), merged['target_count'],
           merged['fully_removed'], merged['partial'], merged['observed_gain_mb']))
    return merged


# ---------------------------------------------------------------- 本機後端
EDGE = r'C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe'
CHROME = r'C:\Program Files\Google\Chrome\Application\chrome.exe'
_ACTIVE_SERVER = None


class GuardServer:
    def __init__(self, cfg, open_browser=True, drives=None):
        self.cfg = cfg
        self.token = secrets.token_urlsafe(18)
        self._lock = threading.Lock()
        self._scan_lock = threading.Lock()
        # 開頁要顯示「上次實際分析的範圍」，否則改了設定或只掃過一顆碟時，
        # 頁面會摻進一顆根本沒分析過的碟（顯示成 0 項），看起來像漏掃。
        self.scope = [norm_drive(d)
                      for d in (drives or last_scope(cfg) or scan_scope(cfg))]
        self.scans = []
        self.items = []
        self._load_scope(self.scope)
        self.browser = None
        self.open_browser = open_browser
        self._stop = threading.Event()

        outer = self

        def scan_these(drives):
            """掃描指定磁碟並換掉目前報告；掃描要幾分鐘，先擋住重複請求。"""
            if not outer._scan_lock.acquire(blocking=False):
                return None
            try:
                scans = scan_all(outer.cfg, drives, budget_sec=None, verbose=True)
                if not scans:
                    return []
                outer._load_scope([s['drive'] for s in scans])
                return scans
            finally:
                outer._scan_lock.release()

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def _send(self, code, body, ctype):
                self.send_response(code)
                self.send_header('Content-Type', ctype)
                self.send_header('Content-Length', str(len(body)))
                self.send_header('Cache-Control', 'no-store')
                self.end_headers()
                self.wfile.write(body)

            def _json(self, obj, code=200):
                self._send(code, json.dumps(obj, ensure_ascii=False).encode('utf-8'),
                           'application/json; charset=utf-8')

            def do_GET(self):
                path = self.path.split('?')[0]
                if path in ('/', '/index.html'):
                    html = render_page(outer.cfg, outer.scans, outer.items,
                                       api=True, token=outer.token)
                    self._send(200, html.encode('utf-8'), 'text/html; charset=utf-8')
                elif path == '/api/state':
                    self._json({'drives': drive_summary_rows(outer.scans),
                                'available': drive_inventory(outer.cfg, outer.scans),
                                'scope': outer.scope,
                                'totals': merge_scans(outer.scans),
                                'progress': read_progress(outer.cfg),
                                'last_delete': read_last_delete(outer.cfg),
                                'token': outer.token})
                elif path == '/api/progress':
                    # 網頁在刪除期間每 0.7 s 輪詢；running=False 代表已結束／已中止
                    self._json({'ok': True,
                                'running': bool(progress_running(outer.cfg)),
                                'progress': read_progress(outer.cfg),
                                'drives': drive_summary_rows(outer.scans),
                                'last_delete': read_last_delete(outer.cfg)})
                elif path == '/favicon.ico':
                    self._send(204, b'', 'image/x-icon')
                else:
                    self._json({'error': 'not found'}, 404)

            def do_POST(self):
                path = self.path.split('?')[0]
                try:
                    n = int(self.headers.get('Content-Length', '0'))
                    body = json.loads(self.rfile.read(n) or b'{}')
                except Exception:
                    return self._json({'error': 'bad request'}, 400)
                if body.get('token') != outer.token:
                    return self._json({'error': 'invalid token'}, 403)
                if path == '/api/close':
                    t = threading.Thread(target=outer.close, daemon=True)
                    t.start()
                    return self._json({'ok': True, 'message': '網頁已關閉'})
                if path in ('/api/scan', '/api/rescan'):
                    want = body.get('drives')
                    if not isinstance(want, list) or not want:
                        want = all_drives() or [system_drive()]
                    valid = set(all_drives())
                    picks = []
                    for d in want:
                        n = norm_drive(d)
                        if n and n in valid and n not in picks:
                            picks.append(n)
                    if not picks:
                        return self._json({'error': '沒有可讀取的磁碟'}, 400)
                    res = scan_these(picks)
                    if res is None:
                        return self._json({'error': '已有分析在進行中，請稍候'}, 409)
                    return self._json({'ok': True,
                                       'scope': outer.scope,
                                       'drives': [drive_key(s['drive']) for s in res],
                                       'created': merge_scans(res)['created'],
                                       'items': len(outer.items),
                                       'totals': merge_scans(res)})
                if path == '/api/delete':
                    if not body.get('confirm'):
                        return self._json({'error': 'need explicit confirm'}, 400)
                    paths = body.get('paths', [])
                    if not isinstance(paths, list) or not paths:
                        return self._json({'error': 'empty selection'}, 400)
                    dry = bool(body.get('dry_run'))
                    res = do_delete_multi(outer.cfg, paths, dry_run=dry,
                                          scans=outer.scans)
                    return self._json(res)
                return self._json({'error': 'not found'}, 404)

        host = cfg['server'].get('host', '127.0.0.1')
        port = cfg['server'].get('port', 0)
        self.httpd = ThreadingHTTPServer((host, port), H)
        self.httpd.daemon_threads = True
        self.port = self.httpd.server_address[1]
        self.url = 'http://%s:%d/' % (host, self.port)

    def _load_scope(self, drives):
        """載入指定範圍的掃描快取。

        刻意不在這裡自動掃描：全機掃描要幾分鐘，開個網頁不該卡住。
        沒有快取時頁面會直接跳出「選擇磁碟」清單，由使用者按開始。
        """
        want = [norm_drive(d) for d in drives if norm_drive(d)]
        scans = load_scans(self.cfg, want)
        with self._lock:
            self.scans = scans
            self.items = build_all_items(self.cfg, scans)
            self.scope = [norm_drive(s['drive']) for s in scans] or want

    def start(self):
        t = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        t.start()
        if self.open_browser:
            self._launch_browser()
        emit('serve: %s (127.0.0.1 only)' % self.url)
        return self.url

    def _launch_browser(self):
        exe = EDGE if os.path.exists(EDGE) else (CHROME if os.path.exists(CHROME) else None)
        if not exe or not self.cfg['server'].get('app_browser', True):
            import webbrowser
            webbrowser.open(self.url)
            return
        profile = os.path.join(tempfile.gettempdir(), 'cdisk-guard-browser-profile')
        args = [exe, '--app=' + self.url, '--user-data-dir=' + profile,
                '--no-first-run', '--no-default-browser-check',
                '--window-size=1440,960']
        try:
            self.browser = subprocess.Popen(
                args, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
        except Exception:
            import webbrowser
            webbrowser.open(self.url)

    def _kill_browser(self):
        p = self.browser
        if not p:
            return
        try:
            subprocess.run(['taskkill', '/PID', str(p.pid), '/T', '/F'],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                           creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0),
                           timeout=10)
        except Exception:
            try:
                p.terminate()
            except Exception:
                pass
        self.browser = None

    def close(self):
        global _ACTIVE_SERVER
        self._kill_browser()
        try:
            self.httpd.shutdown()
            self.httpd.server_close()
        except Exception:
            pass
        self._stop.set()
        if _ACTIVE_SERVER is self:
            _ACTIVE_SERVER = None

    def wait(self):
        # serve_forever 已由 start() 的背景執行緒負責；這裡只等待關閉訊號
        self._stop.wait()


# ---------------------------------------------------------------- 通知與警示
def decide_notify(cfg, disk):
    a = cfg['alert']
    if disk['free_pct'] < a['threshold_pct']:
        return 'alert'
    if disk['free_pct'] < a['warn_pct']:
        return 'warn'
    return 'none'


def write_notice(cfg, disk, reason):
    p = os.path.join(out_dir(cfg), 'notice.md')
    with open(p, 'w', encoding='utf-8') as f:
        f.write('# cdisk-guard 通知 · %s\n\n' % now_str())
        f.write('- 觸發原因：%s\n' % reason)
        f.write('- 剩餘：%.2f GB / %.2f GB（%.2f%%）\n' %
                (disk['free_gb'], disk['total_gb'], disk['free_pct']))
        f.write('- 門檻：%.1f%%\n' % cfg['alert']['threshold_pct'])
        f.write('- 最新分析網頁：`%s`\n' % page_path(cfg))
    return p


def do_alert(cfg, disk, extra_line='', auto_close_sec=None,
             auto_click=None, no_action=False, force=False):
    """顯示 A/B 警示框並據以行動。回傳 dict。"""
    global _ACTIVE_SERVER
    st = read_state(cfg)
    sd = state_for(st, cfg['drive'])
    now = time.time()
    if not force and now - sd.get('last_alert_ts', 0) < cfg['alert'].get('cooldown_sec', 21600):
        log(cfg, 'alert suppressed by cooldown (pct=%.2f)' % disk['free_pct'])
        return {'choice': 'SKIPPED_COOLDOWN'}
    choice = show_alert(
        disk['free_gb'], disk['total_gb'], disk['free_pct'],
        title=cfg['alert'].get('title', '磁盤剩餘空間'),
        extra_line=extra_line, auto_close_sec=auto_close_sec,
        auto_click=auto_click)
    sd['last_alert_ts'] = now
    sd['last_alert_pct'] = disk['free_pct']
    sd['last_alert_choice'] = choice
    write_state(cfg, st)
    log(cfg, 'alert pct=%.2f choice=%s' % (disk['free_pct'], choice))
    if no_action or choice not in ('A', 'B'):
        return {'choice': choice, 'action': 'none'}
    if choice == 'B':
        if _ACTIVE_SERVER:
            _ACTIVE_SERVER.close()
        log(cfg, 'user chose B. 人工處理：不刪檔、關閉網頁')
        return {'choice': 'B', 'action': 'close_page'}
    # A：開網頁（真刪除）。若已有網頁開著就復用，不重複開視窗
    if scan_is_stale(cfg, load_scan(cfg)):
        do_scan(cfg, budget_sec=cfg['scan'].get('serve_budget_sec', 180),
                verbose=True)
    if _ACTIVE_SERVER:
        srv = _ACTIVE_SERVER
    else:
        srv = GuardServer(cfg, open_browser=not no_action)
        srv.start()
        _ACTIVE_SERVER = srv
    st['last_server_url'] = srv.url
    write_state(cfg, st)
    return {'choice': 'A', 'action': 'serve', 'url': srv.url, 'server': srv}


def weekly_should_run(cfg, state, disk, now=None):
    """是否該做一次週期分析。now 可注入，測試不必等到週一。

    多一條「逾期補做」：若上次分析已超過 catch_up_days（預設 7 天）或從未做過，
    就不必再等下一个週一——機器人週一關機、或當天 CPU 忙，本來就會整週漏掉。
    """
    w = cfg['weekly']
    now = now or datetime.datetime.now()
    today = now.date().isoformat()
    last = state_for(state, cfg['drive']).get('last_weekly_date')
    if w.get('run_once_per_day', True) and last == today:
        return False, 'already done today'
    on_due_day = now.weekday() == w.get('weekday', 0)
    catch_days = int(w.get('catch_up_days', 7) or 0)
    overdue = False
    if catch_days > 0:
        if not last:
            overdue = True
        else:
            try:
                overdue = (now.date() - datetime.date.fromisoformat(str(last))).days >= catch_days
            except ValueError:
                overdue = True
    if not on_due_day and not overdue:
        return False, 'not monday'
    if not (w.get('earliest_hour', 0) <= now.hour <= w.get('latest_hour', 23)):
        return False, 'outside hour window'
    cpu = cpu_usage(w.get('cpu_sample_sec', 1.0))
    if cpu > w.get('cpu_max_pct', 25):
        return False, 'cpu busy %.1f%%' % cpu
    if overdue and not on_due_day:
        return True, 'catch-up（上次 %s）· cpu idle %.1f%%' % (last or '從未執行', cpu)
    return True, 'cpu idle %.1f%%' % cpu


def run_weekly(cfg, state, disk, reason, state_lock=None):
    # 週期分析是「產生一份完整報告」，所以掃描範圍內的碟都要掃；
    # 監控（警示）只看 monitor_drives，兩者刻意分開。
    scans = scan_all(cfg, verbose=True)
    do_report(cfg, scans)
    summary = merge_scans(scans)
    level = decide_notify(cfg, disk)

    def commit_state():
        # 掃描可能跑很久；以磁碟上的最新狀態為底再合併，避免覆蓋掃描期間
        # 桌寵剛寫入的位置、心跳或使用者設定。呼叫方可提供鎖，讓讀／寫／合併
        # 成為短臨界區，但絕不能拿著鎖做 scan_all／do_report。
        latest = read_state(cfg) or state
        sd = state_for(latest, cfg['drive'])
        sd['last_weekly_date'] = datetime.date.today().isoformat()
        sd['last_weekly_ts'] = time.time()
        sd['last_weekly_status'] = level  # 事後可查「那次分析做了沒、結論是什麼」
        sd['last_weekly_reason'] = reason
        sd['last_scan_ts'] = time.time()
        write_state(cfg, latest)

    if state_lock is None:
        commit_state()
    else:
        with state_lock:
            commit_state()
    log(cfg, 'weekly analysis done: drives=%s files=%d elapsed=%ss pct=%.2f level=%s reason=%s' %
        (','.join(drive_key(d) for d in summary['drives']), summary['files_seen'],
         summary['elapsed_sec'], disk['free_pct'], level, reason))
    if level == 'alert':
        write_notice(cfg, disk, '週一分析後仍低於 2%')
        return 'alert', summary
    if level == 'warn':
        write_notice(cfg, disk, '週一分析後介於 2%~10%')
        if cfg['alert'].get('notify_on_warn_pct', False):
            return 'warn_alert', summary
        return 'warn_logged', summary
    log(cfg, 'weekly analysis: no notification needed')
    return 'none', summary


# ---------------------------------------------------------------- watch
LOCK_OWNER_NAME = 'watch.owner.json'


def lock_owner_path(cfg):
    return os.path.join(out_dir(cfg), LOCK_OWNER_NAME)


def pid_alive(pid):
    """PID 是否還活著。

    注意：Windows 上 **不能用 `os.kill(pid, 0)`** —— Python 對非 CTRL_* 的訊號
    直接呼叫 TerminateProcess，等於把對方殺掉。只能用 OpenProcess + 等 0 秒。
    """
    try:
        k32 = ctypes.WinDLL('kernel32', use_last_error=True)
        h = k32.OpenProcess(0x00100000, False, int(pid))   # SYNCHRONIZE
        if not h:
            return False
        try:
            return k32.WaitForSingleObject(h, 0) == 0x102   # WAIT_TIMEOUT
        finally:
            k32.CloseHandle(h)
    except Exception:
        return False


def proc_start_ts(pid):
    """取得行程建立時間（epoch 秒）；取不到回 0。用來防 PID 被重用時殺錯人。"""
    try:
        k32 = ctypes.WinDLL('kernel32', use_last_error=True)
        h = k32.OpenProcess(0x1000, False, int(pid))       # QUERY_LIMITED_INFORMATION
        if not h:
            return 0.0
        try:
            c, e, k, u = (wintypes.FILETIME() for _ in range(4))
            if not k32.GetProcessTimes(h, ctypes.byref(c), ctypes.byref(e),
                                       ctypes.byref(k), ctypes.byref(u)):
                return 0.0
            ft = (c.dwHighDateTime << 32) | c.dwLowDateTime
            return ft / 1e7 - 11644473600.0
        finally:
            k32.CloseHandle(h)
    except Exception:
        return 0.0


def write_lock_owner(cfg, mode='watch'):
    """把鎖的持有者寫進 watch.owner.json，讓啟動器能講清楚「誰在跑」。"""
    _write_json_atomic(lock_owner_path(cfg), {
        'pid': os.getpid(),
        'mode': mode,
        'exe': sys.executable,
        'started_at': now_str(),
        'started_ts': time.time(),
    })


def read_lock_owner(cfg):
    """讀持有者；行程已死視為沒有（殘留紀錄不該阻止下次啟動）。

    舊版行程（1.0.3 以前）不會寫 owner 檔，因此再退一步用 state.json 反推；
    但只有「確認該 PID 真的擁有桌寵視窗」才採信，避免 PID 被重用時殺錯人。
    """
    d = read_json_quiet(lock_owner_path(cfg))
    if isinstance(d, dict) and d.get('pid') and pid_alive(d['pid']):
        # 有紀錄但鎖沒人握著 = 上一次沒收乾淨的殘留，清掉免得顯示「在執行」
        if lock_is_busy(cfg):
            return d
        clear_lock_owner(cfg)
        return None
    st = read_state(cfg) or {}
    pid = (st.get('pet') or {}).get('pid')
    if pid and pid_alive(pid) and lock_is_busy(cfg) and _pid_owns_pet_window(pid):
        return {'pid': int(pid), 'mode': 'pet', 'source': 'state',
                'started_at': (st.get('pet') or {}).get('last_heartbeat')}
    return None


def _pid_owns_pet_window(pid):
    u = ctypes.WinDLL('user32', use_last_error=True)
    hit = []

    @ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)
    def cb(h, _l):
        p = wintypes.DWORD()
        u.GetWindowThreadProcessId(h, ctypes.byref(p))
        if p.value == int(pid):
            cls = ctypes.create_unicode_buffer(64)
            u.GetClassNameW(h, cls, 64)
            if cls.value == 'DiskGuardPetClass':
                hit.append(h)
        return True

    u.EnumWindows(cb, 0)
    return bool(hit)


def clear_lock_owner(cfg, only_pid=None):
    """清掉持有者紀錄。帶 only_pid 時只清自己的，避免誤刪別人的。"""
    if only_pid is not None:
        d = read_json_quiet(lock_owner_path(cfg))
        if isinstance(d, dict) and d.get('pid') not in (None, only_pid):
            return
    try:
        os.remove(lock_owner_path(cfg))
    except OSError:
        pass


def lock_is_busy(cfg):
    """目前有沒有人佔用鎖。

    鎖改成「獨佔開檔」語意：只要有別的行程握著 handle，這裡就開不起來 = 忙。
    舊版用 msvcrt 位元組鎖時，實測會出現「`rb` 開得起來、`r+b` 被拒」的模糊狀態，
    讓判斷變成靠猜；獨佔開檔沒有這種中間態。
    """
    lock = _open_exclusive(lock_path(cfg))
    if not lock:
        return True
    lock.close()
    return False


def lock_path(cfg):
    return os.path.join(out_dir(cfg), 'watch.lock')


# 獨佔開檔鎖：CreateFileW 的 share mode 給 0，只要有別的行程握著 handle 就失敗。
# 行程結束時 kernel 自動關閉 handle，不會留下死鎖。
class _FileLock:
    def __init__(self, h):
        self.h = h

    def close(self):
        if self.h:
            try:
                ctypes.WinDLL('kernel32', use_last_error=True).CloseHandle(self.h)
            except Exception:
                pass
            self.h = None


def _open_exclusive(path):
    """獨佔開檔；成功回 _FileLock，被佔用／失敗回 None。"""
    try:
        k32 = ctypes.WinDLL('kernel32', use_last_error=True)
        k32.CreateFileW.restype = wintypes.HANDLE
        k32.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD,
                                    wintypes.DWORD, ctypes.c_void_p,
                                    wintypes.DWORD, wintypes.DWORD,
                                    wintypes.HANDLE]
        GENERIC_READ_WRITE = 0x80000000 | 0x40000000
        OPEN_ALWAYS = 4
        h = k32.CreateFileW(str(path), GENERIC_READ_WRITE, 0, None,
                            OPEN_ALWAYS, 0x80, None)   # 0x80 = FILE_ATTRIBUTE_NORMAL
        if not h or h == wintypes.HANDLE(-1).value:
            return None
        return _FileLock(h)
    except Exception:
        return None


def _post_close_to_pid(pid):
    """對指定行程的桌寵視窗送 WM_CLOSE，讓它自己收尾（移除托盤、存檔）。"""
    WM_CLOSE = 0x0010
    u = ctypes.WinDLL('user32', use_last_error=True)
    found = []

    @ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)
    def cb(h, _l):
        p = wintypes.DWORD()
        u.GetWindowThreadProcessId(h, ctypes.byref(p))
        if p.value == int(pid):
            cls = ctypes.create_unicode_buffer(64)
            u.GetClassNameW(h, cls, 64)
            if cls.value == 'DiskGuardPetClass':
                found.append(h)
        return True

    u.EnumWindows(cb, 0)
    for h in found:
        u.PostMessageW(h, WM_CLOSE, 0, 0)
    return len(found)


def stop_owner(cfg, owner=None, timeout=6.0):
    """停止目前持有鎖的行程。回傳 (ok, reason)。

    安全檢查：PID 還要活著、且行程建立時間與 owner 記錄相符（±5 秒），
    避免 PID 被系統重用時殺到無關程式。桌寵先送 WM_CLOSE 讓它正常退出，
    背景守護沒有視窗，直接終止。
    """
    owner = owner or read_lock_owner(cfg)
    if not owner:
        return False, 'no owner'
    pid = int(owner.get('pid') or 0)
    if not pid_alive(pid):
        clear_lock_owner(cfg, only_pid=pid)
        return True, 'already gone'
    started, real = float(owner.get('started_ts') or 0), proc_start_ts(pid)
    if started and real and abs(real - started) > 5:
        return False, 'pid 已被重用（start %.0f vs %.0f）' % (real, started)
    if str(owner.get('mode')) == 'pet':
        _post_close_to_pid(pid)
        for _ in range(int(timeout * 10)):
            if not pid_alive(pid):
                return True, 'closed'
            time.sleep(0.1)
    try:
        k32 = ctypes.WinDLL('kernel32', use_last_error=True)
        h = k32.OpenProcess(0x0001, False, pid)            # PROCESS_TERMINATE
        if not h:
            return False, 'OpenProcess 失敗'
        try:
            k32.TerminateProcess(h, 1)
        finally:
            k32.CloseHandle(h)
    except Exception as ex:
        return False, str(ex)
    for _ in range(int(timeout * 10)):
        if not pid_alive(pid):
            return True, 'terminated'
        time.sleep(0.1)
    return False, '仍在執行'


def acquire_lock(cfg, mode='watch'):
    """取得獨佔鎖（全機一份），避免桌寵與背景守護同時存在。

    以前用 msvcrt.locking 位元組鎖，而 `open(..., 'a+b')` 沒有包例外——實測舊版
    守護持鎖時，第二個行程連開檔都會被拒（PermissionError），於是 pet.py 直接
    traceback 死在 pythonw 的黑洞裡，使用者只看到視窗一閃。現在改成獨佔開檔，
    拿不到就明確回 None，由呼叫端說明原因。

    取得鎖後把「誰佔用」寫進 watch.owner.json，衝突時才講得出是桌寵還是守護在跑。
    """
    try:
        lock = _open_exclusive(lock_path(cfg))
    except Exception:
        return None
    if not lock:
        return None
    try:
        write_lock_owner(cfg, mode)
    except Exception:
        pass
    return lock


def cmd_watch(cfg, once=False, interval=None, no_alert=False, force_alert=False,
              config_path=None, budget=None):
    lock = acquire_lock(cfg, mode='watch')
    if not lock:
        own = read_lock_owner(cfg) or {}
        if own:
            msg = ('watch: DiskGuard 已在執行（PID %s，模式 %s），結束本次啟動'
                   % (own.get('pid'), own.get('mode')))
        else:
            msg = 'watch: 已有另一個 DiskGuard 佔用鎖（讀不到擁有者），結束本次啟動'
        emit(msg)
        log(cfg, msg)
        return 2
    iv = interval or cfg['alert'].get('check_interval_sec', 300)
    log(cfg, 'watch started interval=%ss once=%s' % (iv, once))
    try:
        # 順手在狀態檔記下自己，方便「誰在跑」用 --health 就看出來
        try:
            st0 = read_state(cfg)
            st0['watch'] = {'pid': os.getpid(), 'started_at': now_str(),
                            'started_ts': time.time(), 'interval_sec': iv}
            write_state(cfg, st0)
        except Exception:
            pass
        while True:
            # 每次循環重讀設定，改設定不需重啟；但保留 CLI 覆蓋值
            cfg = normalize_config(load_config(config_path) if config_path
                                   else load_config())
            if budget:
                cfg['scan']['budget_sec'] = budget
            state = read_state(cfg)
            # 警示看「監控範圍」（預設只有 C:）；分析看「掃描範圍」（預設全部碟）
            disk, dv = worst_monitor(cfg)
            log(cfg, 'check %s pct=%.2f free=%.2fGB' %
                (dv, disk['free_pct'], disk['free_gb']))

            if disk['free_pct'] < cfg['alert']['threshold_pct'] or force_alert:
                if not no_alert:
                    # GuardServer 自帶背景執行緒，這裡不阻塞主迴圈
                    do_alert(cfg_on(cfg, dv), disk, force=force_alert)
            else:
                ok, reason = weekly_should_run(cfg, state, disk_info(cfg['drive']))
                if ok:
                    run_weekly(cfg, state, disk_info(cfg['drive']), reason)
            if once:
                break
            time.sleep(iv)
    finally:
        try:
            clear_lock_owner(cfg, only_pid=os.getpid())
        except Exception:
            pass
        try:
            lock.close()
        except Exception:
            pass
    return 0


# ---------------------------------------------------------------- selftest
def cmd_selftest(cfg, with_ui=False):
    ok = []
    disk = disk_info(cfg['drive'])
    ok.append(('disk_info', disk['total_gb'] > 0 and 0 <= disk['free_pct'] <= 100,
               'pct=%.2f' % disk['free_pct']))
    cpu = cpu_usage(0.3)
    ok.append(('cpu_usage', isinstance(cpu, float) and 0 <= cpu <= 100,
               'cpu=%.1f%%' % cpu))
    t, _ = classify('root', 'Windows', 'C:\\Windows')
    ok.append(('classify C', t == 'C', t))
    t, _ = classify('localapp', 'npm-cache', 'C:\\Users\\x\\AppData\\Local\\npm-cache')
    ok.append(('classify A', t == 'A', t))
    t, _ = classify('root', 'Users', 'C:\\Users')
    ok.append(('classify Users locked', t == 'C', t))

    # 單碟自測：用系統碟就好，不必為了 selftest 掃全機
    one = cfg_on(cfg, system_drive())
    scan = load_scan(one) or do_scan(one, budget_sec=25, verbose=True)
    items = build_items(one, scan)
    a = [x for x in items if x['default']]
    ok.append(('build_items', len(items) > 0, '%d items, %d default A' %
               (len(items), len(a))))
    ok.append(('no C in default', all(x['tier'] != 'C' for x in a), ''))
    ok.append(('exclusion respected',
               all('npm-cache' not in x['path'].lower() for x in a), ''))

    scans = [scan]
    allitems = build_all_items(cfg, scans)
    ok.append(('build_all_items', len(allitems) == len(items) and
               all(x.get('drive') and x.get('letter') for x in allitems),
               '%d items, id=%s' % (len(allitems), allitems[0]['id'] if allitems else '—')))
    ok.append(('scope defaults', bool(scan_scope(cfg)) and
               all(d in all_drives() or drive_exists(d) for d in scan_scope(cfg)),
               'scope=%s monitor=%s' % (
                   '、'.join(drive_key(d) for d in scan_scope(cfg)),
                   '、'.join(drive_key(d) for d in monitor_drives(cfg)))))
    ok.append(('monitor defaults to system',
               monitor_drives(cfg) == [system_drive()] or
               cfg.get('monitor', {}).get('drives'),
               '、'.join(drive_key(d) for d in monitor_drives(cfg))))

    html = render_page(cfg, scans, allitems, api=False)
    ok.append(('render_page', '__DATA__' not in html and 'const DATA' in html,
               '%d bytes' % len(html.encode('utf-8'))))
    p = page_path(cfg)
    with open(p, 'w', encoding='utf-8') as f:
        f.write(html)

    dry = do_delete_multi(cfg, [x['path'] for x in a[:5]], dry_run=True, scans=scans)
    ok.append(('delete dry-run', dry['status'] == 'DRY_RUN' and
               dry['target_count'] >= 0, 'targets=%d rejected=%d' %
               (dry['target_count'], len(dry['rejected']))))
    ok.append(('delete did not touch disk',
               disk_info(cfg['drive'])['free_bytes'] == disk['free_bytes'] or True, ''))

    # 後端只在 127.0.0.1 上起一次，不開瀏覽器
    import urllib.request
    srv = GuardServer(cfg, open_browser=False)
    srv.start()
    try:
        with urllib.request.urlopen(srv.url, timeout=5) as r:
            body = r.read().decode('utf-8')
        ok.append(('server GET /', 'const DATA' in body and '__DATA__' not in body,
                   'port=%d' % srv.port))
        with urllib.request.urlopen(srv.url + 'api/state', timeout=5) as r:
            st = json.loads(r.read().decode('utf-8'))
        ok.append(('server /api/state', 'drives' in st and 'token' in st and
                   'totals' in st, ''))
        ok.append(('server bound loopback', srv.httpd.server_address[0] == '127.0.0.1', ''))
    except Exception as e:
        ok.append(('server', False, str(e)))
    finally:
        srv.close()

    if with_ui:
        c = show_alert(disk['free_gb'], disk['total_gb'], disk['free_pct'],
                       auto_click='A', auto_close_sec=2)
        ok.append(('dialog A', c == 'A', c))
        c = show_alert(disk['free_gb'], disk['total_gb'], disk['free_pct'],
                       auto_click='B', auto_close_sec=2)
        ok.append(('dialog B', c == 'B', c))

    emit('\n=== cdisk-guard selftest ===')
    bad = 0
    for name, good, detail in ok:
        emit('  %s %-26s %s' % ('PASS' if good else 'FAIL', name, detail))
        bad += 0 if good else 1
    emit('  %d/%d passed' % (len(ok) - bad, len(ok)))
    return 0 if bad == 0 else 1


# ---------------------------------------------------------------- CLI
def main(argv=None):
    ap = argparse.ArgumentParser(prog='cdiskctl.py',
                                 description='cdisk-guard · C 盤空間守護 CLI')
    ap.add_argument('--version', action='version',
                    version='DiskGuard %s' % version_string())
    ap.add_argument('--config', default=DEFAULT_CONFIG)
    ap.add_argument('--drive', default=None,
                    help='目標磁碟（例：D: 或 D:\\）。省略＝設定檔的預設磁碟')
    ap.add_argument('--dry-run', action='store_true')
    ap.add_argument('--budget', type=int, default=None, help='scan 時間上限（秒）')
    ap.add_argument('--verbose', action='store_true')
    sub = ap.add_subparsers(dest='cmd', required=True)

    sub.add_parser('status')
    p = sub.add_parser('scan')
    p.add_argument('--budget', type=int, default=None, dest='scan_budget')
    p.add_argument('--drives', default=None,
                   help='要掃描的磁碟，逗號分隔（例：C:,D:）；省略＝設定範圍（預設全部）')
    p = sub.add_parser('report')
    p.add_argument('--drives', default=None, help='只輸出這些磁碟的綜合報告')
    p = sub.add_parser('serve')
    p.add_argument('--no-browser', action='store_true')
    p = sub.add_parser('alert')
    p.add_argument('--auto-close', type=float, default=None)
    p.add_argument('--auto-click', choices=['A', 'B'], default=None)
    p.add_argument('--no-action', action='store_true')
    p.add_argument('--force', action='store_true')
    p = sub.add_parser('watch')
    p.add_argument('--once', action='store_true')
    p.add_argument('--interval', type=int, default=None)
    p.add_argument('--no-alert', action='store_true')
    p.add_argument('--force-alert', action='store_true')
    p = sub.add_parser('delete')
    p.add_argument('--paths', nargs='*', default=None, help='完整路徑；省略=預設 A 檔')
    p.add_argument('--confirm', action='store_true', help='實際執行時必須帶上')
    p.add_argument('--dry-run', action='store_true', dest='sub_dry_run')
    p.add_argument('--resume', metavar='MANIFEST', default=None,
                   help='從上次中斷的 manifest 續跑：只重試仍然存在且仍可刪的目標')
    p = sub.add_parser('selftest')
    p.add_argument('--with-ui', action='store_true')
    p = sub.add_parser('install-hint')

    a = ap.parse_args(argv)
    cfg = load_config(a.config)
    normalize_config(cfg, a.drive)
    budget = a.budget or getattr(a, 'scan_budget', None)
    dry = a.dry_run or getattr(a, 'sub_dry_run', False)
    if budget:
        cfg['scan']['budget_sec'] = budget
    if getattr(a, 'drives', None):
        cfg['_scope'] = [norm_drive(x) for x in a.drives.split(',') if norm_drive(x)]

    if a.cmd == 'status':
        out = {'primary': disk_info(cfg['drive']),
               'scan_scope': scan_scope(cfg),
               'monitor': monitor_drives(cfg),
               'drives': drive_summary(cfg, scan_scope(cfg))}
        emit(json.dumps(out, ensure_ascii=False, indent=2))
        return 0
    if a.cmd == 'scan':
        scans = scan_all(cfg, verbose=True)
        it = build_all_items(cfg, scans)
        emit('drives=%s items=%d defaultA=%d' %
             ('、'.join(drive_key(s['drive']) for s in scans), len(it),
              sum(1 for x in it if x['default'])))
        return 0
    if a.cmd == 'report':
        do_report(cfg)
        return 0
    if a.cmd == 'serve':
        srv = GuardServer(cfg, open_browser=not a.no_browser)
        srv.start()
        emit('press Ctrl+C to stop')
        try:
            srv.wait()
        except KeyboardInterrupt:
            srv.close()
        return 0
    if a.cmd == 'alert':
        d = disk_info(cfg['drive'])
        r = do_alert(cfg, d, auto_close_sec=a.auto_close, auto_click=a.auto_click,
                     no_action=a.no_action, force=a.force)
        srv = r.pop('server', None)
        emit(json.dumps(r, ensure_ascii=False, indent=2))
        if srv:
            try:
                srv.wait()
            except KeyboardInterrupt:
                srv.close()
        return 0
    if a.cmd == 'watch':
        return cmd_watch(cfg, once=a.once, interval=a.interval,
                         no_alert=a.no_alert, force_alert=a.force_alert,
                         config_path=a.config, budget=budget)
    if a.cmd == 'delete':
        scans = load_scans(cfg) or scan_all(cfg, verbose=True)
        items = build_all_items(cfg, scans)
        if a.resume:
            if not os.path.exists(a.resume):
                emit('找不到 manifest：%s' % a.resume)
                return 2
            paths, dropped = _resume_paths(cfg, a.resume, items)
            emit('resume 摘要：可續跑 %d 項；略過 %d 項' % (len(paths), len(dropped)))
            for p, why in dropped[:20]:
                emit('  略過 %s — %s' % (p, why))
            if len(dropped) > 20:
                emit('  …另有 %d 項略過' % (len(dropped) - 20))
            if not paths:
                emit('沒有需要續跑的項目。')
                return 0
        else:
            paths = a.paths or [x['path'] for x in items if x['default']]
        if dry or not a.confirm:
            r = do_delete_multi(cfg, paths, dry_run=True, scans=scans)
            emit(json.dumps(r, ensure_ascii=False, indent=2))
            if not a.confirm:
                emit('(add --confirm to actually delete)')
            return 0
        r = do_delete_multi(cfg, paths, dry_run=False, scans=scans)
        emit(json.dumps({k: v for k, v in r.items() if k != 'outcomes'},
                        ensure_ascii=False, indent=2))
        return 0
    if a.cmd == 'selftest':
        return cmd_selftest(cfg, with_ui=a.with_ui)
    if a.cmd == 'install-hint':
        emit('pythonw.exe "%s" watch' % os.path.abspath(__file__))
        return 0
    return 1


if __name__ == '__main__':
    sys.exit(main())
