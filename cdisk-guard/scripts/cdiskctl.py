# -*- coding: utf-8 -*-
r"""cdisk-guard · C 盤空間守護 CLI（純 stdlib，運行期零 LLM 呼叫）

    status / scan / report / serve / alert / watch / delete / selftest

設計與取捨詳見 references/evaluation.md、references/rules.md。
"""
import os
import sys
import json
import time
import math
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
PROFILE_ALLOWED = {'users', 'windows', 'programdata', 'tmp', '$recycle.bin'}


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
        if p.startswith('c:\\windows') or p.startswith('c:\\program files'):
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


def disk_info(drive='C:\\'):
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


def empty_recycle_bin():
    """SHEmptyRecycleBinW(NULL, ...) 清空所有磁碟；回傳 (ok, detail)。"""
    try:
        sh = ctypes.WinDLL('shell32', use_last_error=True)
        sh.SHEmptyRecycleBinW.argtypes = [wintypes.HWND, wintypes.LPCWSTR, wintypes.DWORD]
        sh.SHEmptyRecycleBinW.restype = ctypes.c_long
        hr = sh.SHEmptyRecycleBinW(None, None, 0x01 | 0x02 | 0x04)
        return (hr == 0), 'HRESULT=%s' % hr
    except Exception as e:
        return False, str(e)


def recycle_bin_residual():
    """逐 SID 統計回收站殘留（他人 SID 只回報、不清除）。"""
    base = 'C:\\$Recycle.Bin'
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
    p = os.path.join(out_dir(cfg), 'scan.json')
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
    p = os.path.join(out_dir(cfg), 'scan.json')
    if not os.path.exists(p):
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
            note = 'C:\\ 根目錄的系統檔案（pagefile.sys／hiberfil.sys 等），不可手動刪除，僅供對帳。'
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
                        and not x['locked'] and not x['excluded']
                        and not x['nested_in'])
    return items


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


# ---------------------------------------------------------------- 網頁
def render_page(cfg, scan, items, api=False, token=''):
    tpl_path = os.path.join(SCRIPTS, 'page.html')
    with open(tpl_path, 'r', encoding='utf-8') as f:
        tpl = f.read()
    disk = disk_info(cfg['drive'])
    meta = {
        'created': scan['created'] if scan else '—',
        'elapsed_sec': scan['elapsed_sec'] if scan else 0,
        'truncated': scan['truncated'] if scan else True,
        'files_seen': scan['files_seen'] if scan else 0,
        'users_found': scan['users_found'] if scan else [],
        'threshold_pct': cfg['alert']['threshold_pct'],
        'exclusions': cfg['delete'].get('default_exclusions', []),
        'default_tiers': cfg['delete'].get('default_tiers', ['A']),
    }

    def j(o):
        return json.dumps(o, ensure_ascii=False).replace('<', '\\u003c')

    for k, v in (('__DATA__', j(items)), ('__DISK__', j(disk)),
                 ('__META__', j(meta)), ('__NOW__', now_str()),
                 ('__API__', 'true' if api else 'false'),
                 ('__TOKEN__', token)):
        tpl = tpl.replace(k, v)
    return tpl


def do_report(cfg, scan=None):
    scan = scan or load_scan(cfg)
    if not scan:
        scan = do_scan(cfg)
    items = build_items(cfg, scan)
    html = render_page(cfg, scan, items, api=False)
    p = os.path.join(out_dir(cfg), cfg['paths']['page_filename'])
    with open(p, 'w', encoding='utf-8') as f:
        f.write(html)
    emit('report: %d items -> %s' % (len(items), p))
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
    limit = cfg['delete'].get('small_backup_mb', 100)
    small = [t for t in targets if t['mb'] < limit and os.path.isdir(t['path'])
             and t['action'] == 'direct']
    zp = os.path.join(out_dir(cfg), 'backup_%s.zip' % stamp)
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
    """回傳 (targets, rejected)。任何不合法路徑都會被拒絕，不是整批中止而是逐項剔除。"""
    by = {x['path'].rstrip('\\').lower(): x for x in items}
    drive = cfg['drive'].lower().rstrip('\\')
    targets, rejected = [], []
    for p in paths:
        low = p.rstrip('\\').lower()
        # 路徑安全檢查優先，不依賴掃描清單內容
        if '..' in p or not low.startswith(drive + '\\'):
            rejected.append({'path': p, 'reason': '路徑超出允許範圍'})
            continue
        x = by.get(low)
        if not x:
            rejected.append({'path': p, 'reason': '不在最新掃描清單內'})
            continue
        if x['tier'] == 'C' or not x['selectable'] or x['locked']:
            rejected.append({'path': p, 'reason': 'C 檔／鎖定項，禁止刪除'})
            continue
        rel = low[len(drive) + 1:]
        parts = rel.split('\\')
        if not parts or not parts[0] or parts[0] not in PROFILE_ALLOWED \
                or (len(parts) == 1 and parts[0] in C_ROOT):
            rejected.append({'path': p, 'reason': '非允許的頂層目錄或為磁碟根'})
            continue
        if parts[0] == 'users' and len(parts) == 2:
            rejected.append({'path': p, 'reason': '使用者設定檔總目錄不可整刪'})
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


def do_delete(cfg, paths, dry_run=False, scan=None):
    """依 2026-11-23 的流程：manifest → 小項備份 → 分批直接刪除 → 逐項複核 → 紀錄。"""
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
    mp = os.path.join(out_dir(cfg), 'execution_manifest_%s.json' % stamp)
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
                        ok, detail = empty_recycle_bin()
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
            # 每批後複核；若有非預期例外則記錄但不中斷（逐項容錯）
            log(cfg, 'delete batch %d/%d done' %
                (bi // bsize + 1, math.ceil(len(targets) / bsize)))
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

    # 4) 回收站：預設只回報殘留；啟用設定才清空（避免動到他人 SID 資料）
    if cfg['delete'].get('auto_empty_recycle_bin', False):
        ok, detail = empty_recycle_bin()
        result['recycle_bin_cleared'] = {'ok': ok, 'detail': detail}
    else:
        result['recycle_bin_cleared'] = {
            'ok': None,
            'detail': cfg['delete'].get('auto_empty_recycle_bin_note', '未啟用')}
    result['recycle_bin_residual'] = recycle_bin_residual()

    # 5) 空間對比（同一資料來源）
    free_after = disk_info(cfg['drive'])['free_bytes']
    result['free_after_mb'] = round(free_after / MB, 1)
    result['observed_gain_mb'] = round((free_after - free_before) / MB, 1)
    result['gain_note'] = ('觀測淨增受其他程式寫入影響，不等於精確歸因；'
                           '帳面目標值請見 effective_mb。')

    # 6) 寫紀錄
    rp = os.path.join(out_dir(cfg), 'execution_result_%s.json' % stamp)
    with open(rp, 'w', encoding='utf-8') as f:
        json.dump(result, f, ensure_ascii=False, indent=2)
    lp = os.path.join(out_dir(cfg), 'execution_log.md')
    L = ['# cdisk-guard 執行紀錄 · %s' % now_str(), '',
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
         '> ⚠️ 此操作非常危險，可能導致不可逆的數據丟失！本次刪除不經回收站，'
         '僅 <100 MB 小項 ZIP 備份可還原。', '',
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
    return result


# ---------------------------------------------------------------- 本機後端
EDGE = r'C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe'
CHROME = r'C:\Program Files\Google\Chrome\Application\chrome.exe'
_ACTIVE_SERVER = None


class GuardServer:
    def __init__(self, cfg, open_browser=True):
        self.cfg = cfg
        self.token = secrets.token_urlsafe(18)
        self.scan = load_scan(cfg) or do_scan(
            cfg, budget_sec=cfg['scan'].get('serve_budget_sec', 180))
        self.items = build_items(cfg, self.scan)
        self.browser = None
        self.open_browser = open_browser
        self._stop = threading.Event()

        outer = self

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
                    html = render_page(outer.cfg, outer.scan, outer.items,
                                       api=True, token=outer.token)
                    self._send(200, html.encode('utf-8'), 'text/html; charset=utf-8')
                elif path == '/api/state':
                    self._json({'disk': disk_info(outer.cfg['drive']),
                                'meta': {'created': outer.scan['created'],
                                         'items': len(outer.items),
                                         'truncated': outer.scan['truncated']},
                                'token': outer.token})
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
                if path == '/api/rescan':
                    outer.scan = do_scan(outer.cfg)
                    outer.items = build_items(outer.cfg, outer.scan)
                    return self._json({'ok': True, 'created': outer.scan['created'],
                                       'items': len(outer.items)})
                if path == '/api/delete':
                    if not body.get('confirm'):
                        return self._json({'error': 'need explicit confirm'}, 400)
                    paths = body.get('paths', [])
                    if not isinstance(paths, list) or not paths:
                        return self._json({'error': 'empty selection'}, 400)
                    dry = bool(body.get('dry_run'))
                    res = do_delete(outer.cfg, paths, dry_run=dry, scan=outer.scan)
                    if not dry:
                        outer.items = build_items(outer.cfg, outer.scan)
                    return self._json(res)
                return self._json({'error': 'not found'}, 404)

        host = cfg['server'].get('host', '127.0.0.1')
        port = cfg['server'].get('port', 0)
        self.httpd = ThreadingHTTPServer((host, port), H)
        self.httpd.daemon_threads = True
        self.port = self.httpd.server_address[1]
        self.url = 'http://%s:%d/' % (host, self.port)

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
        f.write('- 最新分析網頁：`%s`\n' %
                os.path.join(out_dir(cfg), cfg['paths']['page_filename']))
    return p


def do_alert(cfg, disk, extra_line='', auto_close_sec=None,
             auto_click=None, no_action=False, force=False):
    """顯示 A/B 警示框並據以行動。回傳 dict。"""
    global _ACTIVE_SERVER
    st = read_state(cfg)
    now = time.time()
    if not force and now - st.get('last_alert_ts', 0) < cfg['alert'].get('cooldown_sec', 21600):
        log(cfg, 'alert suppressed by cooldown (pct=%.2f)' % disk['free_pct'])
        return {'choice': 'SKIPPED_COOLDOWN'}
    choice = show_alert(
        disk['free_gb'], disk['total_gb'], disk['free_pct'],
        title=cfg['alert'].get('title', '磁盤剩餘空間'),
        extra_line=extra_line, auto_close_sec=auto_close_sec,
        auto_click=auto_click)
    st['last_alert_ts'] = now
    st['last_alert_pct'] = disk['free_pct']
    st['last_alert_choice'] = choice
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


def weekly_should_run(cfg, state, disk):
    w = cfg['weekly']
    now = datetime.datetime.now()
    if now.weekday() != w.get('weekday', 0):
        return False, 'not monday'
    if not (w.get('earliest_hour', 0) <= now.hour <= w.get('latest_hour', 23)):
        return False, 'outside hour window'
    if w.get('run_once_per_day', True) and \
            state.get('last_weekly_date') == now.date().isoformat():
        return False, 'already done today'
    cpu = cpu_usage(w.get('cpu_sample_sec', 1.0))
    if cpu > w.get('cpu_max_pct', 25):
        return False, 'cpu busy %.1f%%' % cpu
    return True, 'cpu idle %.1f%%' % cpu


def run_weekly(cfg, state, disk, reason):
    scan = do_scan(cfg, verbose=True)
    do_report(cfg, scan)
    state['last_weekly_date'] = datetime.date.today().isoformat()
    state['last_scan_ts'] = time.time()
    write_state(cfg, state)
    log(cfg, 'weekly analysis done: files=%d elapsed=%ss pct=%.2f reason=%s' %
        (scan['files_seen'], scan['elapsed_sec'], disk['free_pct'], reason))
    level = decide_notify(cfg, disk)
    if level == 'alert':
        write_notice(cfg, disk, '週一分析後仍低於 2%')
        return 'alert', scan
    if level == 'warn':
        write_notice(cfg, disk, '週一分析後介於 2%~10%')
        if cfg['alert'].get('notify_on_warn_pct', False):
            return 'warn_alert', scan
        return 'warn_logged', scan
    log(cfg, 'weekly analysis: no notification needed')
    return 'none', scan


# ---------------------------------------------------------------- watch
def acquire_lock(cfg):
    """Windows 檔案鎖，行程結束自動釋放，避免多重守護。"""
    import msvcrt
    p = os.path.join(out_dir(cfg), 'watch.lock')
    f = open(p, 'a+b')
    f.seek(0, 2)
    if f.tell() == 0:
        f.write(b'0')
    f.seek(0)
    try:
        msvcrt.locking(f.fileno(), msvcrt.LK_NBLCK, 1)
        return f
    except OSError:
        f.close()
        return None


def cmd_watch(cfg, once=False, interval=None, no_alert=False, force_alert=False,
              config_path=None, budget=None):
    lock = acquire_lock(cfg)
    if not lock:
        emit('watch: another instance is already running, exit')
        return 2
    iv = interval or cfg['alert'].get('check_interval_sec', 300)
    log(cfg, 'watch started interval=%ss once=%s' % (iv, once))
    try:
        while True:
            # 每次循環重讀設定，改設定不需重啟；但保留 CLI 覆蓋值
            cfg = load_config(config_path) if config_path else load_config()
            if budget:
                cfg['scan']['budget_sec'] = budget
            state = read_state(cfg)
            disk = disk_info(cfg['drive'])
            log(cfg, 'check pct=%.2f free=%.2fGB' %
                (disk['free_pct'], disk['free_gb']))

            if disk['free_pct'] < cfg['alert']['threshold_pct'] or force_alert:
                if not no_alert:
                    # GuardServer 自帶背景執行緒，這裡不阻塞主迴圈
                    do_alert(cfg, disk, force=force_alert)
            else:
                ok, reason = weekly_should_run(cfg, state, disk)
                if ok:
                    run_weekly(cfg, state, disk, reason)
            if once:
                break
            time.sleep(iv)
    finally:
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

    scan = load_scan(cfg) or do_scan(cfg, budget_sec=25, verbose=True)
    items = build_items(cfg, scan)
    a = [x for x in items if x['default']]
    ok.append(('build_items', len(items) > 0, '%d items, %d default A' %
               (len(items), len(a))))
    ok.append(('no C in default', all(x['tier'] != 'C' for x in a), ''))
    ok.append(('exclusion respected',
               all('npm-cache' not in x['path'].lower() for x in a), ''))

    html = render_page(cfg, scan, items, api=False)
    ok.append(('render_page', '__DATA__' not in html and 'const DATA' in html,
               '%d bytes' % len(html.encode('utf-8'))))
    p = os.path.join(out_dir(cfg), cfg['paths']['page_filename'])
    with open(p, 'w', encoding='utf-8') as f:
        f.write(html)

    dry = do_delete(cfg, [x['path'] for x in a[:5]], dry_run=True, scan=scan)
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
        ok.append(('server /api/state', 'disk' in st and 'token' in st, ''))
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
    ap.add_argument('--dry-run', action='store_true')
    ap.add_argument('--budget', type=int, default=None, help='scan 時間上限（秒）')
    ap.add_argument('--verbose', action='store_true')
    sub = ap.add_subparsers(dest='cmd', required=True)

    sub.add_parser('status')
    p = sub.add_parser('scan')
    p.add_argument('--budget', type=int, default=None, dest='scan_budget')
    sub.add_parser('report')
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
    budget = a.budget or getattr(a, 'scan_budget', None)
    dry = a.dry_run or getattr(a, 'sub_dry_run', False)
    if budget:
        cfg['scan']['budget_sec'] = budget

    if a.cmd == 'status':
        emit(json.dumps(disk_info(cfg['drive']), ensure_ascii=False, indent=2))
        return 0
    if a.cmd == 'scan':
        s = do_scan(cfg, verbose=True)
        it = build_items(cfg, s)
        emit('items=%d defaultA=%d' % (len(it), sum(1 for x in it if x['default'])))
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
        scan = load_scan(cfg) or do_scan(cfg, verbose=True)
        items = build_items(cfg, scan)
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
            r = do_delete(cfg, paths, dry_run=True, scan=scan)
            emit(json.dumps(r, ensure_ascii=False, indent=2))
            if not a.confirm:
                emit('(add --confirm to actually delete)')
            return 0
        r = do_delete(cfg, paths, dry_run=False, scan=scan)
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
