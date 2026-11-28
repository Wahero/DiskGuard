#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""DiskGuard 共用工具：原子寫入、JSON 快取、路徑與檔案走訪輔助。

只放跨模組重複且低風險的實作；磁碟掃描／刪除政策仍留在 cdiskctl.py。
"""
from __future__ import annotations

import json
import os
import stat
import tempfile
import threading


# 固定條帶鎖：避免每個 manifest／result 路徑都永久留一個 Lock 物件。
_PATH_LOCKS = tuple(threading.Lock() for _ in range(64))


def _path_lock(path):
    return _PATH_LOCKS[hash(os.path.abspath(path)) % len(_PATH_LOCKS)]


def ensure_dir(path):
    if path:
        os.makedirs(path, exist_ok=True)


def atomic_write_bytes(path, data, durable=True):
    """同目錄唯一暫存檔寫入，完成後 os.replace；可選擇是否 fsync。"""
    with _path_lock(path):
        return _atomic_write_bytes_locked(path, data, durable=durable)


def _atomic_write_bytes_locked(path, data, durable=True):
    path = os.path.abspath(path)
    parent = os.path.dirname(path)
    ensure_dir(parent)
    fd, tmp = tempfile.mkstemp(prefix='.' + os.path.basename(path) + '.',
                               suffix='.tmp', dir=parent)
    try:
        with os.fdopen(fd, 'wb') as f:
            f.write(data)
            f.flush()
            if durable:
                try:
                    os.fsync(f.fileno())
                except OSError:
                    pass
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def atomic_write_text(path, text, durable=True, encoding='utf-8'):
    atomic_write_bytes(path, text.encode(encoding), durable=durable)


def atomic_write_json(path, obj, durable=True, indent=2):
    text = json.dumps(obj, ensure_ascii=False, indent=indent)
    atomic_write_text(path, text, durable=durable)


def read_json(path, default=None):
    try:
        with open(path, 'r', encoding='utf-8') as f:
            return json.load(f)
    except (OSError, ValueError, TypeError):
        return default


def file_signature(path):
    """(mtime_ns, size)；不存在回 None。用來避免反覆 open/parse 未變的 JSON。"""
    try:
        st = os.stat(path)
        return st.st_mtime_ns, st.st_size
    except OSError:
        return None


class JsonFileCache:
    """執行緒安全、依檔案指紋快取的 JSON 讀取器。

    檔案未變時只做一次 stat，不重複 open／json.loads；缺檔也會快取，
    避免每秒製造並捕捉 FileNotFoundError。
    """
    def __init__(self):
        self._lock = threading.Lock()
        self._items = {}

    def get(self, path, default=None):
        try:
            sig = file_signature(path)
        except Exception:
            return default
        with self._lock:
            old = self._items.get(path)
            if old is not None and old[0] == sig:
                return old[1]
        value = read_json(path, default)
        with self._lock:
            self._items[path] = (sig, value)
        return value

    def clear(self):
        with self._lock:
            self._items.clear()


def tail_lines(path, count=5, block_size=8192):
    """從檔案尾端有限讀取最後 count 行，不把整個 log 載入記憶體。"""
    if count <= 0:
        return []
    try:
        with open(path, 'rb') as f:
            f.seek(0, os.SEEK_END)
            pos = f.tell()
            data = b''
            while pos > 0 and data.count(b'\n') <= count:
                n = min(block_size, pos)
                pos -= n
                f.seek(pos)
                data = f.read(n) + data
    except OSError:
        return []
    lines = data.decode('utf-8', errors='replace').splitlines()
    return lines[-count:]


def is_reparse_path(path):
    """目標本身是否為 junction／symlink／其他 reparse point。"""
    try:
        return bool(os.lstat(path).st_file_attributes & 0x400)
    except (OSError, AttributeError):
        return False


def nearest_ancestors(paths):
    """回傳每個路徑最近的祖先索引；O(N log N)，取代雙重迴圈。"""
    paths = list(paths)
    result = [None] * len(paths)
    order = sorted(range(len(paths)), key=lambda i: paths[i])
    stack = []
    for i in order:
        p = paths[i]
        while stack and not p.startswith(paths[stack[-1]] + '\\'):
            stack.pop()
        if stack:
            result[i] = stack[-1]
        stack.append(i)
    return result


def walk_files_safe(root, on_error=None):
    """走訪普通檔案，遞迴前剪除 reparse point；不跟隨連結。

    回傳 (path, stat_result)。目錄列舉或 stat 失敗會呼叫 on_error(path, exc)，
    呼叫者可據此判定備份不完整，而不是靜默略過。
    """
    try:
        root_st = os.lstat(root)
    except OSError as exc:
        if on_error:
            on_error(root, exc)
        return
    if root_st.st_file_attributes & 0x400:
        if on_error:
            on_error(root, OSError('reparse point refused'))
        return
    if not stat.S_ISDIR(root_st.st_mode):
        yield root, root_st
        return
    stack = [root]
    while stack:
        cur = stack.pop()
        try:
            with os.scandir(cur) as it:
                entries = list(it)
        except OSError as exc:
            if on_error:
                on_error(cur, exc)
            continue
        for e in entries:
            try:
                st = e.stat(follow_symlinks=False)
            except OSError as exc:
                if on_error:
                    on_error(e.path, exc)
                continue
            if st.st_file_attributes & 0x400:
                if on_error:
                    on_error(e.path, OSError('reparse point skipped'))
                continue
            if stat.S_ISDIR(st.st_mode):
                stack.append(e.path)
            else:
                yield e.path, st
