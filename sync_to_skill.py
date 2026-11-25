#!/usr/bin/env python3
"""把工作目錄的 cdisk-guard 單向同步到 WorkBuddy 已安裝技能目錄。

Source of truth: C:\\AI\\@Project\\DiskGuard\\cdisk-guard\\
Installed copy : ~\\.workbuddy\\skills\\cdisk-guard\\

用法：
    python sync_to_skill.py              # 同步程式／設定／文件（保留已安裝的 data/）
    python sync_to_skill.py --dry-run    # 只列出差異，不寫入
    python sync_to_skill.py --with-data  # 連 data/（掃描、網頁、狀態、日誌）一起覆寫

注意：這是單向同步（工作目錄 -> 已安裝技能）。直接改已安裝副本會在下次同步時被覆蓋。
"""

import argparse
import hashlib
import os
import shutil
import sys

ROOT = os.path.dirname(os.path.abspath(__file__))
SRC = os.path.join(ROOT, 'cdisk-guard')
DST = os.path.join(os.path.expanduser('~'), '.workbuddy', 'skills', 'cdisk-guard')

SKIP_DIRS = {'__pycache__', '.git', '.venv'}
SKIP_EXT = {'.pyc', '.pyo', '.tmp'}


def digest(path):
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for chunk in iter(lambda: f.read(65536), b''):
            h.update(chunk)
    return h.hexdigest()


def collect(with_data):
    out = []
    for cur, dirs, files in os.walk(SRC):
        dirs[:] = sorted(d for d in dirs if d not in SKIP_DIRS)
        rel = os.path.relpath(cur, SRC)
        if not with_data and (rel == 'data' or rel.startswith('data' + os.sep)):
            dirs[:] = []
            continue
        for fn in sorted(files):
            if os.path.splitext(fn)[1].lower() in SKIP_EXT:
                continue
            full = os.path.join(cur, fn)
            out.append((os.path.relpath(full, SRC), full))
    return out


def main():
    ap = argparse.ArgumentParser(description='cdisk-guard 單向同步到已安裝技能')
    ap.add_argument('--dry-run', action='store_true', help='只列出差異，不寫入')
    ap.add_argument('--with-data', action='store_true', help='連 data/ 一併覆寫')
    a = ap.parse_args()

    if not os.path.isdir(SRC):
        print('找不到來源目錄：' + SRC)
        return 1
    if not os.path.isdir(DST):
        print('找不到已安裝技能目錄：' + DST)
        return 1

    files = collect(a.with_data)
    changed, same = [], []
    for rel, src_path in files:
        dst = os.path.join(DST, rel)
        if os.path.isfile(dst) and digest(dst) == digest(src_path):
            same.append(rel)
        else:
            changed.append(rel)

    print('來源：' + SRC)
    print('目的：' + DST)
    print('檔案總數 %d｜相同 %d｜需更新 %d｜模式：%s'
          % (len(files), len(same), len(changed),
             'DRY-RUN' if a.dry_run else 'WRITE'))
    for rel in changed:
        print('  %s  %s' % ('[would]' if a.dry_run else '[sync] ', rel))

    if a.dry_run or not changed:
        print('未寫入任何檔案。' if a.dry_run else '已安裝技能已是最新版。')
        return 0

    for rel in changed:
        src_path = os.path.join(SRC, rel)   # 來源必須由 rel 重新算出，不可沿用迴圈變數
        dst = os.path.join(DST, rel)
        os.makedirs(os.path.dirname(dst), exist_ok=True)
        shutil.copy2(src_path, dst)
        if digest(dst) != digest(src_path):
            print('同步後校驗失敗：' + rel)
            return 2
    print('同步完成：%d 個檔案已更新（data/ %s）。'
          % (len(changed), '已同步' if a.with_data else '保留不動'))
    return 0


if __name__ == '__main__':
    sys.exit(main())
