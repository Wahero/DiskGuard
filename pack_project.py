#!/usr/bin/env python3
"""把整個 DiskGuard 工作目錄打包成 dist/ 下的 zip。

用法：
    python pack_project.py                     # 預設 dist\\DiskGuard_工作目錄_<今天>.zip
    python pack_project.py 自訂名稱.zip        # 自訂輸出檔名（仍放在 dist\\）
    python pack_project.py --with-dist         # 連 dist\\ 內的舊 zip 一起打包（會很大）

會略過 __pycache__、*.pyc/*.tmp、輸出 zip 本身，以及被常駐行程鎖住的檔案
（例如 watch.lock）。預設略過整個 dist\\ 目錄，避免舊 zip 層層嵌套。
無法讀取的檔案會列出而不中斷。
"""
import datetime
import os
import sys
import zipfile

ROOT = r'C:\AI\@Project\DiskGuard'
TODAY = datetime.date.today().strftime('%Y%m%d')

args = [a for a in sys.argv[1:] if not a.startswith('--')]
WITH_DIST = '--with-dist' in sys.argv[1:]
NAME = args[0] if args else 'DiskGuard_工作目錄_%s.zip' % TODAY
DST = os.path.join(ROOT, 'dist', NAME)

SKIP_DIRS = {'__pycache__', '.git', '.venv'}
if not WITH_DIST:
    SKIP_DIRS.add('dist')
SKIP_EXT = {'.pyc', '.pyo', '.tmp'}
SKIP_NAMES = {'watch.lock'}

os.makedirs(os.path.dirname(DST), exist_ok=True)
count, skipped = 0, []
with zipfile.ZipFile(DST, 'w', zipfile.ZIP_DEFLATED) as z:
    for cur, dirs, files in os.walk(ROOT):
        dirs[:] = sorted(d for d in dirs if d not in SKIP_DIRS)
        for f in sorted(files):
            if os.path.splitext(f)[1].lower() in SKIP_EXT or f in SKIP_NAMES:
                continue
            fp = os.path.join(cur, f)
            if os.path.abspath(fp) == os.path.abspath(DST):
                continue
            rel = os.path.relpath(fp, ROOT).replace('\\', '/')
            try:
                z.write(fp, rel)
                count += 1
            except OSError as e:
                skipped.append((rel, str(e)))
print('ZIP      =', DST)
print('FILES    =', count, '| BYTES =', os.path.getsize(DST))
print('SKIPPED  =', skipped)
with zipfile.ZipFile(DST) as z:
    names = z.namelist()
    print('TOPLEVEL =', sorted(set(n.split('/')[0] for n in names)))
    print('HAS_TEST =', any(n.startswith('_delete_test/') for n in names))
    print('HAS_PET  =', any(n.endswith('scripts/pet.py') for n in names))
