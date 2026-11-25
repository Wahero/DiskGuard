#!/usr/bin/env python3
"""從原始碼產生 GitHub Release 用的乾淨 zip。

用法：
    python make_release.py            # → dist\\DiskGuard-v<版本>.zip
    python make_release.py --check    # 只檢查內容，不寫檔

版本號唯一來源：cdisk-guard\\VERSION。
打包白名單：cdisk-guard\\（去掉 data\\、__pycache__、*.pyc、watch.lock）＋ README／LICENSE／CHANGELOG。
執行期資料、日誌、診斷產出、個人清理紀錄一律不進包。
"""
import hashlib
import os
import sys
import zipfile

ROOT = os.path.dirname(os.path.abspath(__file__))
APP = os.path.join(ROOT, 'cdisk-guard')
DIST = os.path.join(ROOT, 'dist')

ROOT_FILES = ['README.md', 'LICENSE', 'CHANGELOG.md']
SKIP_DIRS = {'__pycache__', 'data', '.git', '.venv'}
SKIP_EXT = {'.pyc', '.pyo', '.tmp', '.log'}
SKIP_NAMES = {'watch.lock', 'state.json'}


def read_version():
    with open(os.path.join(APP, 'VERSION'), encoding='utf-8') as f:
        return f.read().strip()


def collect():
    items = []
    for name in ROOT_FILES:
        p = os.path.join(ROOT, name)
        if os.path.isfile(p):
            items.append((p, name))
    for cur, dirs, files in os.walk(APP):
        dirs[:] = sorted(d for d in dirs if d.lower() not in SKIP_DIRS)
        for f in sorted(files):
            if os.path.splitext(f)[1].lower() in SKIP_EXT or f in SKIP_NAMES:
                continue
            p = os.path.join(cur, f)
            items.append((p, os.path.relpath(p, ROOT).replace('\\', '/')))
    return items


def main():
    ver = read_version()
    items = collect()
    total = sum(os.path.getsize(p) for p, _ in items)
    print('VERSION  =', ver)
    print('FILES    =', len(items), '| RAW = %.1f KB' % (total / 1024))

    if '--check' in sys.argv[1:]:
        bad = [a for _, a in items if '/data/' in a or a.endswith('.log')]
        print('LEAK     =', bad or 'none')
        return 0 if not bad else 1

    os.makedirs(DIST, exist_ok=True)
    dst = os.path.join(DIST, 'DiskGuard-v%s.zip' % ver)
    with zipfile.ZipFile(dst, 'w', zipfile.ZIP_DEFLATED) as z:
        for p, arc in items:
            z.write(p, arc)

    size = os.path.getsize(dst)
    h = hashlib.sha256()
    with open(dst, 'rb') as f:
        for chunk in iter(lambda: f.read(1 << 20), b''):
            h.update(chunk)
    with zipfile.ZipFile(dst) as z:
        names = z.namelist()
        tops = sorted(set(n.split('/')[0] for n in names))
    print('ZIP      =', dst)
    print('SIZE     = %.1f KB (%d bytes)' % (size / 1024, size))
    print('SHA256   =', h.hexdigest())
    print('TOPLEVEL =', tops)
    print('CONTAINS = pet.py %s | page.html %s | sfx %d' % (
        any(n.endswith('scripts/pet.py') for n in names),
        any(n.endswith('scripts/page.html') for n in names),
        sum(1 for n in names if '/assets/sfx/' in n)))
    return 0


if __name__ == '__main__':
    sys.exit(main())
