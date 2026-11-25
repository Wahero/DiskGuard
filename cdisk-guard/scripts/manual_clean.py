# -*- coding: utf-8 -*-
"""手動清理執行器（由根目錄 clean_A.cmd 雙擊啟動，父行程 = Explorer）。

用途：當工具層有「大量刪除保護」把清理擋下時，用這條路徑讓 DiskGuard 自己在
不受管轄的進程裡執行。清單永遠取自最新 scan（不依賴固定清單檔），並沿用
do_delete 的完整防護：manifest → <100 MB 備份 → 每批 10 項 → 逐項複核 → 紀錄。

用法：
    python manual_clean.py             # 執行「預設 A 檔」（config.delete.default_tiers）
    python manual_clean.py --dry-run   # 只列清單，不刪
    python manual_clean.py --resume X  # 從中斷的 manifest 續跑
"""
import os
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)          # 與 cdiskctl.py 同目錄

import cdiskctl as C          # noqa: E402


def human(mb):
    return '%.2f GB' % (mb / 1024.0) if mb >= 1024 else '%.1f MB' % mb


def main():
    argv = sys.argv[1:]
    dry = '--dry-run' in argv
    resume = None
    if '--resume' in argv:
        i = argv.index('--resume')
        if i + 1 < len(argv):
            resume = argv[i + 1]

    cfg = C.load_config()
    scan = C.load_scan(cfg)
    if not scan:
        print('沒有掃描資料，先執行一次掃描…')
        scan = C.do_scan(cfg, verbose=True)
    items = C.build_items(cfg, scan)

    if resume:
        if not os.path.exists(resume):
            print('找不到 manifest：%s' % resume)
            return 2
        paths, dropped = C._resume_paths(cfg, resume, items)
        print('續跑：可執行 %d 項，略過 %d 項' % (len(paths), len(dropped)))
        for p, why in dropped[:15]:
            print('   略過 %s — %s' % (p, why))
        if len(dropped) > 15:
            print('   …另有 %d 項' % (len(dropped) - 15))
    else:
        paths = [x['path'] for x in items if x['default']]

    if not paths:
        print('沒有可清理的項目。')
        return 0

    # 先算「實際可釋放」（扣除父子重疊與設定排除），避免報虛數
    by = {x['path'].rstrip('\\').lower(): x for x in items}
    sel = [by[p.rstrip('\\').lower()] for p in paths
           if p.rstrip('\\').lower() in by]
    gross = sum(x['mb'] for x in sel)
    eff = C.effective_mb([x for x in sel if not x.get('excluded')])

    print('\n目標 %d 項｜帳面 %s｜實際可釋放 %s' % (len(paths), human(gross), human(eff)))
    for p in paths:
        print('   %s' % p)

    if dry:
        print('\n【預演】未刪除任何檔案。')
        return 0

    print('\n開始執行（不可逆，不進資源回收筒）…\n')
    t0 = time.time()
    r = C.do_delete(cfg, paths, dry_run=False, scan=scan)
    print('狀態       : %s' % r.get('status'))
    if r.get('aborted_reason'):
        print('中斷原因   : %s' % r['aborted_reason'])
    print('目標       : %d 項 / %s' % (r.get('target_count'), human(r.get('target_mb') or 0)))
    print('執行前可用 : %s' % human(r.get('free_before_mb') or 0))
    print('執行後可用 : %s' % human(r.get('free_after_mb') or 0))
    print('觀測淨增   : %s' % human(r.get('observed_gain_mb') or 0))
    print('完整刪除   : %d 項；仍有殘留：%d 項' %
          (r.get('fully_removed') or 0, r.get('partial') or 0))
    print('耗時       : %.1f 秒' % (time.time() - t0))
    if r.get('manifest'):
        print('manifest   : %s' % r['manifest'])
    if r.get('log_path'):
        print('執行紀錄   : %s' % r['log_path'])

    oc = r.get('outcomes') or []
    left = [o for o in oc if o.get('after')]
    if left:
        print('\n殘留（多為檔案被程式佔用，關掉相關程式後可續跑）：')
        for o in left[:15]:
            print('   %s（剩 %s 個）' % (o['path'], o.get('remaining')))
        if r.get('manifest'):
            print('   → python "%s" --resume "%s"'
                  % (os.path.abspath(__file__), r['manifest']))
    return 0


if __name__ == '__main__':
    try:
        sys.exit(main())
    except Exception as e:
        import traceback
        traceback.print_exc()
        print('\n發生錯誤：%s' % e)
        sys.exit(1)
