#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""DiskGuard 啟動器 —— 給 start_pet.cmd / start_guard.cmd 呼叫。

為什麼需要這個檔：
兩個 .cmd 原本直接 `start "" pythonw.exe ...`，但 pythonw 沒有主控台，行程一但
自己決定退出（最常見是 watch.lock 被另一個模式佔住），使用者只看到視窗一閃就消失，
而 cmd 還照樣印「started」——等於什麼都沒說。本檔用 python.exe 執行（有主控台），
負責：

  1. 先查鎖：現在是誰在跑、什麼模式；同模式就明說「已在執行」直接結束
  2. 不同模式 → 詢問是否接手（預設不動，避免誤殺）
  3. 接手：桌寵送 WM_CLOSE 讓它自己收尾，背景守護直接終止
  4. 用 pythonw 分離啟動，等最多 5 秒確認真的拿到鎖；失敗就把日誌尾巴印出來

用法：
  python scripts\\launch.py pet       啟動桌寵
  python scripts\\launch.py guard     啟動背景守護
  python scripts\\launch.py stop      停止目前執行中的 DiskGuard
  python scripts\\launch.py status    只看狀態（不啟動任何東西）
"""
import os
import sys
import time
import subprocess

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)

import cdiskctl as C   # noqa: E402

ROOT = os.path.dirname(HERE)
PET = os.path.join(HERE, 'pet.py')
CTL = os.path.join(HERE, 'cdiskctl.py')

MODES = {
    'pet': ('桌寵', PET, []),
    'guard': ('背景守護', CTL, ['watch']),
}

DETACHED = 0x00000008          # DETACHED_PROCESS
NEW_GROUP = 0x00000200         # CREATE_NEW_PROCESS_GROUP
YES = False                    # --yes：不詢問，直接接手


def say(msg=''):
    print(msg, flush=True)


def pythonw():
    """優先找同目錄的 pythonw.exe（無主控台）；找不到就退回目前解譯器。"""
    cand = os.path.join(os.path.dirname(sys.executable), 'pythonw.exe')
    return cand if os.path.exists(cand) else sys.executable


def interactive():
    try:
        return sys.stdin is not None and sys.stdin.isatty()
    except Exception:
        return False


def ask(prompt, default=False):
    if YES:
        say('%s y（--yes）' % prompt.rstrip())
        return True
    if not interactive():
        say('（非互動環境，預設不接手；要強制接手請加 --yes）')
        return default
    try:
        ans = input(prompt).strip().lower()
    except (EOFError, KeyboardInterrupt):
        say()
        return default
    if not ans:
        return default
    return ans in ('y', 'yes', '是', '好')


def tail_log(cfg, n=12):
    p = os.path.join(C.out_dir(cfg), cfg['paths']['log_filename'])
    try:
        with open(p, encoding='utf-8', errors='replace') as f:
            lines = f.readlines()[-n:]
    except Exception:
        return []
    return [ln.rstrip() for ln in lines]


MODE_LABEL = {'pet': '桌寵', 'guard': '背景守護', 'watch': '背景守護'}


def describe(owner):
    if not owner:
        return '無'
    label = MODE_LABEL.get(str(owner.get('mode')), str(owner.get('mode')))
    return '%s（PID %s）' % (label, owner.get('pid'))


def show_status(cfg):
    own = C.read_lock_owner(cfg)
    busy = C.lock_is_busy(cfg)
    d = C.disk_info(cfg['drive'])
    say('DiskGuard 狀態')
    say('  C: 剩 %.2f GB（%.2f%%）' % (d['free_gb'], d['free_pct']))
    if busy and own:
        say('  執行中：%s' % describe(own))
        say('          啟動於 %s' % owner_time(own))
    elif busy:
        say('  執行中：有行程佔用鎖，但讀不到擁有者紀錄')
    else:
        say('  執行中：無（桌寵與背景守護都沒在跑）')
    say('  桌寵視窗：%s' % ('有' if _pet_window() else '無'))
    return 0


def owner_time(owner):
    return str(owner.get('started_at') or '-')


def _pet_window():
    """有沒有可見的 DiskGuardPetClass 視窗（確認桌寵真的畫出來了）。"""
    import ctypes
    from ctypes import wintypes
    u = ctypes.WinDLL('user32', use_last_error=True)
    hit = []

    @ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)
    def cb(h, _l):
        cls = ctypes.create_unicode_buffer(64)
        u.GetClassNameW(h, cls, 64)
        if cls.value == 'DiskGuardPetClass' and u.IsWindowVisible(h):
            hit.append(h)
        return True

    u.EnumWindows(cb, 0)
    return hit


def launch(cfg, mode):
    label, script, args = MODES[mode]
    proc = subprocess.Popen(
        [pythonw(), script] + args,
        cwd=ROOT, stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        creationflags=DETACHED | NEW_GROUP, close_fds=True)
    # 等它拿到鎖（同時看有沒有提早退出）
    for _ in range(50):
        time.sleep(0.1)
        own = C.read_lock_owner(cfg) or {}
        if own.get('pid') == proc.pid and C.lock_is_busy(cfg):
            return True, proc.pid
        if proc.poll() is not None:
            return False, proc.pid
    return False, proc.pid


def cmd_start(cfg, mode):
    label = MODES[mode][0]
    own = C.read_lock_owner(cfg)
    busy = C.lock_is_busy(cfg)
    if busy:
        if own and own.get('mode') == mode:
            say('%s 已經在執行（PID %s），不重複啟動。' % (label, own.get('pid')))
            return 0
        if own:
            say('目前執行中的是「%s」。' % describe(own))
        else:
            say('有一個 DiskGuard 行程佔用著鎖，但讀不到它的 PID。')
        say('桌寵與背景守護共用一把鎖，同時只能有一個。')
        if not ask('要停止它並改開「%s」嗎？[y/N] ' % label):
            say('已取消，沒有做任何變更。')
            return 1
        ok, why = C.stop_owner(cfg, own)
        if not ok:
            say('停不下來：%s' % why)
            say('請手動到工作管理員結束 pythonw.exe，或登出後重試。')
            return 1
        say('已停止（%s）。' % why)
        for _ in range(60):
            if not C.lock_is_busy(cfg):
                break
            time.sleep(0.1)
        else:
            say('鎖仍未釋放，啟動中止。請等幾秒後重試。')
            return 1
    say('正在啟動%s…' % label)
    ok, pid = launch(cfg, mode)
    if ok:
        say('已啟動：%s（PID %s）' % (label, pid))
        if mode == 'pet':
            for _ in range(25):          # 視窗建立比拿鎖慢一點，最多再等 2.5 秒
                if _pet_window():
                    break
                time.sleep(0.1)
            if _pet_window():
                say('桌寵已出現在上次的位置；左鍵看用量，右鍵開選單。')
            else:
                say('（提示：還沒看到桌寵視窗，可能被上次的「隱藏」設定藏起來了）')
        else:
            say('背景守護已接手，不會出現視窗（這是正常的）。')
        return 0
    say('啟動失敗：行程 %s 沒有在 5 秒內取得執行鎖。' % (pid or '?'))
    say('--- 日誌最後幾行 ---')
    for ln in tail_log(cfg):
        say('  ' + ln)
    say('--- 結束 ---')
    say('可先跑一次  python scripts\\pet.py --health  看狀態。')
    return 1


def cmd_stop(cfg):
    own = C.read_lock_owner(cfg)
    if not own and not C.lock_is_busy(cfg):
        say('目前沒有 DiskGuard 在執行。')
        return 0
    if not own:
        say('有行程佔用鎖但讀不到擁有者，無法安全停止。')
        say('請到工作管理員結束 pythonw.exe。')
        return 1
    say('正在停止 %s…' % describe(own))
    ok, why = C.stop_owner(cfg, own)
    if ok:
        say('已停止（%s）。' % why)
        return 0
    say('停止失敗：%s' % why)
    return 1


def main(argv=None):
    global YES
    argv = list(sys.argv[1:] if argv is None else argv)
    YES = any(a in ('--yes', '-y') for a in argv)
    rest = [a for a in argv if a not in ('--yes', '-y')]
    action = (rest[0] if rest else 'status').lower()
    try:
        cfg = C.load_config()
    except Exception as ex:
        say('讀取設定失敗：%s' % ex)
        say('請確認 cdisk-guard\\config.json 存在且格式正確。')
        return 1
    if action == 'status':
        return show_status(cfg)
    if action in MODES:
        return cmd_start(cfg, action)
    if action in ('stop', 'quit'):
        return cmd_stop(cfg)
    say('用法：launch.py [pet|guard|stop|status]')
    return 2


if __name__ == '__main__':
    sys.exit(main())
