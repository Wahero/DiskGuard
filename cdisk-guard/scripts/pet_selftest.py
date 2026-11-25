# -*- coding: utf-8 -*-
"""pet_selftest.py — Phase 1 離線自測入口（薄包裝，實際邏輯在 pet.py --selftest）

    python scripts/pet_selftest.py

長期維護只需改 pet.cmd_selftest；本檔保留獨立入口是為了與既有
cdiskctl.py selftest 的呼叫習慣一致。不啟動 UI、不起服務、不刪檔。
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import pet  # noqa: E402


if __name__ == '__main__':
    sys.exit(pet.cmd_selftest(pet.C.load_config()))
