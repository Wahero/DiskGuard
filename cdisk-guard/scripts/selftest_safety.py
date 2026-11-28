#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""DiskGuard 最佳化與刪除安全回歸測試；只使用暫存目錄，不碰使用者檔案。"""
import copy
import json
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import zipfile
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import cdiskctl as C
import dg_common as COM


class SafetyTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix='dg-safety-',
                                    dir=os.environ.get('TEMP'))
        self.out = os.path.join(self.tmp, 'out')
        self.cfg = {
            'drive': 'C:\\', 'drives': ['C:\\'],
            'monitor': {'drives': ['C:\\']},
            'alert': {'threshold_pct': 2.0, 'warn_pct': 10.0},
            'scan': {'max_age_hours': 24, 'top_n': 40, 'big_file_mb': 100},
            'delete': {
                'default_exclusions': [], 'default_tiers': ['A'],
                'small_backup_mb': 100, 'batch_size': 10,
                'allow_direct_delete': True, 'auto_empty_recycle_bin': False,
                'locked_paths': ['$recycle.bin'],
                'special_actions': {'thumbcache_only': ['\\microsoft\\windows\\explorer'],
                                    'empty_recycle_bin': ['$recycle.bin']},
            },
            'paths': {'output_dir': self.out, 'log_filename': 'test.log',
                      'page_filename': 'report.html'},
        }

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _item(self, path, action='direct', nbytes=1234):
        return {'id': 'C-i001', 'drive': 'C:\\', 'letter': 'C',
                'group': 'junk', 'kind': 'temp', 'name': 'test',
                'path': path, 'bytes': nbytes, 'mb': round(nbytes / C.MB, 1),
                'tier': 'A', 'note': '', 'denied': False, 'locked': False,
                'excluded': False, 'nested_in': None, 'action': action,
                'selectable': True, 'default': True}

    def _scan(self):
        return {'created': C.now_str(), 'drive': 'C:\\', 'agg': {},
                'big': [], 'users_found': [], 'junk_paths': {},
                'appdata_paths': {}, 'temp_paths': {},
                'files_seen': 0, 'dirs_seen': 0, 'truncated': False,
                'elapsed_sec': 0.0, 'disk': C.disk_info('C:\\')}

    def test_rmtree_normal_and_reparse_safe(self):
        target = os.path.join(self.tmp, 'tree')
        os.makedirs(os.path.join(target, 'sub'))
        with open(os.path.join(target, 'a.txt'), 'w') as f:
            f.write('a')
        with open(os.path.join(target, 'sub', 'b.txt'), 'w') as f:
            f.write('b')
        removed, errors = C.rmtree_safe(target)
        self.assertGreaterEqual(removed, 2)
        self.assertEqual(errors, 0)
        self.assertFalse(os.path.exists(target))

        external = os.path.join(self.tmp, 'external')
        os.makedirs(external)
        marker = os.path.join(external, 'KEEP.txt')
        with open(marker, 'w') as f:
            f.write('keep')
        target = os.path.join(self.tmp, 'linked-tree')
        os.makedirs(target)
        with open(os.path.join(target, 'delete.txt'), 'w') as f:
            f.write('delete')
        link = os.path.join(target, 'junction')
        try:
            subprocess.run(['cmd', '/c', 'mklink', '/J', link, external],
                           check=True, stdout=subprocess.DEVNULL,
                           stderr=subprocess.DEVNULL)
        except subprocess.CalledProcessError:
            self.skipTest('junction creation not permitted')
        C.rmtree_safe(target)
        self.assertTrue(os.path.exists(marker))
        self.assertFalse(os.path.exists(os.path.join(target, 'delete.txt')))

    def test_backup_unique_names_and_complete(self):
        roots = []
        targets = []
        for i in range(2):
            root = os.path.join(self.tmp, 'root%d' % i)
            os.makedirs(root)
            with open(os.path.join(root, 'same.txt'), 'w') as f:
                f.write('same-%d' % i)
            roots.append(root)
            targets.append(self._item(root, nbytes=10))
        with mock.patch.object(C, 'disk_info', return_value={
                'free_bytes': 10 * C.GB, 'free_gb': 10 * C.GB}):
            result = C.backup_small(self.cfg, targets, 'teststamp')
        self.assertTrue(result['complete'])
        with zipfile.ZipFile(result['path']) as z:
            names = z.namelist()
        self.assertIn('target_0000/same.txt', names)
        self.assertIn('target_0001/same.txt', names)

    def test_incomplete_backup_blocks_delete(self):
        target = os.path.join(self.tmp, 'target')
        os.makedirs(target)
        marker = os.path.join(target, 'KEEP.txt')
        with open(marker, 'w') as f:
            f.write('keep')
        item = self._item(target)
        with mock.patch.object(C, 'backup_small', return_value={
                'complete': False, 'safe_to_continue': False,
                'error_count': 1, 'errors': ['forced']}), \
                mock.patch.object(C, 'recycle_bin_residual', return_value=[]):
            res = C.do_delete(self.cfg, [target], scan=self._scan(),
                              prepared=([item], [], [item]))
        self.assertEqual(res['status'], 'ABORTED')
        self.assertTrue(os.path.exists(marker))

    def test_stale_scan_and_disabled_delete_are_rejected(self):
        target = os.path.join(self.tmp, 'target')
        os.makedirs(target)
        item = self._item(target)
        old = self._scan()
        old['created'] = '2000-01-01 00:00:00'
        with mock.patch.object(C, 'recycle_bin_residual', return_value=[]):
            res = C.do_delete(self.cfg, [target], scan=old,
                              prepared=([item], [], [item]))
        self.assertEqual(res['status'], 'REJECTED')
        self.assertTrue(os.path.exists(target))
        cfg = copy.deepcopy(self.cfg)
        cfg['delete']['allow_direct_delete'] = False
        res = C.do_delete(cfg, [target], scan=self._scan(),
                          prepared=([item], [], [item]))
        self.assertEqual(res['status'], 'REJECTED')
        self.assertTrue(os.path.exists(target))

    def test_direct_delete_and_thumbcache_verification(self):
        target = os.path.join(self.tmp, 'target')
        os.makedirs(target)
        with open(os.path.join(target, 'delete.txt'), 'w') as f:
            f.write('delete')
        item = self._item(target, nbytes=6)
        with mock.patch.object(C, 'recycle_bin_residual', return_value=[]):
            res = C.do_delete(self.cfg, [target], scan=self._scan(),
                              prepared=([item], [], [item]))
        self.assertEqual(res['status'], 'EXECUTED')
        self.assertEqual(res['fully_removed'], 1)
        self.assertFalse(os.path.exists(target))
        self.assertTrue(res['backup']['complete'])
        journal = res['manifest'] + '.outcomes.jsonl'
        self.assertTrue(os.path.exists(journal))
        with open(journal, encoding='utf-8') as f:
            self.assertEqual(len([x for x in f if x.strip()]), 1)
        with open(res['manifest'], encoding='utf-8') as f:
            self.assertEqual(len(json.load(f).get('outcomes') or []), 1)

        thumb = os.path.join(self.tmp, 'thumb')
        os.makedirs(thumb)
        with open(os.path.join(thumb, 'thumbcache_1.db'), 'w') as f:
            f.write('x')
        keep = os.path.join(thumb, 'KEEP.txt')
        with open(keep, 'w') as f:
            f.write('keep')
        item = self._item(thumb, action='thumbcache_only', nbytes=1)
        with mock.patch.object(C, 'recycle_bin_residual', return_value=[]):
            res = C.do_delete(self.cfg, [thumb], scan=self._scan(),
                              prepared=([item], [], [item]))
        self.assertEqual(res['status'], 'EXECUTED')
        self.assertEqual(res['fully_removed'], 1)
        self.assertTrue(os.path.exists(keep))
        self.assertFalse(os.path.exists(os.path.join(thumb, 'thumbcache_1.db')))

    def test_effective_bytes_and_output_overlap(self):
        parent = self._item(os.path.join(self.tmp, 'parent'), nbytes=100)
        child = self._item(os.path.join(self.tmp, 'parent', 'child'), nbytes=40)
        self.assertEqual(C.effective_bytes([parent, child]), 100)
        parent_thumb = dict(parent, action='thumbcache_only')
        self.assertEqual(C.effective_bytes([parent_thumb, child]), 140)

        outroot = os.path.abspath(self.out)
        item = self._item(self.tmp, nbytes=1)
        targets, rejected = C.validate_targets(self.cfg, [self.tmp], [item])
        self.assertFalse(targets)
        self.assertTrue(rejected)
        self.assertEqual(os.path.commonpath([outroot, self.tmp]), self.tmp)

    def test_json_cache_and_atomic_concurrency(self):
        path = os.path.join(self.out, 'state.json')
        COM.atomic_write_json(path, {'v': 1})
        cache = COM.JsonFileCache()
        first = cache.get(path)
        self.assertEqual(first['v'], 1)
        self.assertIs(cache.get(path), first)
        COM.atomic_write_json(path, {'v': 2, 'extra': 'x'})
        self.assertEqual(cache.get(path)['v'], 2)

        errors = []
        def writer(i):
            try:
                COM.atomic_write_json(path, {'writer': i}, durable=False)
            except Exception as exc:
                errors.append(exc)
        threads = [threading.Thread(target=writer, args=(i,)) for i in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertFalse(errors)
        self.assertIn('writer', COM.read_json(path))

    def test_scan_bytes_and_merge_precision(self):
        raw_bytes = 123456789
        scan = self._scan()
        scan['agg'] = {'root': [{'key': ['root', 'Temp'],
                                'bytes': raw_bytes,
                                'mb': round(raw_bytes / C.MB, 1)}]}
        items = C.build_items(self.cfg, scan)
        temp = next(x for x in items if x['name'].lower() == 'temp')
        self.assertEqual(temp['bytes'], raw_bytes)
        self.assertEqual(temp['mb'], round(raw_bytes / C.MB, 1))

        scans = [dict(scan, drive='C:\\'), dict(scan, drive='D:\\')]
        with mock.patch.object(C, 'disk_info', side_effect=[
                {'total_bytes': 1000, 'free_bytes': 400, 'used_bytes': 600,
                 'total_gb': 0.0, 'free_gb': 0.0, 'used_gb': 0.0,
                 'free_pct': 40.0, 'checked_at': ''},
                {'total_bytes': 2000, 'free_bytes': 500, 'used_bytes': 1500,
                 'total_gb': 0.0, 'free_gb': 0.0, 'used_gb': 0.0,
                 'free_pct': 25.0, 'checked_at': ''}]):
            merged = C.merge_scans(scans)
        self.assertEqual(merged['total_bytes'], 3000)
        self.assertEqual(merged['free_bytes'], 900)
        self.assertEqual(merged['used_bytes'], 2100)
        self.assertEqual(merged['free_pct'], 30.0)

    def test_delete_mutex(self):
        self.assertTrue(C._DELETE_LOCK.acquire(blocking=False))
        try:
            res = C.do_delete_multi(self.cfg, [], dry_run=True)
            self.assertEqual(res['status'], 'BUSY')
        finally:
            C._DELETE_LOCK.release()


if __name__ == '__main__':
    unittest.main(verbosity=2)
