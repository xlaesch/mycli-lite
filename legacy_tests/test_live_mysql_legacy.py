# -*- coding: utf-8 -*-
# ruff: noqa
"""Environment-gated live MySQL tests for the universal legacy artifact."""

from __future__ import absolute_import, print_function, unicode_literals

import os
import subprocess
import sys
import unittest

HOST = os.environ.get('MYCLI_LITE_TEST_HOST')
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ARTIFACT = os.path.join(ROOT, 'mycli_lite_legacy.py')
if sys.version_info[0] == 2:
    import imp

    legacy = imp.load_source('mycli_lite_legacy', ARTIFACT)
else:
    import importlib.util

    spec = importlib.util.spec_from_file_location('mycli_lite_legacy', ARTIFACT)
    if hasattr(importlib.util, 'module_from_spec'):
        legacy = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(legacy)
    else:
        legacy = spec.loader.load_module('mycli_lite_legacy')


@unittest.skipUnless(HOST, 'MYCLI_LITE_TEST_HOST is not configured')
class LiveMySQLTests(unittest.TestCase):
    def connect(self, ssl_mode):
        return legacy.connect(
            host=HOST,
            port=int(os.environ.get('MYCLI_LITE_TEST_PORT', '3306')),
            user=os.environ.get('MYCLI_LITE_TEST_USER', 'root'),
            password=os.environ.get('MYCLI_LITE_TEST_PASSWORD', ''),
            database=os.environ.get('MYCLI_LITE_TEST_DATABASE') or None,
            ssl_mode=ssl_mode,
            get_server_public_key=True,
        )

    def test_caching_sha2_rsa_and_multiple_results(self):
        connection = self.connect('disabled')
        try:
            results = connection.query('SELECT VERSION(), CURRENT_USER(), DATABASE(); SELECT 1;')
        finally:
            connection.close()

        self.assertEqual(len(results), 2)
        self.assertTrue(results[0].has_rows)
        self.assertEqual(len(results[0].rows[0]), 3)
        self.assertEqual(results[1].rows, [('1',)])

    def test_required_tls(self):
        connection = self.connect('required')
        try:
            results = connection.query('SELECT 1;')
            self.assertTrue(connection.secure)
            self.assertTrue(connection.tls_version)
        finally:
            connection.close()
        self.assertEqual(results[0].rows, [('1',)])

    def test_batch_cli(self):
        command = [
            sys.executable,
            '-B',
            '-E',
            '-s',
            '-S',
            ARTIFACT,
            '--host',
            HOST,
            '--port',
            os.environ.get('MYCLI_LITE_TEST_PORT', '3306'),
            '--user',
            os.environ.get('MYCLI_LITE_TEST_USER', 'root'),
            '--password-env',
            'MYCLI_LITE_TEST_PASSWORD',
            '--database',
            os.environ.get('MYCLI_LITE_TEST_DATABASE', 'mycli_test'),
            '--ssl-mode',
            'disabled',
            '--get-server-public-key',
            '--format',
            'tsv',
            '--skip-column-names',
            '--execute',
            'SELECT 1;',
        ]
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = process.communicate()
        self.assertEqual(process.returncode, 0, stderr.decode('utf-8', 'replace'))
        self.assertEqual(stdout, b'1\n')


if __name__ == '__main__':
    unittest.main()
