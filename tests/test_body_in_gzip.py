#-*- coding:utf-8 -*-
import httplib
import os
import sys
import unittest

import requests

PWD = os.path.dirname(os.path.realpath(__file__))
FOLDER_PARENT = os.path.dirname(PWD)
sys.path.insert(0, FOLDER_PARENT)

import config


class TestBodyInGzip(unittest.TestCase):

    def test_it(self):
        url = 'http://httpbin.org/gzip'
        r = requests.get(url=url, proxies=config.proxies, timeout=config.timeout)
        status_code = r.status_code
        entry_body = r.json()

        self.assertTrue(entry_body['gzipped'])
        self.assertEqual(entry_body['method'], 'GET')
        self.assertIn('gzip', entry_body['headers']['Accept-Encoding'])
        self.assertEqual(status_code, httplib.OK)
        self.assertTrue(len(entry_body) > 0)

if __name__ == '__main__':
    unittest.main()