#-*- coding:utf-8 -*-
import hashlib
import httplib
import os
import sys
import unittest

PWD = os.path.dirname(os.path.realpath(__file__))
FOLDER_PARENT = os.path.dirname(PWD)
sys.path.insert(0, FOLDER_PARENT)

import requests
import requests.auth
import config
proxy_auth = requests.auth.HTTPProxyAuth(username=config.username, password=config.password)


class TestBodyWithContentLength(unittest.TestCase):

    def test_it(self):
        r = requests.get('http://tools.ietf.org/rfc/rfc7230.txt', timeout=config.timeout, auth=proxy_auth)
        self.assertEqual(r.status_code, httplib.OK)
        self.assertEqual(r.reason, httplib.responses[httplib.OK])

        cl = int(r.headers['content-length'])
        body_got = r.text
        body_expected = file(os.path.join(PWD, 'rfc7230.txt')).read()

        self.assertTrue(cl > 0)
        self.assertEqual(len(body_got), len(body_expected))
        self.assertEqual(hashlib.md5(body_got).hexdigest(), hashlib.md5(body_expected).hexdigest())


if __name__ == '__main__':
    unittest.main()