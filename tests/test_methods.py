import os
import unittest
import httplib
import sys

PWD = os.path.dirname(os.path.realpath(__file__))
FOLDER_PARENT = os.path.dirname(PWD)
sys.path.insert(0, FOLDER_PARENT)

import requests
import requests.auth
import config

proxy_auth = requests.auth.HTTPProxyAuth(username=config.username, password=config.password)


class TestMethodGET(unittest.TestCase):

    def test_method_head(self):
        url = 'http://tools.ietf.org/html/rfc868.html'
        r = requests.head(url=url, proxies=config.proxies, timeout=config.timeout, auth=proxy_auth)
        status_code = r.status_code
        entry_body = r.text

        self.assertEqual(status_code, httplib.OK)
        self.assertEqual(entry_body, '')

    def test_method_get(self):
        url = 'http://tools.ietf.org/html/rfc868.html'
        r = requests.get(url=url, proxies=config.proxies, timeout=config.timeout, auth=proxy_auth)
        status_code = r.status_code
        entry_body = r.text

        self.assertEqual(status_code, httplib.OK)
        self.assertTrue(len(entry_body))

    def test_method_post(self):
        url = 'http://httpbin.org/post'
        r = requests.post(url=url, data={'foo': 'bar'}, proxies=config.proxies, timeout=config.timeout, auth=proxy_auth)
        status_code = r.status_code
        entry_body = r.json()

        self.assertEqual(status_code, httplib.OK)
        self.assertTrue(entry_body['form']['foo'] == 'bar')

    def test_method_put(self):
        url = 'http://httpbin.org/put'
        r = requests.put(url=url, data={'foo': 'bar'}, proxies=config.proxies, timeout=config.timeout, auth=proxy_auth)
        status_code = r.status_code
        entry_body = r.json()

        self.assertEqual(status_code, httplib.OK)
        self.assertTrue(entry_body['form']['foo'] == 'bar')

class TestMethodCONNECT(unittest.TestCase):

    def test_method_head(self):
        url = 'https://tools.ietf.org/html/rfc868.html'
        r = requests.head(url=url, verify=False, proxies=config.proxies, timeout=config.timeout, auth=proxy_auth)
        status_code = r.status_code
        entry_body = r.text

        self.assertEqual(status_code, httplib.OK)
        self.assertEqual(entry_body, '')

    def test_method_get(self):
        url = 'https://tools.ietf.org/html/rfc868.html'
        r = requests.get(url=url, verify=False, proxies=config.proxies, timeout=config.timeout, auth=proxy_auth)
        status_code = r.status_code
        entry_body = r.text

        self.assertEqual(status_code, httplib.OK)
        self.assertTrue(len(entry_body))

if __name__ == "__main__":
    unittest.main()
