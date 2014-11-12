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


class TestMethodTimeout(unittest.TestCase):

    def test_method_get(self):
        # Twitter was banned in China by Chinese Great FireWall,
        # any TCP connections should get RST and timeout.
        url = 'http://twitter.com'
        r = requests.head(url=url, proxies=config.proxies, auth=proxy_auth)
        status_code = r.status_code

        self.assertEqual(status_code, httplib.GATEWAY_TIMEOUT)

    def test_method_post(self):
        url = 'http://twitter.com'
        r = requests.head(url=url, proxies=config.proxies, auth=proxy_auth)
        status_code = r.status_code

        self.assertEqual(status_code, httplib.GATEWAY_TIMEOUT)

    def test_method_connect(self):
        url = 'http://twitter.com'
        r = requests.head(url=url, proxies=config.proxies, auth=proxy_auth)
        status_code = r.status_code

        self.assertEqual(status_code, httplib.GATEWAY_TIMEOUT)

if __name__ == "__main__":
    unittest.main()
