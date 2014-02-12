import unittest
import httplib

import requests
import requests.auth

import config


auth = requests.auth.HTTPBasicAuth(config.username, config.password)
proxy_auth = requests.auth.HTTPProxyAuth(config.proxy_username, config.proxy_password)


class TestMethodOthers(unittest.TestCase):

    def setUp(self):
        url_add_node = config.URL_ADMIN + '/proxy/add?addr=' + config.node_add
        r = requests.get(url=url_add_node, auth=auth)
        assert r.status_code == httplib.OK

    def tearDown(self):
        url_add_node = config.URL_ADMIN + '/proxy/delete?addr=' + config.node_add
        r = requests.get(url=url_add_node, auth=auth)
        assert r.status_code == httplib.OK

    def test_method_head(self):
        r = requests.head('http://baidu.com', proxies=config.proxies, auth=proxy_auth)
        self.assertEqual(r.status_code, httplib.OK)
        self.assertNotIn('proxy-authenticate', r.headers)
        self.assertEqual(r.text, '')

    def test_method_get(self):
        r = requests.get('http://baidu.com', proxies=config.proxies, auth=proxy_auth)
        self.assertEqual(r.status_code, httplib.OK)
        self.assertNotIn('proxy-authenticate', r.headers)
        self.assertNotEqual(r.text, '')
        self.assertNotEqual(r.text.find('http://www.baidu.com'), -1)


if __name__ == "__main__":
    unittest.main()
