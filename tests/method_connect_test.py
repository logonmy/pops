import unittest
import httplib

import requests
import requests.auth

import config


auth = requests.auth.HTTPBasicAuth(config.username, config.password)
proxy_auth = requests.auth.HTTPProxyAuth(config.proxy_username, config.proxy_password)


class TestMethodCONNECT(unittest.TestCase):

    def setUp(self):
        proxy_ip_addr_port_list = ','.join(requests.get(url=config.URL_STAT, auth=auth).json()['proxy_list'].keys())
        if proxy_ip_addr_port_list:
            url_add_node = config.URL_ADMIN + '/node/delete?addr=' + proxy_ip_addr_port_list
            r = requests.get(url=url_add_node, auth=auth)
            assert r.status_code == httplib.OK

        url_add_node = config.URL_ADMIN + '/node/add?addr=' + config.node_add
        r = requests.get(url=url_add_node, auth=auth)
        assert r.status_code == httplib.OK

    def tearDown(self):
        proxy_ip_addr_port_list = ','.join(requests.get(url=config.URL_STAT, auth=auth).json()['proxy_list'].keys())
        if proxy_ip_addr_port_list:
            url_add_node = config.URL_ADMIN + '/node/delete?addr=' + proxy_ip_addr_port_list
            r = requests.get(url=url_add_node, auth=auth)
            assert r.status_code == httplib.OK

    def test_method_head(self):
        url = 'https://github.com'
        r = requests.head(url=url, verify=False, proxies=config.proxies_with_auth)
        status_code = r.status_code
        entry_body = r.text

        self.assertEqual(status_code, httplib.OK)
        self.assertEqual(entry_body, '')

    def test_method_get(self):
        url = 'https://github.com'
        r = requests.get(url=url, verify=False, proxies=config.proxies_with_auth)
        status_code = r.status_code
        entry_body = r.text

        self.assertEqual(status_code, httplib.OK)
        self.assertTrue(len(entry_body))


if __name__ == "__main__":
    unittest.main()
