import unittest
import httplib
import httplib2

import requests
import requests.auth

import config


auth = requests.auth.HTTPBasicAuth(config.username, config.password)
proxy_auth = requests.auth.HTTPProxyAuth(config.proxy_username, config.proxy_password)
PROXY_TYPE_HTTP = 3
proxy_info = httplib2.ProxyInfo(proxy_type=PROXY_TYPE_HTTP, proxy_host='127.0.0.1', proxy_port=1080, proxy_user='god', proxy_pass='hidemyass')


class TestMethodCONNECT(unittest.TestCase):

    def setUp(self):
        proxy_ip_addr_port_list = ','.join(requests.get(url=config.URL_STAT, auth=auth).json()['proxy_list'].keys())
        if proxy_ip_addr_port_list:
            url_add_node = config.URL_ADMIN + '/proxy/delete?addr=' + proxy_ip_addr_port_list
            r = requests.get(url=url_add_node, auth=auth)
            assert r.status_code == httplib.OK

        url_add_node = config.URL_ADMIN + '/proxy/add?addr=' + config.node_add
        r = requests.get(url=url_add_node, auth=auth)
        assert r.status_code == httplib.OK

    def tearDown(self):
        proxy_ip_addr_port_list = ','.join(requests.get(url=config.URL_STAT, auth=auth).json()['proxy_list'].keys())
        if proxy_ip_addr_port_list:
            url_add_node = config.URL_ADMIN + '/proxy/delete?addr=' + proxy_ip_addr_port_list
            r = requests.get(url=url_add_node, auth=auth)
            assert r.status_code == httplib.OK

    def test_method_head(self):
        url = 'https://github.com'
        h = httplib2.Http(disable_ssl_certificate_validation=True, proxy_info=proxy_info)
        headers, entry_body = h.request(url, 'HEAD')
        status_code = int(headers['status'])

        self.assertEqual(status_code, httplib.OK)
        self.assertEqual(entry_body, '')

    def test_method_get(self):
        url = 'https://github.com'
        h = httplib2.Http(disable_ssl_certificate_validation=True, proxy_info=proxy_info)
        headers, entry_body = h.request(url, 'GET')
        status_code = int(headers['status'])

        self.assertEqual(status_code, httplib.OK)
        self.assertTrue(len(entry_body))


if __name__ == "__main__":
    unittest.main()
