import unittest
import httplib

import requests
import requests.auth

import config


auth = requests.auth.HTTPBasicAuth(config.username, config.password)
proxy_auth = requests.auth.HTTPProxyAuth(config.proxy_username, config.proxy_password)


class TestAuth(unittest.TestCase):

    def setUp(self):
        url_add_node = config.URL_ADMIN + '/proxy/add?addr=' + config.node_add
        r = requests.get(url=url_add_node, auth=auth)
        assert r.status_code == httplib.OK

    def tearDown(self):
        url_add_node = config.URL_ADMIN + '/proxy/delete?addr=' + config.node_add
        r = requests.get(url=url_add_node, auth=auth)
        assert r.status_code == httplib.OK



class TestProxyAuth(unittest.TestCase):

    def setUp(self):
        url_add_node = config.URL_ADMIN + '/proxy/add?addr=' + config.node_add
        r = requests.get(url=url_add_node, auth=auth)
        assert r.status_code == httplib.OK

    def tearDown(self):
        url_add_node = config.URL_ADMIN + '/proxy/delete?addr=' + config.node_add
        r = requests.get(url=url_add_node, auth=auth)
        assert r.status_code == httplib.OK



if __name__ == "__main__":
    unittest.main()