import unittest
import httplib

import requests
import requests.auth

import config


auth = requests.auth.HTTPBasicAuth(config.username, config.password)
proxy_auth = requests.auth.HTTPProxyAuth(config.proxy_username, config.proxy_password)


class TestAdmin(unittest.TestCase):

    def setUp(self):
        proxy_ip_addr_port_list = ','.join(requests.get(url=config.URL_STAT, auth=auth).json()['proxy_list'].keys())
        if proxy_ip_addr_port_list:
            url_add_node = config.URL_ADMIN + '/node/delete?addr=' + proxy_ip_addr_port_list
            r = requests.get(url=url_add_node, auth=auth)
            assert r.status_code == httplib.OK

    def tearDown(self):
        proxy_ip_addr_port_list = ','.join(requests.get(url=config.URL_STAT, auth=auth).json()['proxy_list'].keys())
        if proxy_ip_addr_port_list:
            url_add_node = config.URL_ADMIN + '/node/delete?addr=' + proxy_ip_addr_port_list
            r = requests.get(url=url_add_node, auth=auth)
            assert r.status_code == httplib.OK


    def test_admin_curd_node(self):
        r = requests.get(url=config.URL_ADMIN + '/node/add?' + 'addr=' + config.node_add, auth=auth)
        self.assertEqual(r.status_code, httplib.OK)

        proxy_ip_addr_port_list = requests.get(url=config.URL_STAT, auth=auth).json()['proxy_list'].keys()
        self.assertEqual(len(proxy_ip_addr_port_list), 1)
        self.assertIn(config.node_add, proxy_ip_addr_port_list)


        # add duplicated record
        r = requests.get(url=config.URL_ADMIN + '/node/add?' + 'addr=' + config.node_add, auth=auth)
        self.assertEqual(r.status_code, httplib.OK)

        proxy_ip_addr_port_list = requests.get(url=config.URL_STAT, auth=auth).json()['proxy_list'].keys()
        self.assertEqual(len(proxy_ip_addr_port_list), 1)
        self.assertIn(config.node_add, proxy_ip_addr_port_list)

        r = requests.get(url=config.URL_ADMIN + '/node/add?' + 'addr=' + config.node_b_add, auth=auth)
        self.assertEqual(r.status_code, httplib.OK)
        proxy_ip_addr_port_list = requests.get(url=config.URL_STAT, auth=auth).json()['proxy_list'].keys()
        self.assertEqual(len(proxy_ip_addr_port_list), 2)
        self.assertIn(config.node_b_add, proxy_ip_addr_port_list)


        r = requests.get(url=config.URL_ADMIN + '/node/delete?' + 'addr=' + config.node_add, auth=auth)
        self.assertEqual(r.status_code, httplib.OK)
        r = requests.get(url=config.URL_ADMIN + '/node/delete?' + 'addr=' + config.node_b_add, auth=auth)
        self.assertEqual(r.status_code, httplib.OK)

        proxy_ip_addr_port_list = requests.get(url=config.URL_STAT, auth=auth).json()['proxy_list'].keys()
        self.assertEqual(len(proxy_ip_addr_port_list), 0)
        self.assertNotIn(config.node_add, proxy_ip_addr_port_list)


    def test_admin_modify_server_settings(self):
        r = requests.get(url=config.URL_STAT, auth=auth)
        self.assertEqual(r.status_code, httplib.OK)

        old_node_check_interval = r.json()['server_settings']['node_check_interval']
        new_node_check_interval = int(old_node_check_interval) + 10

        r = requests.get(url=config.URL_ADMIN + '/server_settings/update?' + 'k=node_check_interval&v=' + str(new_node_check_interval), auth=auth)
        self.assertEqual(r.status_code, httplib.OK)

        r = requests.get(url=config.URL_STAT, auth=auth)
        current_node_check_interval = int(r.json()['server_settings']['node_check_interval'])
        self.assertEqual(r.status_code, httplib.OK)
        self.assertEquals(current_node_check_interval, new_node_check_interval)