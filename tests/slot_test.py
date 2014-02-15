import unittest
import httplib
import multiprocessing

import requests
import requests.auth

import config


auth = requests.auth.HTTPBasicAuth(config.username, config.password)
proxy_auth = requests.auth.HTTPProxyAuth(config.proxy_username, config.proxy_password)


class TestSlot(unittest.TestCase):

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

    def test_slot_one_node_method_head(self):
        r = requests.head('http://baidu.com', proxies=config.proxies, auth=proxy_auth)
        self.assertEqual(r.status_code, httplib.SERVICE_UNAVAILABLE)

        url_add_node = config.URL_ADMIN + '/node/add?addr=' + config.node_add
        r = requests.get(url=url_add_node, auth=auth)
        self.assertEqual(r.status_code, httplib.OK)

        r = requests.head('http://baidu.com', proxies=config.proxies, auth=proxy_auth)
        self.assertEqual(r.status_code, httplib.OK)

    def test_slot_one_node_method_get(self):
        r = requests.get('http://baidu.com', proxies=config.proxies, auth=proxy_auth)
        self.assertEqual(r.status_code, httplib.SERVICE_UNAVAILABLE)

        url_add_node = config.URL_ADMIN + '/node/add?addr=' + config.node_add
        r = requests.get(url=url_add_node, auth=auth)
        self.assertEqual(r.status_code, httplib.OK)

        r = requests.get('http://baidu.com', proxies=config.proxies, auth=proxy_auth)
        self.assertEqual(r.status_code, httplib.OK)

    def test_slot_multiple_nodes(self):
        r = requests.head('http://baidu.com', proxies=config.proxies, auth=proxy_auth)
        self.assertEqual(r.status_code, httplib.SERVICE_UNAVAILABLE)

        r = requests.get('http://baidu.com', proxies=config.proxies, auth=proxy_auth)
        self.assertEqual(r.status_code, httplib.SERVICE_UNAVAILABLE)

        url_add_node = config.URL_ADMIN + '/node/add?addr=' + config.node_add
        r = requests.get(url=url_add_node, auth=auth)
        self.assertEqual(r.status_code, httplib.OK)

        url_add_node = config.URL_ADMIN + '/node/add?addr=' + '192.168.1.255:8080'
        r = requests.get(url=url_add_node, auth=auth)
        self.assertEqual(r.status_code, httplib.OK)

        pool = []
        p_lock = multiprocessing.Lock()
        mp_manager = multiprocessing.Manager()
        stat = mp_manager.dict({httplib.OK: 0, httplib.SERVICE_UNAVAILABLE: 0})
        for i in xrange(4):
            p = multiprocessing.Process(target=TestSlot._test_get, kwargs={'self': self, 'lock': p_lock, 'stat': stat})
            pool.append(p)
        [p.start() for p in pool]
        [p.join() for p in pool]

        self.assertEqual(stat[httplib.OK], 1)
        self.assertEqual(stat[httplib.SERVICE_UNAVAILABLE], 3)

    @staticmethod
    def _test_get(self, lock, stat):
        r = requests.get('http://baidu.com', proxies=config.proxies, auth=proxy_auth)
        lock.acquire()
        stat[r.status_code] += 1
        lock.release()



if __name__ == "__main__":
    unittest.main()
