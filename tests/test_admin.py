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


class TestAdminAuth(unittest.TestCase):

    def test_add_node(self):
        url = 'http://%s:%d/admin/node/add?addr=%s' % (
            config.proxy_host,
            config.proxy_port,
            '127.0.0.1:8080'
        )
        r = requests.get(url=url)
        self.assertEqual(httplib.UNAUTHORIZED, r.status_code)

        r = requests.get(url=url, auth=(config.username, config.password))
        self.assertEqual(httplib.OK, r.status_code)


if __name__ == '__main__':
    unittest.main()