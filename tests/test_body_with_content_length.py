#-*- coding:utf-8 -*-
import hashlib
import httplib
import os
import socket
import sys
import unittest

PWD = os.path.dirname(os.path.realpath(__file__))
FOLDER_PARENT = os.path.dirname(PWD)
sys.path.insert(0, FOLDER_PARENT)

import config
import helper


class TestBodyWithContentLength(unittest.TestCase):

    def test_it(self):
        chunks = [
            'GET http://tools.ietf.org/html/rfc2616.html HTTP/1.1',
            'Host: tools.ietf.org',
            'Connection: close',
        ]
        req = '\r\n'.join(chunks) + '\r\n' * 2

        sock = socket.socket()
        sock.connect((config.proxy_host, config.proxy_port))
        sock.sendall(req)


        until = '\r\n\r\n'
        data = helper.Helper.read_until(sock, until)

        start_line_headers = data.split(until)[0]
        splits = start_line_headers.split('\r\n')

        start_line = splits[0]
        version, status_code, reason = start_line.split(None, 2)
        status_code = int(status_code)
        self.assertEqual(status_code, httplib.OK)
        self.assertEqual(reason, httplib.responses[httplib.OK])
        self.assertEqual(version, 'HTTP/1.1')

        headers = splits[1:]
        cl = helper.Helper.get_header_value_by_name(headers, 'Content-Length')
        body_got = helper.Helper.recv_all(sock, int(cl))
        body_expected = file(os.path.join(FOLDER_PARENT, 'html', 'rfc2616.html')).read()

        self.assertEqual(len(body_got), len(body_expected))
        self.assertEqual(hashlib.md5(body_got).hexdigest(), hashlib.md5(body_expected).hexdigest())


if __name__ == '__main__':
    unittest.main()