#-*- coding:utf-8 -*-
import gzip
import hashlib
import os
import socket
import sys
import unittest
import cStringIO

PWD = os.path.dirname(os.path.realpath(__file__))
FOLDER_PARENT = os.path.dirname(PWD)
sys.path.insert(0, FOLDER_PARENT)

import config
import helper


class TestBodyInGzip(unittest.TestCase):

    def test_it(self):
        chunks = [
            'GET http://tools.ietf.org/html/rfc2616.html HTTP/1.1',
            'Host: tools.ietf.org',
            'Accept-Encoding: gzip',
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
        headers = splits[1:]
        cl = helper.Helper.get_header_value_by_name(headers, 'content-length')

        content_encoding = helper.Helper.get_header_value_by_name(headers, 'Content-Encoding')
        using_gzip = True
        if content_encoding.lower().find('gzip') == -1:
            using_gzip = False
        # self.assertNotEqual(content_encoding.lower().find('gzip'), -1)

        if cl is not None:
            body = helper.Helper.recv_all(sock, int(cl))
        else:
            body = ''
            while True:
                chunk  = helper.Helper.read_until(sock, '\r\n')
                if not chunk:
                    break
                splits = chunk.rstrip('\r\n').split(';')
                if len(splits) > 1:
                    chunk_ext_list = splits[1:]
                chunk_size = int(splits[0], 16)
                if chunk_size is 0: # last-chunk
                    sock.recv(2) # skip last CRLF
                    break
                chunk_data = sock.recv(chunk_size)
                if not chunk_data:
                    break
                sock.recv(2) # skip CRLF
                body += chunk_data

        if using_gzip:
            body_got = gzip.GzipFile(fileobj=cStringIO.StringIO(body)).read()
        else:
            body_got = body

        body_expected = file(os.path.join(FOLDER_PARENT, 'html', 'rfc2616.html')).read()

        self.assertEqual(len(body_got), len(body_expected))
        self.assertEqual(hashlib.md5(body_got).hexdigest(), hashlib.md5(body_expected).hexdigest())

if __name__ == '__main__':
    unittest.main()