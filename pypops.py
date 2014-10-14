#!/usr/bin/env python
#-*- coding:utf-8 -*-
from BaseHTTPServer import BaseHTTPRequestHandler
import asynchat
import asyncore
import socket
import sys
import urlparse

from pops import HTTPRequest
from pops import HTTPResponse


__version__ = "201410"


class HTTPHelper(object):

    @staticmethod
    def is_proxy_request(s):
        """
        request_uri => 'http://baidu.com'
        parses.scheme => 'http://'
        parses.netloc => 'baidu.com'
        parses.path => '/'

        request_uri => '/index.html'
        parses.scheme => ''
        parses.netloc => ''
        parses.path => '/index.html
        """
        parses = urlparse.urlparse(s)
        return parses.scheme and parses.netloc
        
    @staticmethod    
    def parse_request_uri_from_urlparse(parses):
        request_uri = parses.path or '/'
        if parses.query:
            request_uri += '?' + parses.query
        if parses.fragment:
            request_uri += '#' + parses.fragment                
        return request_uri
    
    @staticmethod
    def parse_addr_from_urlparse(parses):
        splits = parses.netloc.split(':')
        if len(splits) == 2:
            host, port = splits[0], int(splits[1])
        else:
            host, port = splits[0], 80
        return (host, port)


EOL = '\r\n\r\n'


class ProxySender(asynchat.async_chat):

    def __init__(self, proxy_receiver, addr_server):
        asynchat.async_chat.__init__(self)

        self.receiver = proxy_receiver
        self.addr_server = addr_server
        self.addr_server_formatted = ':'.join(str(i) for i in addr_server)

        self.create_socket(socket.AF_INET, socket.SOCK_STREAM)
        self.set_terminator(EOL)
        self.connect(addr_server)

        self.raw_msg = ''
        self.msg_resp = None

    def handle_connect(self):
        print 'connect to', self.addr_server_formatted

    def collect_incoming_data(self, data):
        self.raw_msg += data

    def found_terminator(self):
        terminator = self.get_terminator()

        print 'sender terminator', repr(terminator)

        if isinstance(terminator, basestring):
            self.raw_msg += EOL

            print ' ', repr(self.raw_msg)

            self.msg_resp = HTTPResponse(msg=self.raw_msg)
            cl = self.msg_resp.headers.get_value('Content-Length')
            # if self.receiver.msg_req.method != 'HEAD' and \
            #                 self.msg_resp.status_code >= httplib.OK and \
            #                 self.msg_resp.status_code not in (httplib.NO_CONTENT, httplib.SEE_OTHER, httplib.NOT_MODIFIED):
            #     cl = self.msg_resp.headers.get_value('Content-Length')
            if cl is not None:
                cl = int(cl)
                if cl > 0:
                    self.set_terminator(cl)
                else:
                    self.receiver.push(self.raw_msg)
            elif self.msg_resp.is_chunked():
                raise NotImplementedError
            else:
                self.set_terminator(None)
        elif isinstance(terminator, int) or isinstance(terminator, long):
            if terminator is 0:
                self.receiver.push(self.raw_msg)
            else:
                self.receiver.push(self.raw_msg)
                print 'WARNING: remain %d bytes' % terminator

    def handle_close(self):
        self.receiver.close()
        self.close()


class ProxyReceiver(asynchat.async_chat):
    channel_counter = 0

    def __init__(self, server, (sock_client, addr_client)):
        asynchat.async_chat.__init__ (self, sock_client)

        self.server = server

        self.sock_client = sock_client
        self.addr_client = addr_client
        self.addr_client_formatted = ':'.join(str(i) for i in addr_client)

        self.id = self.channel_counter
        self.channel_counter = self.channel_counter + 1

        self.raw_msg = ''
        self.msg_req = None

        self.set_terminator(EOL)
        self.sender = None

    def collect_incoming_data(self, data):
        self.raw_msg += data

    def found_terminator(self):
        terminator = self.get_terminator()

        print 'receiver terminator:', repr(terminator)

        if isinstance(terminator, basestring):
            self.raw_msg += EOL
            print ' ', repr(self.raw_msg)

            self.msg_req = HTTPRequest(self.raw_msg)

            assert HTTPHelper.is_proxy_request(self.msg_req.request_uri)

            parses = urlparse.urlparse(self.msg_req.request_uri)
            addr = HTTPHelper.parse_addr_from_urlparse(parses)
            self._setup_sender(addr)

            cl = self.msg_req.headers.get_value('Content-Length')
            if cl is not None:
                self.set_terminator(int(cl))
            else:
                self.sender.push(self.raw_msg)

        elif isinstance(terminator, int) or isinstance(terminator, long):
            if terminator is 0:
                self.sender.push(self.raw_msg)
            else:
                self.sender.push(self.raw_msg)
                print 'WARNING: remain %d bytes' % terminator


    def _setup_sender(self, addr):
        self.sender = ProxySender(self, addr)
        self.sender.id = self.id


class HTTPServer(asyncore.dispatcher):

    allow_reuse_address = True
    request_queue_size = 5

    responses = BaseHTTPRequestHandler.responses

    def __init__(self, server_address, RequestHandlerClass):
        asyncore.dispatcher.__init__(self)

        self.RequestHandlerClass = RequestHandlerClass

        self.create_socket(socket.AF_INET, socket.SOCK_STREAM)
        self.set_reuse_addr()
        self.bind(server_address)
        self.listen(self.request_queue_size)

    def serve_forever(self):
        asyncore.loop()

    def handle_accept(self):
        sock_client, addr_client = self.accept()
        addr_client_formatted = ':'.join(str(i) for i in addr_client)
        msg = addr_client_formatted + ' connected'
        print msg

        self.RequestHandlerClass(self, (sock_client, addr_client))


if __name__ == "__main__":
    args = sys.argv[1:]
    if args:
        host, port = args[0], int(args[1])
    else:
        host, port = '', 1080
    server_addr = (host, port)


    httpd = HTTPServer(server_addr, ProxyReceiver)

    sa = httpd.socket.getsockname()
    print "Serving HTTP on", sa[0], "port", sa[1], "..."

    httpd.serve_forever()