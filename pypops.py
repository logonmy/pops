#!/usr/bin/env python
#-*- coding:utf-8 -*-
from BaseHTTPServer import BaseHTTPRequestHandler
from BaseHTTPServer import _quote_html
import argparse
import asynchat
import asyncore
import httplib
import multiprocessing
import os
import socket
import sys
import urlparse

try:
    from daemon import runner
except ImportError:
    if sys.platform in ['linux2', 'darwin']:
        raise ImportError

from pops import HTTPRequest
from pops import HTTPResponse


__version__ = "201410"


format_addr = lambda addr : ':'.join(str(i) for i in addr)

DEFAULT_ERROR_MESSAGE = """\
<head>
<title>Error response</title>
</head>
<body>
<h1>Error response</h1>
<p>Error code %(code)d.
<p>Message: %(message)s.
<p>Error code explanation: %(code)s = %(explain)s.
</body>
"""
DEFAULT_ERROR_CONTENT_TYPE = "text/html"

responses = BaseHTTPRequestHandler.responses


class StringHelper(object):
    MAX_LEN = 280

    @staticmethod
    def cut_long_str_for_human(s):
        s_len = len(s)
        if s_len <= StringHelper.MAX_LEN:
            return s
        else:
            CONTEXT_LEN = 20
            prefix = s[:StringHelper.MAX_LEN - CONTEXT_LEN]
            suffix = s[StringHelper.MAX_LEN - CONTEXT_LEN:]
            return prefix +\
                   '%s...< %d bytes >...%s' % (suffix[:CONTEXT_LEN/2], len(suffix) - CONTEXT_LEN, suffix[-CONTEXT_LEN/2:])


def generate_resp(code, reason=None, body=None, protocol_version='HTTP/1.1'):
    try:
        short, long = responses[code]
    except KeyError:
        short, long = '???', '???'
    if reason is None:
        reason = short
    explain = long

    body = (DEFAULT_ERROR_MESSAGE %
               {'code': code, 'message': _quote_html(reason), 'explain': explain})

    lines = '\r\n'.join([
        "%s %d %s" % (protocol_version, code, reason),
        "Content-Type: %s" % DEFAULT_ERROR_CONTENT_TYPE,
        'Content-Length: %d' % len(body),
        'Connection: close'
    ])
    msg = lines + EOL + body
    return msg


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
        self.server = proxy_receiver.server

        self.addr_server = addr_server
        self.addr_server_formatted = ':'.join(str(i) for i in addr_server)

        self.create_socket(socket.AF_INET, socket.SOCK_STREAM)
        self.set_terminator(EOL)
        self.connect(addr_server)

        self.raw_msg = ''
        self.msg_resp = None

    def handle_connect(self):
        if self.server.args.verbose:
            print >>sys.stdout, 'connect to', self.addr_server_formatted

    def collect_incoming_data(self, data):
        self.raw_msg += data

    def found_terminator(self):
        terminator = self.get_terminator()

        if self.server.args.verbose:
            print >>sys.stdout, 'sender terminator', repr(terminator)

        if isinstance(terminator, basestring):
            self.raw_msg += EOL

            if self.server.args.verbose:
                print >>sys.stdout, ' ', repr(StringHelper.cut_long_str_for_human(self.raw_msg))

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
            self.msg_resp = HTTPResponse(msg=self.raw_msg)

            if self.server.args.verbose:
                print >>sys.stdout, ' ', repr(StringHelper.cut_long_str_for_human(self.raw_msg))

            if terminator is 0:
                self.receiver.push(self.raw_msg)
            else:
                self.receiver.push(self.raw_msg)
                print >>sys.stderr, 'WARNING: %s received bytes less than expected, remain %d bytes in server' % (self, terminator)

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

        if self.server.args.verbose:
            print >>sys.stdout, 'receiver terminator:', repr(terminator)

        if isinstance(terminator, basestring):
            self.raw_msg += EOL

            if self.server.args.verbose:
                print >>sys.stdout, ' ', repr(StringHelper.cut_long_str_for_human(self.raw_msg))

            self.msg_req = HTTPRequest(self.raw_msg)

            if not HTTPHelper.is_proxy_request(self.msg_req.request_uri):
                msg = generate_resp(code=httplib.BAD_REQUEST)
                self.push(msg)
                return

            parses = urlparse.urlparse(self.msg_req.request_uri)
            addr = HTTPHelper.parse_addr_from_urlparse(parses)
            self._setup_sender(addr)

            cl = self.msg_req.headers.get_value('Content-Length')
            if cl is not None:
                self.set_terminator(int(cl))
            else:
                self.sender.push(self.raw_msg)

        elif isinstance(terminator, int) or isinstance(terminator, long):
            if self.server.args.verbose:
                print >>sys.stdout, ' ', repr(StringHelper.cut_long_str_for_human(self.raw_msg))

            self.msg_req = HTTPRequest(self.raw_msg)

            # translate absoluteURI to abs_path
            parses = urlparse.urlparse(self.msg_req.request_uri)
            request_uri = HTTPHelper.parse_request_uri_from_urlparse(parses)
            first_line = self.msg_req.method + ' ' + request_uri + ' ' + self.msg_req.version
            lines = [first_line]
            for item in self.msg_req.headers.headers:
                line = '%s: %s' % (item[0], item[1])
                lines.append(line)
            msg = '\r\n'.join(lines) + EOL + self.msg_req.body or ''

            if terminator is 0:
                self.sender.push(msg)
            else:
                self.sender.push(msg)
                print 'WARNING: remain %d bytes' % terminator
                print >>sys.stderr, 'WARNING: %s received bytes less than expected, remain %d bytes in client' % (self, terminator)


    def _setup_sender(self, addr):
        self.sender = ProxySender(self, addr)
        self.sender.id = self.id


class HTTPServer(asyncore.dispatcher):

    allow_reuse_address = True
    request_queue_size = 5

    args = None

    def __init__(self, server_address, RequestHandlerClass):
        asyncore.dispatcher.__init__(self)

        self.RequestHandlerClass = RequestHandlerClass

        self.create_socket(socket.AF_INET, socket.SOCK_STREAM)
        self.set_reuse_addr()
        self.bind(server_address)
        self.listen(self.request_queue_size)

    def serve_forever(self):
        asyncore.loop()

    def server_close(self):
        self.close()

    def handle_accept(self):
        sock_client, addr_client = self.accept()

        if self.args.verbose:
            addr_client_formatted = ':'.join(str(i) for i in addr_client)
            msg = addr_client_formatted + ' connected'
            print >>sys.stdout, msg

        self.RequestHandlerClass(self, (sock_client, addr_client))

        
class MyDaemon(object):
    def __init__(self, args):
        self.args = args

        self.stdin_path = os.devnull
        self.stdout_path = os.devnull
        self.stderr_path = args.error_log or os.devnull
        self.pidfile_path = args.pid
        self.pidfile_timeout = 3

    def run(self):
        main(self.args)


def serve_forever(httpd_inst):
    try:
        print >> sys.stdout, '%s started' % multiprocessing.current_process().name
        httpd_inst.serve_forever()
    finally:
        httpd_inst.server_close()

def main(args):
    server_address = (args.addr, args.port)
    
    pid = os.getpid()

    httpd_inst = HTTPServer(server_address, ProxyReceiver)
    httpd_inst.args = args

    if httpd_inst.args.mode == 'node':
        srv_name = 'node'
    else:
        srv_name = 'slot'
    print >> sys.stdout, "POPS %s started, listen on %s:%s, pid %d" % (srv_name, server_address[0], server_address[1], pid)
    try:
        httpd_inst.serve_forever()
    finally:
        httpd_inst.server_close()

if __name__ == "__main__":
    multiprocessing.freeze_support()

    parser = argparse.ArgumentParser(prog=sys.argv[0], description='POPS', version=__version__)

    parser.add_argument('--auth',
                        default='god:hidemyass',
                        help='default god:hidemyass')

    parser.add_argument('--proxy_auth',
                        default='god:hidemyass',
                        help='default god:hidemyass')

    parser.add_argument('--proxy_node_auth',
                        default='god:hidemyass',
                        help='default god:hidemyass')

    parser.add_argument('--addr',
                        default='127.0.0.1',
                        help='default 127.0.0.1')

    parser.add_argument('--port',
                        type=int,
                        default=1080,
                        help='default 1080')

    parser.add_argument('--mode',
                        choices=['slot', 'node'],
                        default='node',
                        help='default node')

    parser.add_argument('--verbose',
                        action='store_true',
                        help='dump headers of request and response into stdout, it requires --processes=0')

    parser.add_argument('--http1.0',
                        action='store_true',
                        help='dump entry body of request and response into stdout, it requires --verbose')

    parser.add_argument('--error_log',
                        help='default /dev/null')

    parser.add_argument('--pid')

    parser.add_argument('--daemon', action='store_true')

    parser.add_argument('--stop',
                        action='store_true',
                        help='default start')

    args = parser.parse_args()

    if args.daemon or args.stop:
        if sys.platform not in ['linux2', 'darwin']:
            print >>sys.stderr, "This program could runs as daemon on linux and darwin only."
            sys.exit(1)

        if not args.pid:
            print >>sys.stderr, "You must set `--pid /path/to/pid` for `--daemon`.\n"
            sys.exit(1)

        if args.stop:
            action = 'stop'
        else:
            action = 'start'

        class MyDaemonRunner(runner.DaemonRunner):
            def __init__(self, app, action):
                self.action = action
                runner.DaemonRunner.__init__(self, app)

            def parse_args(self, *args, **kwargs): pass

        d_runner = MyDaemonRunner(MyDaemon(args), action)
        d_runner.do_action()
    else:
        main(args)
