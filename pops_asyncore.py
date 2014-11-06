"""
Rewritten pops in asyncore and asyncore_patch.

See also:
 - http://bugs.python.org/issue6692
 - https://github.com/shuge/asyncore_patch
"""
from BaseHTTPServer import BaseHTTPRequestHandler
from BaseHTTPServer import _quote_html
import StringIO
import argparse
import asyncore_patch; asyncore_patch.patch_all()
import errno

import asyncore
import asynchat
import gzip
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

__version__ = "201411"


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


class HTTPHeadersCaseSensitive(object):
    """
    I would like to keep it as origin in case sensitive,
    although RFC2616 said 'Field names are case-insensitive.'
    http://tools.ietf.org/html/rfc2616#section-4.2
    """

    # http://www.mnot.net/blog/2011/07/11/what_proxies_must_do
    HOP_BY_HOP_HEADERS = (
        'Connection',
        'TE',
        'Transfer-Encoding',
        'Keep-Alive',
        'Proxy-Authorization',
        'Proxy-Authentication',
        'Trailer',
        'Upgrade',
    )

    def __init__(self, lines, ignores=None):
        self.headers = []
        self.parse_headers(lines, ignores)

    @staticmethod
    def contains(iterable, element):
        for i in iterable:
            if i.lower() == element:
                return True
        return False

    def _merge_field_value(self, k, v):
        for item in self.headers:
            if item[0].lower() == k.lower():
                item[1] = item[1] + ', ' + v
                break

    def parse_headers(self, lines, ignores=None):
        field_name_list = set()
        for line in lines:
            first_semicolon = line.index(':')
            k, v = line[:first_semicolon], line[first_semicolon + 1:].strip()
            k_lower = k.lower()

            if ignores and HTTPHeadersCaseSensitive.contains(ignores, k_lower):
                continue

            if k_lower in field_name_list:
                self._merge_field_value(k, v)
            else:
                field_name_list.add(k.lower())
                item = [k, v]
                self.headers.append(item)

    def get_value(self, name, default=None):
        for item in self.headers:
            if item[0].lower() == name.lower():
                value = item[1]
                return value or default
        return default

    def filter_headers(self, headers):
        field_name_list = set()
        new_headers = []

        for item in self.headers:
            name = item[0].lower()
            if not HTTPHeadersCaseSensitive.contains(headers, name):
                field_name_list.add(name)
                new_headers.append(item)
        self.headers = new_headers

    def add_header(self, name, value, override=False):
        for item in self.headers:
            if item[0].lower() == name.lower():
                if override:
                    item[1] = value
                else:
                    item[1] += ', ' + value
                return
        item = (name, value)
        self.headers.append(item)


class HTTPMessage(object):
    def __init__(self, msg, ignores_headers=None):
        self.raw = msg
        self.first_line = None
        self.headers = None
        self.body = None
        if not ignores_headers:
            ignores_headers = []
        self.parse_msg(ignores_headers)

    def parse_first_line(self):
        pass

    def parse_msg(self, ignores_headers):
        splits = self.raw.split('\r\n\r\n')
        if len(splits) == 2:
            first_line_headers, self.body = splits[0], splits[1]
        else:
            first_line_headers = splits[0]

        lines = [i for i in first_line_headers.split('\r\n') if i]
        self.first_line = lines[0]
        self.headers = HTTPHeadersCaseSensitive(lines=lines[1:], ignores=ignores_headers)

    def is_chunked(self):
        cl = self.headers.get_value('Content-Length')
        te = self.headers.get_value('Transfer-Encoding')
        return cl is None and te and te.lower() == 'chunked'

    def __str__(self):
        lines = [self.first_line]
        for item in self.headers.headers:
            lines.append('%s: %s' % (item[0], item[1]))
        body = self.body or ''
        msg = '\r\n'.join(lines) + '\r\n\r\n' + body
        return msg


class HTTPRequest(HTTPMessage):
    def __init__(self, msg):
        super(HTTPRequest, self).__init__(msg=msg)

        self.method = None
        self.request_uri = None
        self.version = None
        self.parse_first_line()

    def parse_first_line(self):
        method, request_uri, version = self.first_line.split(None, 2)
        self.method = method
        self.request_uri = request_uri
        self.version = version


class HTTPResponse(HTTPMessage):
    def __init__(self, msg):
        super(HTTPResponse, self).__init__(msg=msg)

        self.version = None
        self.status_code = None
        self.reason = None
        self.parse_first_line()

    def parse_first_line(self):
        version, status_code, reason = self.first_line.split(None, 2)
        self.version = version
        self.status_code = int(status_code)
        self.reason = reason


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


def generate_resp(code,
                  reason=None,
                  headers=None,
                  body=None,
                  using_body_template=False,
                  close_it=False,
                  protocol_version='HTTP/1.1'):
    try:
        short, long = responses[code]
    except KeyError:
        short, long = '???', '???'
    if reason is None:
        reason = short
    explain = long

    status_line = "%s %d %s" % (protocol_version, code, reason)

    if not body and using_body_template and code != httplib.OK:
        body = (DEFAULT_ERROR_MESSAGE %
               {'code': code, 'message': _quote_html(reason), 'explain': explain})
    else:
        body = ''

    if body:
        other_headers = [
            "Content-Type: %s" % DEFAULT_ERROR_CONTENT_TYPE,
            'Content-Length: %d' % len(body),
        ]
    else:
        other_headers = [
            "Content-Type: %s" % DEFAULT_ERROR_CONTENT_TYPE,
        ]

    if close_it:
        other_headers.append('Connection: close')

    lines = [status_line]
    if headers:
        lines.extend(headers)
    lines.extend(other_headers)

    if body:
        msg = '\r\n'.join(lines) + EOL + body
    else:
        msg = '\r\n'.join(lines) + EOL

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

    @staticmethod
    def rewriteReqForProxy(msg_req):
        """
        translate absoluteURI to abs_path
        filter headers for forward request
        """
        HEADERS_DROP_FOR_PROXY = ('Proxy-Connection', )
        HEADERS_DROP = HTTPHeadersCaseSensitive.HOP_BY_HOP_HEADERS + HEADERS_DROP_FOR_PROXY

        parses = urlparse.urlparse(msg_req.request_uri)
        request_uri = HTTPHelper.parse_request_uri_from_urlparse(parses)
        first_line = msg_req.method + ' ' + request_uri + ' ' + msg_req.version
        lines = [first_line]
        for item in msg_req.headers.headers:
            k_lower = item[0]
            if HTTPHeadersCaseSensitive.contains(HEADERS_DROP, k_lower):
                continue
            line = '%s: %s' % (item[0], item[1])
            lines.append(line)
        body = msg_req.body or ''
        msg = '\r\n'.join(lines) + EOL + body
        return msg

    @staticmethod
    def rewriteResp(msg_resp, ignore_headers=None):
        """
        filter headers for forward request
        """
        if not ignore_headers:
            ignore_headers = []

        lines = [msg_resp.first_line]
        for item in msg_resp.headers.headers:
            k_lower = item[0]
            if HTTPHeadersCaseSensitive.contains(ignore_headers, k_lower):
                continue
            line = '%s: %s' % (item[0], item[1])
            lines.append(line)
        header = '\r\n'.join(lines) + EOL
        return header


EOL = '\r\n\r\n'

def print_msg(msg, msg_type):
    print '>>> %s' % msg_type
    print msg


class ProxySender(asynchat.async_chat):

    def __init__(self, proxy_receiver, addr_server, map):
        asynchat.async_chat.__init__(self, map=map)

        self.receiver = proxy_receiver
        self.server = proxy_receiver.server

        self.addr_server = addr_server
        self.addr_server_formatted = ':'.join(str(i) for i in addr_server)

        self.create_socket(socket.AF_INET, socket.SOCK_STREAM)
        self.set_terminator(EOL)
        self.connect(addr_server)

        self.raw_msg = ''
        self.msg_resp = None
        self.reading_chunk = False
        self.chunks = []
        self.forward_resp_in_chunked_for_ge_http11 = None
        self._forward_resp_in_chunked_for_lt_http11 = None

        self.is_tunnel = False

    def handle_connect_event(self):
        try:
            asynchat.async_chat.handle_connect_event(self)
        except socket.timeout:
            msg = generate_resp(code=httplib.GATEWAY_TIMEOUT,
                          protocol_version=self.server.protocol_version)
            self.receiver.push(msg)
            self.close_when_done()

    def handle_connect(self):
        if self.server.args.vvv:
            print
            print '>>> %s connected' % self.addr_server_formatted

    def collect_incoming_data(self, data):
        if not self.is_tunnel:
            self.raw_msg += data
        else:
            if self.server.args.vv or self.server.args.vvv:
                print_msg(msg=repr(data), msg_type='response(forward)')
            self.receiver.push(data)


    def found_terminator(self):
        terminator = self.get_terminator()

        if self.server.args.vvv:
            print
            print '>>> sender terminator', repr(terminator)

        if isinstance(terminator, basestring):
            if not self.reading_chunk:
                self._handle_header()
            else:
                self._handle_body_in_chunked()

        elif isinstance(terminator, (int, long)):
            if not self.reading_chunk:
                self.msg_resp = HTTPResponse(msg=self.raw_msg)

                if self.server.args.v:
                    print_msg(msg=self.raw_msg.split('\r\n')[0], msg_type='response')
                elif self.server.args.vv or self.server.args.vvv:
                    print_msg(msg=self.raw_msg, msg_type='response')

                if terminator is 0:
                    self.receiver.push(self.raw_msg)
                else:
                    self.receiver.push(self.raw_msg)
                    print >>sys.stderr, 'WARNING: %s received bytes less than expected, remain %d bytes in server' % (self, terminator)
            else:
                self._handle_body_in_chunked()

    def handle_close(self):
        self.receiver.close()
        self.close()

        if self.server.args.vvv:
            print
            print '>>> %s disconnect' % self.addr_server_formatted


    def _handle_header(self):
        terminator = self.get_terminator()
        self.raw_msg += terminator

        self.msg_resp = HTTPResponse(msg=self.raw_msg)

        if self.receiver.msg_req.method != 'HEAD' and \
                        self.msg_resp.status_code >= httplib.OK and \
                        self.msg_resp.status_code not in (httplib.NO_CONTENT, httplib.NOT_MODIFIED):
            cl = self.msg_resp.headers.get_value('Content-Length')
            if cl is not None:
                cl = int(cl)
                if cl > 0:
                    self.set_terminator(cl)
                else:
                    self.set_terminator(EOL)

                    if self.server.args.v:
                        print_msg(msg=self.raw_msg.split('\r\n')[0], msg_type='response')
                    elif self.server.args.vv or self.server.args.vvv:
                        print_msg(msg=self.raw_msg, msg_type='response')

                    self.receiver.push(self.raw_msg)
            elif self.msg_resp.is_chunked():

                if self.receiver.msg_req.version >= "HTTP/1.1":

                    self.msg_resp.headers.add_header('Transfer-Encoding', 'chunked', override=True)

                    msg = str(self.msg_resp)

                    if self.server.args.v:
                        print_msg(msg=msg.split('\r\n')[0], msg_type='response')
                    elif self.server.args.vv or self.server.args.vvv:
                        print_msg(msg=msg, msg_type='response')

                    self.receiver.push(msg)
                    self.raw_msg = ''

                    self.forward_resp_in_chunked_for_ge_http11 = True
                else:
                    msg = HTTPHelper.rewriteResp(msg_resp=self.msg_resp, ignore_headers=['Transfer-Encoding'])

                    if self.server.args.v:
                        print_msg(msg=msg.split('\r\n')[0], msg_type='response')
                    elif self.server.args.vv or self.server.args.vvv:
                        print_msg(msg=msg, msg_type='response')

                    self.receiver.push(msg)
                    self.raw_msg = ''

                    self._forward_resp_in_chunked_for_lt_http11 = True

                self.reading_chunk = True
                self.set_terminator('\r\n')
            else:
                if self.server.args.v:
                    print_msg(msg=self.raw_msg.split('\r\n')[0], msg_type='response')
                elif self.server.args.vv or self.server.args.vvv:
                    print_msg(msg=self.raw_msg, msg_type='response')

                self.receiver.push(self.raw_msg)
        else:
            if self.server.args.v:
                print_msg(msg=self.raw_msg.split('\r\n')[0], msg_type='response')
            elif self.server.args.vv or self.server.args.vvv:
                print_msg(msg=self.raw_msg, msg_type='response')

            self.receiver.push(self.raw_msg)

    def _handle_body_in_chunked(self):
        if self.forward_resp_in_chunked_for_ge_http11:
            data = self.raw_msg + '\r\n'

            if self.server.args.vv or self.server.args.vvv:
                print_msg(msg=repr(data), msg_type='response(chunk)')

            self.receiver.push(data)
            self.raw_msg = ''

        elif self._forward_resp_in_chunked_for_lt_http11:
            terminator = self.get_terminator()

            if isinstance(terminator, basestring):
                chunk = self.chunks[-1]
                self.chunks.append(self.raw_msg)
                self.raw_msg = ''

                splits = chunk.rstrip('\r\n').split(';')
                chunk_size = int(splits[0], 16)

                if len(splits) > 1:
                    chunk_ext_list = splits[1:]

                if chunk_size is 0: # last-chunk
                    self.set_terminator('\r\n')

                    gz = gzip.GzipFile(fileobj=StringIO.StringIO(''.join(self.chunks)))
                    body = gz.read()

                    if self.server.args.v:
                        print_msg(msg=body.split('\r\n')[0], msg_type='response')
                    elif self.server.args.vv or self.server.args.vvv:
                        print_msg(msg=body, msg_type='response')
                    self.receiver.push(body)

                    self.set_terminator(EOL)
                    self.reading_chunk = False
                else:
                    self.set_terminator(chunk_size)

            elif isinstance(terminator, (int, long)):
                self.set_terminator(EOL)
            else:
                print >>sys.stderr, 'got unexpected terminator', repr(terminator)


class ProxyReceiver(asynchat.async_chat):
    channel_counter = 0

    def __init__(self, server, (sock_client, addr_client), map):
        asynchat.async_chat.__init__ (self, sock=sock_client, map=map)

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
        self.is_tunnel = False

    def collect_incoming_data(self, data):
        if not self.is_tunnel:
            self.raw_msg += data
        else:
            if self.server.args.vv or self.server.args.vvv:
                print_msg(msg=repr(data), msg_type='request(forward)')
            self.sender.push(data)

    def found_terminator(self):
        terminator = self.get_terminator()

        if self.server.args.vvv:
            print
            print '>>> receiver terminator:', repr(terminator)

        if isinstance(terminator, basestring):
            self.raw_msg += EOL

            if self.server.args.v:
                print_msg(msg=self.raw_msg.split('\r\n')[0], msg_type='request')
            elif self.server.args.vv or self.server.args.vvv:
                print_msg(msg=self.raw_msg, msg_type='request')

            self.msg_req = HTTPRequest(self.raw_msg)

            if not HTTPHelper.is_proxy_request(self.msg_req.request_uri) and self.msg_req.method.upper() != "CONNECT":
                msg = generate_resp(code=httplib.BAD_REQUEST)

                if self.server.args.v:
                    print_msg(msg=msg.split('\r\n')[0], msg_type='response')
                elif self.server.args.vv or self.server.args.vvv:
                    print_msg(msg=msg, msg_type='response')
                self.push(msg)
                return

            parses = urlparse.urlparse(self.msg_req.request_uri)
            if self.msg_req.method.upper() != "CONNECT":
                addr = HTTPHelper.parse_addr_from_urlparse(parses)
            else:
                # self.msg_req.request_uri = 'google.com:443'
                # urlparse.urlparse(self.msg_req.request_uri)
                # ParseResult(scheme='', netloc='', path='google.com:443', params='', query='', fragment='')
                splits = parses.path.split(':')
                addr = (splits[0], int(splits[1]))

            try:
                self._setup_sender(addr)
            except socket.timeout:
                msg = generate_resp(code=httplib.GATEWAY_TIMEOUT,
                              reason='Forwarding failure',
                              protocol_version=self.server.protocol_version)
                self.push(msg)
                return
            except socket.error, ex:
                err_no = ex.args[0]
                if err_no == errno.ECONNREFUSED:
                    msg = generate_resp(code=httplib.SERVICE_UNAVAILABLE,
                              reason='Forwarding failure',
                              protocol_version=self.server.protocol_version)
                    self.push(msg)
                    return
                else:
                    raise ex

            if self.msg_req.method.upper() != "CONNECT":
                cl = self.msg_req.headers.get_value('Content-Length')
                if cl is not None:
                    self.set_terminator(int(cl))
                else:
                    self.set_terminator(EOL)

                    msg = HTTPHelper.rewriteReqForProxy(self.msg_req)

                    if self.server.args.v:
                        print_msg(msg=msg.split('\r\n')[0], msg_type='request(rewritten)')
                    elif self.server.args.vv or self.server.args.vvv:
                        print_msg(msg=msg, msg_type='request(rewritten)')

                    self.sender.push(msg)
            else:
                self.set_terminator(None)

                msg = generate_resp(code=httplib.OK,
                                    reason='Connection established',
                              headers=['Proxy-Agent: %s' % self.server.server_version],
                              protocol_version=self.server.protocol_version)

                if self.server.args.v:
                    print_msg(msg=msg.split('\r\n')[0], msg_type='response')
                elif self.server.args.vv or self.server.args.vvv:
                    print_msg(msg=msg, msg_type='response')

                self.push(msg)
                self.raw_msg = ''

                self.is_tunnel = True

                self.sender.is_tunnel = True

        elif isinstance(terminator, int) or isinstance(terminator, long):
            if self.server.args.v:
                print_msg(msg=self.raw_msg.split('\r\n')[0], msg_type='request')
            elif self.server.args.vv or self.server.args.vvv:
                print_msg(msg=self.raw_msg, msg_type='request')

            self.msg_req = HTTPRequest(self.raw_msg)
            msg = HTTPHelper.rewriteReqForProxy(self.msg_req)

            if self.server.args.v:
                print_msg(msg=msg.split('\r\n')[0], msg_type='request(rewritten)')
            elif self.server.args.vv or self.server.args.vvv:
                print_msg(msg=msg, msg_type='request(rewritten)')

            if terminator is 0:
                self.sender.push(msg)
            else:
                self.sender.push(msg)
                print >>sys.stderr, 'WARNING: %s received bytes less than expected, remain %d bytes in client' % (self, terminator)


    def _setup_sender(self, addr):
        self.sender = ProxySender(self, addr, self._map)
        self.sender.id = self.id

    def handle_close(self):
        self.close()

        if self.server.args.vvv:
            print
            print '>>> %s disconnect' % self.addr_client_formatted


class HTTPServer(asyncore.dispatcher):

    allow_reuse_address = True
    request_queue_size = 5

    DEFAULT_PROTOCOL_VERSION = "HTTP/1.1"
    protocol_version = DEFAULT_PROTOCOL_VERSION
    server_version = "POPS/" + __version__
    args = None

    def __init__(self, server_address, RequestHandlerClass):
        asyncore.dispatcher.__init__(self)

        self.RequestHandlerClass = RequestHandlerClass

        self.create_socket(socket.AF_INET, socket.SOCK_STREAM)
        self.set_reuse_addr()
        self.bind(server_address)
        self.listen(self.request_queue_size)

    def serve_forever(self):
        asyncore.loop(use_select=self.args.select)

    def server_close(self):
        self.close()

    def handle_accept(self):
        """
        walk around problem Thundering herd
        """

        if self.args.vvv:
            print 'thundering herd, pid:%d awake' % os.getpid()
        _ = self.accept()
        if not _:
            return
        if self.args.vvv:
            print 'thundering herd, pid:%d hit' % os.getpid()

        sock_client, addr_client = _[0], _[1]

        if self.args.vvv:
            msg = format_addr(addr_client) + ' connected'
            print >>sys.stdout, msg

        self.RequestHandlerClass(self, (sock_client, addr_client), self._map)

        
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
    processes = int(args.processes)
    pid = os.getpid()

    httpd_inst = HTTPServer(server_address, ProxyReceiver)
    httpd_inst.args = args

    if getattr(args, 'http1.0'):
        httpd_inst.protocol_version = 'HTTP/1.0'

    for i in range(processes):
        p = multiprocessing.Process(target=serve_forever, args=(httpd_inst,))
        if args.daemon:
            p.daemon = args.daemon
        p.start()

    srv_name = 'node'
    print >> sys.stdout, "POPS %s started, listen on %s:%s, pid %d" % (srv_name, server_address[0], server_address[1], pid)
    try:
        httpd_inst.serve_forever()
    finally:
        httpd_inst.server_close()

if __name__ == "__main__":
    multiprocessing.freeze_support()

    parser = argparse.ArgumentParser(prog=sys.argv[0], description='POPS')

    parser.add_argument('--version', action='version', version=__version__)

    parser.add_argument('--addr',
                        default='127.0.0.1',
                        help='default 127.0.0.1')

    parser.add_argument('--port',
                        type=int,
                        default=1080,
                        help='default 1080')

    parser.add_argument('--processes',
                        default=multiprocessing.cpu_count(),
                        help='default cat /proc/cpuinfo | grep processor | wc -l')

    parser.add_argument('-v',
                        action='store_true',
                        help='dump headers of request and response into stdout')

    parser.add_argument('-vv',
                        action='store_true',
                        help='dump body of request and response into stdout')

    parser.add_argument('-vvv',
                        action='store_true',
                        help='dump anything into stdout')

    parser.add_argument('--http1.0',
                        action='store_true',
                        help='force proxy server using HTTP/1.0')

    parser.add_argument('--error_log',
                        help='default /dev/null')

    parser.add_argument('--pid')

    parser.add_argument('--daemon', action='store_true')

    parser.add_argument('--select', action='store_true')

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
