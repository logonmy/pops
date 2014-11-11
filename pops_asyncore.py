"""
Rewritten pops in asyncore and asyncore_patch.

See also:
 - http://bugs.python.org/issue6692
 - https://github.com/shuge/asyncore_patch

TODO:
 - custom connect/read/write timeout via custom asyncore.loop/socket_map/poll_func
"""
import BaseHTTPServer
import cStringIO
import argparse
import asyncore_patch; asyncore_patch.patch_all()
import time
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


DEFAULT_ERROR_MESSAGE = """\
<head>
<title>Response</title>
</head>
<body>
<h1>Response</h1>
<p>Status code %(code)d.
<p>Message: %(message)s.
<p>Code explanation: %(code)s = %(explain)s.
</body>
"""


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
        self.start_line = None
        self.headers = None
        self.body = None
        if not ignores_headers:
            ignores_headers = []
        self.parse_msg(ignores_headers)

    def parse_start_line(self):
        pass

    def parse_msg(self, ignores_headers):
        splits = self.raw.split('\r\n\r\n')
        if len(splits) == 2:
            start_line_headers, self.body = splits[0], splits[1]
        else:
            start_line_headers = splits[0]

        lines = [i for i in start_line_headers.split('\r\n') if i]
        self.start_line = lines[0]
        self.headers = HTTPHeadersCaseSensitive(lines=lines[1:], ignores=ignores_headers)

    def is_chunked(self):
        cl = self.headers.get_value('Content-Length')
        te = self.headers.get_value('Transfer-Encoding')
        return cl is None and te and te.lower() == 'chunked'

    def __str__(self):
        lines = [self.start_line]
        for item in self.headers.headers:
            lines.append('%s: %s' % (item[0], item[1]))
        body = self.body or ''
        msg = '\r\n'.join(lines) + '\r\n\r\n' + body
        return msg


class HTTPRequest(HTTPMessage):
    def __init__(self, msg, ignores_headers=None):
        super(HTTPRequest, self).__init__(msg=msg, ignores_headers=ignores_headers)

        self.method = None
        self.request_uri = None
        self.version = None
        self.parse_start_line()

    def parse_start_line(self):
        method, request_uri, version = self.start_line.split(None, 2)
        self.method = method
        self.request_uri = request_uri
        self.version = version

    @property
    def request_line(self):
        return self.start_line


class HTTPResponse(HTTPMessage):
    def __init__(self, msg, ignores_headers=None):
        super(HTTPResponse, self).__init__(msg=msg, ignores_headers=ignores_headers)

        self.version = None
        self.status_code = None
        self.reason = None
        self.parse_start_line()

    def parse_start_line(self):
        version, status_code, reason = self.start_line.split(None, 2)
        self.version = version
        self.status_code = int(status_code)
        self.reason = reason

    @property
    def status_line(self):
        return self.start_line


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
        short, long = BaseHTTPServer.BaseHTTPRequestHandler.responses[code]
    except KeyError:
        short, long = '???', '???'
    if reason is None:
        reason = short
    explain = long

    status_line = "%s %d %s" % (protocol_version, code, reason)

    if not body and using_body_template and code != httplib.OK:
        body = (DEFAULT_ERROR_MESSAGE %
               {'code': code, 'message': BaseHTTPServer._quote_html(reason), 'explain': explain})
    else:
        body = ''

    if body:
        other_headers = [
            'Content-Length: %d' % len(body),
        ]
    else:
        other_headers = []

    if close_it:
        other_headers.append('Connection: close')

    lines = [status_line]
    if headers:
        lines.extend(headers)
    lines.extend(other_headers)

    if body:
        line = "Content-Type: %s" % BaseHTTPServer.DEFAULT_ERROR_CONTENT_TYPE,
        lines.append(line)
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
    def parse_addr_from_request_uri(uri):
        """
        >>> uri = "http://tools.ietf.org/html/rfc868.html"
        >>> HTTPHelper.parse_addr_from_request_uri(uri) == 'tools.ietf.org:80'
        True
        >>> uri = 'google.com:443'
        >>> HTTPHelper.parse_addr_from_request_uri(uri) == 'google.com:443'
        True
        """
        parses = urlparse.urlparse(uri)
        if parses.netloc:
            splits = parses.netloc.split(':')
            if len(splits) == 2:
                host, port = splits[0], int(splits[1])
            else:
                host, port = splits[0], 80
        else:
            splits = parses.path.split(':')
            if len(splits) == 2:
                host, port = splits[0], int(splits[1])
            else:
                host, port = splits[0], 443
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

        start_line = msg_req.method + ' ' + request_uri + ' ' + msg_req.version
        lines = [start_line]
        for item in msg_req.headers.headers:
            k_lower = item[0]
            if HTTPHeadersCaseSensitive.contains(HEADERS_DROP, k_lower):
                continue
            line = '%s: %s' % (item[0], item[1])
            lines.append(line)
        body = msg_req.body or ''
        msg = '\r\n'.join(lines) + EOL + body
        return msg


EOL = '\r\n\r\n'
CHUNK_EOL = '\r\n'


class async_chat_wrapper(asynchat.async_chat):

    weekdayname = BaseHTTPServer.BaseHTTPRequestHandler.weekdayname
    monthname = BaseHTTPServer.BaseHTTPRequestHandler.monthname

    def date_time_string(self, timestamp=None):
        """ Return the current date and time formatted for a message header.
        String format in 'Thu, 06 Nov 2014 07:43:24 GMT'.
        This copy from BaseHTTPServer.BaseHTTPRequestHandler.
        """
        if timestamp is None:
            timestamp = time.time()
        year, month, day, hh, mm, ss, wd, y, z = time.gmtime(timestamp)
        s = "%s, %02d %3s %4d %02d:%02d:%02d GMT" % (
                self.weekdayname[wd],
                day, self.monthname[month], year,
                hh, mm, ss)
        return s

    def address_string(self):
        return ':'.join(str(i) for i in self.address)

    def handle_header(self):
        raise NotImplemented

    def handle_body(self):
        raise NotImplemented

    def handle_chunk(self):
        raise NotImplemented

    # def handle_tunnel(self):
    #     raise NotImplemented


class ProxySender(async_chat_wrapper):

    def __init__(self, proxy_receiver, addr_origin_server, socket_map):
        async_chat_wrapper.__init__(self, map=socket_map)

        self.server = proxy_receiver.server
        self.receiver = proxy_receiver

        self.addr_origin_server = addr_origin_server

        self.raw_msg = ''
        self.msg_resp = None

        self.reading_chunk = False
        self.chunks = []
        self.user_agent_supports_transfer_encoding_chunked = None
        self.user_agent_not_supports_transfer_encoding_chunked = None

        self.is_tunnel = False
        self.forward_until_conn_close = False

        self.set_terminator(EOL)

        self.socket_closed = False

        self.create_socket(socket.AF_INET, socket.SOCK_STREAM)
        self.connect(self.addr_origin_server)

    @property
    def address(self):
        return self.addr_origin_server

    def collect_incoming_data(self, data):
        if self.server.args.log_all_out:
            self.server.log_message('-', 'out: %s, %s', repr(data), repr(self.get_terminator()))

        if self.is_tunnel:
            self.receiver.push(data)
        elif self.forward_until_conn_close:
            self.receiver.push(data)
        else:
            self.raw_msg += data

    def found_terminator(self):
        terminator = self.get_terminator()

        if isinstance(terminator, basestring):
            if self.reading_chunk:
                self.handle_chunk()
            else:
                self.handle_header()
        elif isinstance(terminator, (int, long)):
            if self.reading_chunk:
                self.handle_chunk()
            else:
                self.handle_body()
        else:
            raise Exception('got un-expected terminator ' + repr(terminator))

    def handle_connect_event(self):
        """ This function called before handle_connect_event. """
        try:
            async_chat_wrapper.handle_connect_event(self)
        except socket.error, ex:
            if ex.errno == errno.ECONNREFUSED:
                # privoxy 3.0.21 responses 503 in this situation, should we response BAD_GATEWAY instead?
                msg = generate_resp(code=httplib.SERVICE_UNAVAILABLE,
                                    reason='Connect failed',
                                    close_it=True,
                              protocol_version=self.server.protocol_version)
                self.receiver.push(msg)
                self.close_when_done()

                if self.server.args.log_conn_status:
                    self.server.log_message('-', 'connect to %s refused', self.address_string())
            elif ex.errno == errno.ETIMEDOUT:
                msg = generate_resp(code=httplib.GATEWAY_TIMEOUT,
                              protocol_version=self.server.protocol_version)
                self.receiver.push(msg)
                self.close_when_done()

                if self.server.args.log_conn_status:
                    self.server.log_message('-', 'connect to %s timeout', self.address_string())
            else:
                raise ex

        # We call receiver.handle_body here instead of receiver.handle_header/handle_header_method_connect,
        # because of sender.connect is non-blocking,
        # it is possible sender.connected is still equal to False when receiver.setup_sender() done.
        if self.connected and self.receiver.msg_req.method.upper() == "CONNECT":
            self.receiver.is_tunnel = True
            self.is_tunnel = True

            self.receiver.raw_msg = generate_resp(code=httplib.OK,
                                reason='Connection established',
                          headers=['Proxy-Agent: %s' % self.server.server_version],
                          protocol_version=self.server.protocol_version)

            self.receiver.push(self.receiver.raw_msg)

            self.receiver.raw_msg_is_resp = True
            self.receiver.handle_body()

            self.receiver.set_terminator(None)

    def handle_connect(self):
        """ This function called after handle_connect_event. """
        if self.server.args.log_conn_status:
            self.server.log_message('-', 'connect to %s, fd:%d', self.address_string(), self.socket.fileno())

    def handle_tunnel(self):
        self.receiver.push(self.raw_msg)
        self.raw_msg = ''

    def handle_close(self):
        if self.socket_closed:
            return
        self.socket_closed = True

        fd = self.socket.fileno()
        async_chat_wrapper.handle_close(self)

        if self.server.args.log_conn_status:
            self.server.log_message('-', 'origin-server %s disconnect, fd:%d', self.address_string(), fd)

        # Sometime upstream/origin server close actively,
        # We have to disconnect client connection after it.
        if not self.receiver.socket_closed:
           self.receiver.handle_close()

    def handle_header(self):
        terminator = self.get_terminator()
        self.raw_msg += terminator

        if self.server.args.log_resp_recv_header:
            self.server.log_message('-', 'receive response headers: %s', repr(self.raw_msg.split(EOL)[0]))

        self.msg_resp = HTTPResponse(msg=self.raw_msg)

        if self.receiver.msg_req.method.upper() != 'HEAD' and \
                        self.msg_resp.status_code >= httplib.OK and \
                        self.msg_resp.status_code not in (httplib.NO_CONTENT, httplib.NOT_MODIFIED):

            conn = self.msg_resp.headers.get_value('Connection')
            cl = self.msg_resp.headers.get_value('Content-Length')

            # For confirm to http://tools.ietf.org/html/rfc7230#section-3.3.3,
            # we detect body if it encoding in chunked before content-length field existing.
            if self.msg_resp.is_chunked():
                if self.receiver.msg_req.version >= "HTTP/1.1":
                    self.msg_resp.headers.add_header('Transfer-Encoding', 'chunked', override=True)
                    self.receiver.push(str(self.msg_resp))
                    self.raw_msg = ''

                    self.user_agent_supports_transfer_encoding_chunked = True
                else:
                    self.msg_resp = HTTPResponse(msg=self.raw_msg, ignores_headers=['Transfer-Encoding'])
                    self.receiver.push(str(self.msg_resp))
                    self.raw_msg = ''

                    self.user_agent_not_supports_transfer_encoding_chunked = True

                self.reading_chunk = True
                self.set_terminator(CHUNK_EOL)
                return

            elif cl is not None:
                try:
                    cl = int(cl)
                except ValueError:
                    self.raw_msg = generate_resp(code=httplib.BAD_REQUEST)
                    self.msg_resp = HTTPResponse(msg=self.raw_msg)
                    self.handle_body()
                    return

                self.receiver.push(self.raw_msg)
                self.raw_msg = ''

                if cl > 0:
                    self.set_terminator(cl)
                    return

                self.handle_body()

            elif conn.lower() == 'close':
                self.forward_until_conn_close = True
                self.set_terminator(None)
            else:
                self.handle_body()
        else:
            self.handle_body()

    def handle_body(self):
        self.receiver.push(self.raw_msg)

        if self.server.args.log_access or self.server.args.log_req_recv_body:

            splits = self.raw_msg.split(EOL)
            body = splits[-1]

            if self.server.args.log_access:
                if self.raw_msg:
                    bytes = len(body)
                else:
                    bytes = 0
                self.server.log_request(
                    addr_client=self.receiver.addr_client[0],
                    request_line=self.receiver.msg_req.request_line,
                    code=self.msg_resp.status_code,
                    size=bytes)

            if self.server.args.log_req_recv_body:
                self.server.log_message('-', 'receive request body: %s', repr(body))

        self.raw_msg = ''
        field_expect = self.receiver.msg_req.headers.get_value('Expect')
        if field_expect is None and self.msg_resp.status_code != httplib.CONTINUE:
            self.receiver.msg_req = None
        self.msg_resp = None

        self.reading_chunk = False
        self.user_agent_not_supports_transfer_encoding_chunked = False
        self.user_agent_supports_transfer_encoding_chunked = False

        self.set_terminator(EOL)

    def handle_chunk(self):
        terminator = self.get_terminator()

        if self.user_agent_supports_transfer_encoding_chunked:
            data = self.raw_msg + terminator
            self.receiver.push(data)
            self.raw_msg = ''

        elif self.user_agent_not_supports_transfer_encoding_chunked:
            if isinstance(terminator, basestring):
                assert terminator == CHUNK_EOL
                chunk_data = self.raw_msg
                splits = chunk_data.rstrip(CHUNK_EOL).split(';')
                self.raw_msg = ''
                chunk_size = int(splits[0], 16)

                if len(splits) > 1:
                    chunk_ext_list = splits[1:]

                if chunk_size is 0: # last-chunk
                    gz = gzip.GzipFile(fileobj=cStringIO.StringIO(s=''.join(self.chunks)))
                    # TODO: read chunk from gz object for improve performance 
                    body = gz.read()
                    self.receiver.push(body)

                    self.reading_chunk = False
                    self.set_terminator(EOL)
                else:
                    self.set_terminator(chunk_size)

            elif isinstance(terminator, (int, long)):
                chunk_data = self.raw_msg[:-2] # strip tail CRLF
                self.chunks.append(chunk_data)
                self.raw_msg = ''
                self.set_terminator(CHUNK_EOL)
            else:
                raise Exception
        else:
            raise Exception


class ProxyReceiver(async_chat_wrapper):

    def __init__(self, server, (sock_client, addr_client), map):
        async_chat_wrapper.__init__(self, sock=sock_client, map=map)

        self.server = server

        self.sock_client = sock_client
        self.addr_client = addr_client

        self.raw_msg = ''
        self.msg_req = None
        self.raw_msg_is_resp = False

        self.set_terminator(EOL)
        self.sender = None
        self.is_tunnel = False

        self.socket_closed = False

    @property
    def address(self):
        return self.addr_client

    def collect_incoming_data(self, data):
        if self.server.args.log_all_out:
            self.server.log_message('-', 'in: %s, %s', repr(data), repr(self.get_terminator()))

        if self.is_tunnel:
            self.sender.push(data)
        else:
            self.raw_msg += data

    def found_terminator(self):
        terminator = self.get_terminator()

        if isinstance(terminator, basestring):
            self.raw_msg += EOL
            self.handle_header()
        elif isinstance(terminator, int) or isinstance(terminator, long):
            self.handle_body()
        else:
            raise Exception('got un-expected terminator ' + repr(terminator))

    def setup_sender(self, addr):
        self.sender = ProxySender(proxy_receiver=self, addr_origin_server=addr, socket_map=self._map)

    def handle_close(self):
        if self.socket_closed:
            return
        self.socket_closed = True

        try:
            fd = self.socket.fileno()
        except socket.error, ex:
            if ex.errno == errno.EBADF:
                fd = -1
            else:
                raise ex

        async_chat_wrapper.handle_close(self)

        if self.server.args.log_conn_status:
            self.server.log_message('-', 'user-agent %s disconnect, fd:%d', self.address_string(), fd)

        if self.sender and not self.sender.socket_closed:
            try:
                self.sender.handle_close()
            except socket.error, ex:
                if ex.errno == errno.EBADF:
                    fd = -1

                    if self.server.args.log_conn_status:
                        self.server.log_message('-', 'origin-server %s disconnect, fd:%d', self.sender.address_string(), fd)
                else:
                    raise ex

    def handle_header(self):
        if self.server.args.log_req_recv_header:
            self.server.log_message('-', 'receive request headers: %s', repr(self.raw_msg.split(EOL)[0]))

        self.msg_req = HTTPRequest(self.raw_msg)

        if self.msg_req.method.upper() == "CONNECT":
            self.handle_header_method_connect()
        else:
            self.handle_header_method_others()

    def handle_header_method_connect(self):
        addr = HTTPHelper.parse_addr_from_request_uri(self.msg_req.request_uri)

        try:
            self.setup_sender(addr)
        except socket.error, ex:
            if ex.errno == errno.ECONNREFUSED:
                self.raw_msg = generate_resp(code=httplib.SERVICE_UNAVAILABLE,
                          reason='Forwarding failure',
                          protocol_version=self.server.protocol_version)
                self.raw_msg_is_resp = True
                self.handle_body()
                return
            elif ex.errno == errno.ETIMEDOUT:
                self.raw_msg = generate_resp(code=httplib.GATEWAY_TIMEOUT,
                              reason='Forwarding failure',
                              protocol_version=self.server.protocol_version)
                self.raw_msg_is_resp = True
                self.handle_body()
                return
            else:
                raise ex

    def handle_header_method_others(self):
        if not HTTPHelper.is_proxy_request(self.msg_req.request_uri):
            self.raw_msg = generate_resp(code=httplib.BAD_REQUEST)
            self.raw_msg_is_resp = True
            self.handle_body()
            return

        addr = HTTPHelper.parse_addr_from_request_uri(self.msg_req.request_uri)

        try:
            self.setup_sender(addr)
        except socket.error, ex:
            err_no = ex.args[0]
            if err_no == errno.ECONNREFUSED:
                self.raw_msg = generate_resp(code=httplib.SERVICE_UNAVAILABLE,
                          reason='Forwarding failure',
                          protocol_version=self.server.protocol_version)
                self.raw_msg_is_resp = True
                self.handle_body()
                return

            elif err_no == errno.ETIMEDOUT:
                self.raw_msg = generate_resp(code=httplib.GATEWAY_TIMEOUT,
                              reason='Forwarding failure',
                              protocol_version=self.server.protocol_version)
                self.raw_msg_is_resp = True
                self.handle_body()
                return
            else:
                raise ex

        field_cl = self.msg_req.headers.get_value('Content-Length')
        if field_cl is not None:
            cl = int(field_cl)

            msg = HTTPHelper.rewriteReqForProxy(self.msg_req)
            self.sender.push(msg)
            self.raw_msg = ''

            if cl > 0:
                # continue to receive request body
                self.set_terminator(cl)
            else:
                # continue to receive next request
                self.set_terminator(EOL)
        else:
            self.raw_msg = HTTPHelper.rewriteReqForProxy(self.msg_req)
            self.handle_body()

    def handle_body(self):
        if not self.is_tunnel:
            self.sender.push(self.raw_msg)

        if self.raw_msg_is_resp:
            if self.server.args.log_access or self.server.args.log_resp_recv_body:
                splits = self.raw_msg.split(EOL)
                body = splits[-1]

                if self.server.args.log_access:
                    if self.raw_msg:
                        bytes = len(body)
                    else:
                        bytes = 0
                    msg_resp = HTTPResponse(msg=self.raw_msg)

                    self.server.log_request(
                        addr_client=self.addr_client[0],
                        request_line=self.msg_req.request_line,
                        code=msg_resp.status_code,
                        size=bytes)

                if self.server.args.log_resp_recv_body:
                    self.server.log_message('-', 'receive response body: %s', repr(body))

                self.raw_msg_is_resp = False

        self.raw_msg = ''

        # We reset self.msg_req to None in sender.handle_body,
        # because of access logging in sender.log_request requires self.msg_req as context.
        #
        # self.msg_req = None

        if not self.is_tunnel:
            self.set_terminator(EOL)


class HTTPServer(asyncore.dispatcher):

    allow_reuse_address = True
    request_queue_size = 5

    DEFAULT_PROTOCOL_VERSION = "HTTP/1.1"
    protocol_version = DEFAULT_PROTOCOL_VERSION
    server_version = "POPS/" + __version__
    args = None

    weekdayname = BaseHTTPServer.BaseHTTPRequestHandler.weekdayname
    monthname = BaseHTTPServer.BaseHTTPRequestHandler.monthname

    def __init__(self, addr_server, RequestHandlerClass):
        asyncore.dispatcher.__init__(self)

        self.addr_server = addr_server
        self.RequestHandlerClass = RequestHandlerClass

        self.create_socket(socket.AF_INET, socket.SOCK_STREAM)
        self.set_reuse_addr()
        self.bind(self.addr_server)
        self.listen(self.request_queue_size)

    def date_time_string(self, timestamp=None):
        """ Return the current date and time formatted for a message header.
        String format in 'Thu, 06 Nov 2014 07:43:24 GMT'.
        This copy from BaseHTTPServer.BaseHTTPRequestHandler.
        """
        if timestamp is None:
            timestamp = time.time()
        year, month, day, hh, mm, ss, wd, y, z = time.gmtime(timestamp)
        s = "%s, %02d %3s %4d %02d:%02d:%02d GMT" % (
                self.weekdayname[wd],
                day, self.monthname[month], year,
                hh, mm, ss)
        return s

    def log_date_time_string(self):
        now = time.time()
        year, month, day, hh, mm, ss, x, y, z = time.gmtime(now)
        s = "%02d/%3s/%04d %02d:%02d:%02d" % (
                day, self.monthname[month], year, hh, mm, ss)
        return s

    def log_request(self, addr_client, request_line, code='-', size='-'):
        """
        client-address + " " +  identity-client + " " + user-id + " " + "[date-time-confirms-RFC1123] + " " + start-line + " " +  status-code + " " + response-body-size
        127.0.0.1 user-identifier frank [10/Oct/2000:13:55:36 -0700] "GET /apache_pb.gif HTTP/1.0" 200 2326
        http://en.wikipedia.org/wiki/Common_Log_Format
        """
        self.log_message(addr_client, '"%s" %s %s', request_line, str(code), str(size))

    def log_error(self, addr_client, format, *args):
        self.log_message(addr_client, format, *args)

    def log_message(self, addr_client, format, *args):
        """Log an arbitrary message.

        This is used by all other logging functions.  Override
        it if you have specific logging wishes.

        The first argument, FORMAT, is a format string for the
        message to be logged.  If the format string contains
        any % escapes requiring parameters, they should be
        specified as subsequent arguments (it's just like
        printf!).

        The client ip address and current date/time are prefixed to every
        message.
        """
        sys.stderr.write("%s - - [%s] %s\n" %
                         (addr_client,
                          self.log_date_time_string(),
                          format%args))

    def address_string(self):
        return ':'.join(str(i) for i in self.addr_server)

    def serve_forever(self):
        if self.args.log_process_status:
            pid = os.getpid()
            self.log_message('-', 'POPS started, listen on %s, pid:%d', self.address_string(), pid)

        asyncore.loop(use_select=self.args.select)


    def handle_accept(self):
        """ Walking around the Thundering herd problem. """
        pid = os.getpid()
        if self.args.log_process_status:
            self.server.log_message('-', 'the thundering herd problem, accept awake process, pid:%d', pid)

        _ = self.accept()
        if not _:
            if self.args.log_process_status:
                self.log_message('-', 'the thundering herd problem, process accept failed, pid:%d', pid)
            return

        if self.args.log_process_status:
            self.log_message('-', 'the thundering herd problem, process accept success, pid:%d', pid)

        sock_client, addr_client = _[0], _[1]

        handler = self.RequestHandlerClass(self, (sock_client, addr_client), self._map)

        if self.args.log_conn_status:
            self.log_message('-', '%s connected, fd:%d', handler.address_string(), sock_client.fileno())

    def server_close(self):
        """ asyncore.dispatcher.handle_close already does close job. """
        pass


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
        httpd_inst.serve_forever()
    finally:
        httpd_inst.server_close()


class DebugLevel(object):

    log_process_status = 1 << 1

    log_conn_status = 1 << 2
    log_io_status = 1 << 3

    log_access = 1 << 4

    log_req_recv_header = 1 << 5
    log_req_recv_body = 1 << 6

    log_resp_recv_header = 1 << 7
    log_resp_recv_body = 1 << 8

    log_all_in = 1 << 9
    log_all_out = 1 << 10


def main(args):
    addr_server = (args.addr, args.port)
    processes = int(args.processes)

    httpd_inst = HTTPServer(addr_server, ProxyReceiver)
    httpd_inst.args = args

    if getattr(args, 'http1.0'):
        httpd_inst.protocol_version = 'HTTP/1.0'

    for i in range(processes):
        p = multiprocessing.Process(target=serve_forever, args=(httpd_inst,))
        if args.daemon:
            p.daemon = args.daemon
        p.start()

    try:
        httpd_inst.serve_forever()
    finally:
        httpd_inst.server_close()

if __name__ == "__main__":
    multiprocessing.freeze_support()

    parser = argparse.ArgumentParser(prog=sys.argv[0], description='POPS')

    parser.add_argument('--version', action='version', version=__version__)

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

    parser.add_argument('--processes',
                        default=multiprocessing.cpu_count(),
                        help='default cat /proc/cpuinfo | grep processor | wc -l')

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

    parser.add_argument('--select', action='store_true')


    parser.add_argument('--stop',
                        action='store_true',
                        help='default start')

    debug_level_list = [(key, val) for key, val in DebugLevel.__dict__.iteritems() if not key.startswith('_')]
    debug_level_list.sort(cmp=lambda a, b: a[1] - b[1])
    for item in debug_level_list:
        key = item[0]
        parser.add_argument('--' + key, action='store_true', help='debug level settings')


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
