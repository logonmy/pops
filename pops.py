#!/usr/bin/env python
#-*- coding:utf-8 -*-
import base64
import copy
import datetime
import errno
import functools
import gzip
import json
import os
import BaseHTTPServer
import httplib
import multiprocessing
import pdb
import random
import socket
import sys
import StringIO
import time
import threading
import traceback
import urlparse
import select

import argparse
from daemon import runner
import re

try:
    import color
except ImportError:
    color = None

__version__ = "201408-r2"

SERVER_RECV_TEIMOUT = 10.0
PROXY_SEND_RECV_TIMEOUT = 10.0

RECV_BUF_SIZE = 8192


class StringHelper(object):
    MAX_LEN = 64

    @staticmethod
    def cut_long_str_for_human(s):
        s_len = len(s)
        if s_len <= StringHelper.MAX_LEN:
            return s
        else:
            return '---%s...< %d bytes >...%s---' % (s[:5], s_len - 10, s[-5:])


def print_io(a, b, dir, data):
    ts_prefix = str(datetime.datetime.today())[:19]

    if not isinstance(data, (set, tuple, list)):
        data = [data]

    if color:
        lines = [
                    '%s %s %s %s' % (color.green(ts_prefix), color.blue(a), color.red(dir), color.blue(b))
                ] + data
    else:
        lines = [
                    '%s %s %s %s' % (ts_prefix, a, dir, b)
                ] + data
    print >> sys.stdout, '\n'.join(lines)


def get_top_domain_name(s):
    if s.count('.') == 1:
        return s
    elif s.count('.') > 1:
        return s[s.index('.') + 1:]
    else:
        raise ValueError


def auth_required(func):
    def check_authorization(handler_obj):
        value = handler_obj.headers.get('authorization')
        if value:
            if value.replace('Basic ', '').strip() == handler_obj.server.auth_base64:
                return True
        return False

    @functools.wraps(func)
    def _wrapped(handler_obj, *args, **kwargs):
        if handler_obj.server.mode == 'slot' and \
                handler_obj.server.auth_base64 and \
                not check_authorization(handler_obj):
            handler_obj.send_error(code=httplib.UNAUTHORIZED)
            return
        else:
            return func(handler_obj, *args, **kwargs)

    return _wrapped


def proxy_auth_required(func):
    def check_proxy_authorization(handler_obj):
        value = handler_obj.headers.get('proxy-authorization')
        if value:
            if value.replace('Basic ', '').strip() == handler_obj.server.proxy_auth_base64:
                return True
        return False

    @functools.wraps(func)
    def _wrapped(handler_obj, *args, **kwargs):
        if handler_obj.server.proxy_auth_base64 and \
                not check_proxy_authorization(handler_obj):
            handler_obj.send_error(code=httplib.PROXY_AUTHENTICATION_REQUIRED)
            return
        else:
            return func(handler_obj, *args, **kwargs)

    return _wrapped


def auto_slot(func):
    @functools.wraps(func)
    def _wrapped(handler_obj, *args, **kwargs):
        if handler_obj.server.mode == 'slot':
            top_domain_name = get_top_domain_name(urlparse.urlparse(handler_obj.path).netloc)
            # foo.bar.com => bar.com, abc.foo.bar.com => bar.com
            node_host_port = handler_obj._get_or_put_free_node('http://' + top_domain_name)
            if node_host_port:
                msg = 'Using free proxy node: ' + node_host_port
                handler_obj.log_message(msg)

                try:
                    kwargs.update(dict(free_node_host_port=node_host_port))
                    func(handler_obj, *args, **kwargs)
                finally:
                    handler_obj._get_or_put_free_node('http://' + top_domain_name, node_host_port=node_host_port)
            else:
                msg = 'Free proxy node not found'
                handler_obj.send_error(code=httplib.SERVICE_UNAVAILABLE, message=msg)
                return
        else:
            return func(handler_obj, *args, **kwargs)

    return _wrapped


def auto_slot_connect(func):
    @functools.wraps(func)
    def _wrapped(handler_obj, *args, **kwargs):
        if handler_obj.server.mode == 'slot':
            OTHERS_DROP_HEADERS = ('Proxy-Connection', )
            handler_obj.headers_case_sensitive = HTTPHeadersCaseSensitive(
                lines=handler_obj.headers.headers,
                ignores=HTTPHeadersCaseSensitive.HOP_BY_HOP_HEADERS + OTHERS_DROP_HEADERS)

            host = handler_obj.path.split(':')[0] # 'tools.ietf.org:443' -> 'tools.ietf.org'
            top_domain_name = get_top_domain_name(host)
            # foo.bar.com => bar.com, abc.foo.bar.com => bar.com
            node_host_port = handler_obj._get_or_put_free_node('https://' + top_domain_name)
            if node_host_port:
                msg = 'Using free proxy node: ' + node_host_port
                handler_obj.log_message(msg)

                host, port = node_host_port.split(':')
                port = int(port)

                hostname, aliaslist, ipaddrlist = socket.gethostbyname_ex(host)
                ip_addr = random.choice(ipaddrlist)

                sock = socket.socket()
                try:
                    sock.connect((ip_addr, port))
                except socket.error, ex:
                    err_no, err_msg = ex.args
                    if err_no == errno.ECONNREFUSED:
                        handler_obj.send_error(httplib.SERVICE_UNAVAILABLE, message='connection refused')
                        return
                    raise ex


                msg = 'Forward request from user-agent %s to proxy node %s' % (handler_obj.client_address_string, node_host_port)
                handler_obj.log_message(msg)
                SocketHelper.send(sock, handler_obj.raw_requestline)
                for item in handler_obj.headers_case_sensitive.headers:
                    line = '%s: %s\r\n' % (item[0], item[1])
                    SocketHelper.send(sock, line)

                if handler_obj.server.mode == 'slot' and handler_obj.server.proxy_node_auth_base64:
                    line = 'Proxy-Authorization: Basic %s\r\n' % handler_obj.server.proxy_node_auth_base64
                    SocketHelper.send(sock, line)

                SocketHelper.send(sock, '\r\n')


                data = SocketHelper.recv_until(sock, '\r\n\r\n')
                msg = 'Forward request from proxy node %s to user-agent %s' % (node_host_port, handler_obj.client_address_string)
                handler_obj.log_message(msg)
                msg_resp = HTTPResponse(msg=data)

                handler_obj.wfile.write(msg_resp.first_line)
                handler_obj.log_request(msg_resp.status_code)

                for item in msg_resp.headers.headers:
                    line = '%s: %s\r\n' % (item[0], item[1])
                    handler_obj.wfile.write(line)
                handler_obj.wfile.write('\r\n')

                if msg_resp.status_code != httplib.OK:
                    sock.close()
                    handler_obj._get_or_put_free_node('https://' + top_domain_name, node_host_port=node_host_port)
                    return

                try:
                    kwargs.update(dict(sock=sock))
                    func(handler_obj, *args, **kwargs)
                finally:
                    handler_obj._get_or_put_free_node('https://' + top_domain_name, node_host_port=node_host_port)
            else:
                msg = 'Free proxy node not found'
                handler_obj.send_error(code=httplib.SERVICE_UNAVAILABLE, message=msg)
                return
        else:
            return func(handler_obj, *args, **kwargs)

    return _wrapped


def stat_request(func):
    @functools.wraps(func)
    def _wrapped(handler_obj, *args, **kwargs):
        handler_obj.server.lock.acquire()
        if handler_obj.server.mode == 'slot':
            handler_obj.server.stat_slot['requests'] += 1
            handler_obj.server.stat_slot['processing'] += 1
        else:
            handler_obj.server.stat_node['requests'] += 1
            handler_obj.server.stat_node['processing'] += 1
        handler_obj.server.lock.release()

        try:
            func(handler_obj, *args, **kwargs)

            handler_obj.server.lock.acquire()
            if handler_obj.server.mode == 'slot':
                handler_obj.server.stat_slot['proxy_requests'] += 1
            else:
                handler_obj.server.stat_node['proxy_requests'] += 1
            handler_obj.server.lock.release()
        except socket.timeout:
            msg = 'socket timeout, fd %d' % handler_obj.connection.fileno()
            handler_obj.log_message(msg)
        except socket.error, ex:
            err_no = ex.args[0]
            if err_no == errno.EPIPE:
                msg = 'broken pipe, fd %d' % handler_obj.connection.fileno()
                handler_obj.log_message(msg)
            else:
                raise ex

        except Exception:
            traceback.print_exc(file=sys.stderr)

        finally:
            handler_obj.server.lock.acquire()
            if handler_obj.server.mode == 'slot':
                handler_obj.server.stat_slot['processing'] -= 1
            else:
                handler_obj.server.stat_node['processing'] -= 1
            handler_obj.server.lock.release()

        return True

    return _wrapped


def test_proxy_node(down_node_list, node_host_port, proxy_node_auth_base64, timeout, lock=None):
    def _():
        chunks = [
            'GET http://baidu.com/ HTTP/1.1',
            'Host: baidu.com',
            'Connection: close',
        ]
        if proxy_node_auth_base64:
            chunks.append('Proxy-Authorization: Basic ' + proxy_node_auth_base64)
        msg_http_req = '\r\n'.join(chunks) + '\r\n\r\n'

        splits = node_host_port.split(':')
        if len(splits) == 2:
            host, port = splits[0], int(splits[1])
        else:
            host, port = splits[0], 80

        sock = socket.socket()
        sock.settimeout(timeout)
        sock.connect((host, port))

        sock.sendall(msg_http_req)

        buf = SocketHelper.recv_until(sock, '\r\n\r\n')
        msg_resp = HTTPResponse(buf)

        if msg_resp.status_code != httplib.OK or msg_resp.reason != 'OK':
            return False

        cl = msg_resp.headers.get_value('Content-Length')
        if cl is None:
            return False
        body = SocketHelper.recv_all(sock, int(cl))

        if body.find('http://www.baidu.com/') != -1:
            return True
        return False

    try:
        if not _():
            if lock and hasattr(lock, 'acquire'):
                lock.acquire()
                down_node_list[node_host_port] = 'un-expected repsonse'
                lock.release()
    except Exception, ex:
        traceback.print_exc(file=sys.stderr)

        if lock and hasattr(lock, 'acquire'):
            lock.acquire()
            down_node_list[node_host_port] = str(ex)
            lock.release()

        return False


def update_node_status(httpd_inst):
    thread_lock = threading.Lock()

    try:
        print >> sys.stdout, '%s started' % multiprocessing.current_process().name

        while True:

            httpd_inst.lock.acquire()
            my_proxy_list = copy.deepcopy(httpd_inst.node_list)
            httpd_inst.lock.release()

            down_node_list = dict()
            node_test_max_concurrency = int(httpd_inst.settings_slot['node_test_max_concurrency'])

            time_s = time.time()
            print >> sys.stdout, 'Test proxy nodes started, node_test_max_concurrency = %d' % node_test_max_concurrency

            for range_start in range(0, len(my_proxy_list), node_test_max_concurrency):
                proxy_node_parts = list(my_proxy_list)[range_start:range_start + int(node_test_max_concurrency)]

                thread_list = []
                for idx in range(len(proxy_node_parts)):
                    kwargs = dict(lock=thread_lock,
                                  down_node_list=down_node_list,
                                  node_host_port=proxy_node_parts[idx]['_host_port'],
                                  proxy_node_auth_base64=httpd_inst.proxy_node_auth_base64,
                                  timeout=float(httpd_inst.settings_slot['node_kick_slow_than']))
                    t = threading.Thread(target=test_proxy_node, kwargs=kwargs)
                    thread_list.append(t)
                [t.start() for t in thread_list]
                [t.join() for t in thread_list]

            time_e = time.time()
            print >> sys.stdout, 'Test proxy nodes finished, total nodes %d in %f seconds' % (len(my_proxy_list), time_e - time_s)

            httpd_inst.lock.acquire()
            for idx in range(len(httpd_inst.node_list)):
                item = httpd_inst.node_list[idx]
                if item['_host_port'] in down_node_list:
                    item['_status'] = ProxyNodeStatus.DELETED_OR_DOWN
                    print >> sys.stdout, 'Test %s got %s, kick it from proxy list' % (item['_host_port'], down_node_list[item['_host_port']])
                else:
                    item['_status'] = ProxyNodeStatus.UP_AND_RUNNING
                httpd_inst.node_list[idx] = item
            httpd_inst.lock.release()

            time.sleep(float(httpd_inst.settings_slot['node_check_interval']))
    finally:
        httpd_inst.server_close()


class SocketHelper(object):
    @staticmethod
    def send(fd, data):
        total = len(data)
        sent = 0
        while sent < total:
            if hasattr(fd, 'write'):
                count = fd.write(data[sent:])
            elif hasattr(fd, 'send'):
                count = fd.send(data[sent:])
            else:
                raise TypeError
            sent += count
        return total - sent

    @staticmethod
    def recv_until(fd, until, size=1):
        data = ''
        while data.find(until) == -1:
            if hasattr(fd, 'read'):
                buf = fd.read(size)
            elif hasattr(fd, 'recv'):
                buf = fd.recv(size)
            else:
                raise TypeError
            if not buf:
                break
            data += buf
        return data

    @staticmethod
    def recv_all(fd, size):
        chunks = []
        total = size
        while total > 0:
            if hasattr(fd, 'read'):
                chunk = fd.read(total)
            elif hasattr(fd, 'recv'):
                chunk = fd.recv(total)
            else:
                raise TypeError
            chunks.append(chunk)
            total -= len(chunk)
        return ''.join(chunks)


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
    def __init__(self, msg):
        self.raw = msg
        self.first_line = None
        self.headers = None
        self.body = None
        self.parse_msg()

    def parse_first_line(self):
        pass

    def parse_msg(self):
        splits = self.raw.split('\r\n\r\n')
        if len(splits) == 2:
            first_line_headers, body = splits[0], splits[1]
        else:
            first_line_headers = splits[0]

        lines = [i for i in first_line_headers.split('\r\n') if i]
        self.first_line = lines[0]
        self.headers = HTTPHeadersCaseSensitive(lines=lines[1:])

    def is_chunked(self):
        cl = self.headers.get_value('Content-Length')
        te = self.headers.get_value('Transfer-Encoding')
        return cl is None and te and te.lower() == 'chunked'

    @staticmethod
    def read_chunks(fd):
        # http://tools.ietf.org/html/rfc2616#section-3.6.1
        while True:
            chunk = SocketHelper.recv_until(fd, '\r\n')
            if not chunk:
                break
            splits = chunk.rstrip('\r\n').split(';')
            chunk_size = int(splits[0], 16)
            if len(splits) > 1:
                chunk_ext_list = splits[1:]
            if chunk_size is 0: # last-chunk
                SocketHelper.recv_all(fd, 2) # skip last CRLF
                break
            chunk_data = SocketHelper.recv_all(fd, chunk_size)
            SocketHelper.recv_all(fd, 2) # skip CRLF
            yield chunk_data


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


class ProxyNodeStatus(object):
    DELETED_OR_DOWN = 0
    UP_AND_RUNNING = 1


def handler_home(handler_obj):
    chunks = [
        "<html><head><title>Welcome to POPS!</title></head><body>",
        "<h1>Welcome to POPS!</h1>",
        "<p><a href=\"https://github.com/shuge/pops/wiki\" target=\"_blank\">documentation</a>",
        "</body></html>\n",
    ]
    body = "".join(chunks)
    handler_obj.send_response(httplib.OK)
    handler_obj.send_header('Content-Type', 'text/html; charset=utf-8')
    handler_obj.send_header('Content-Length', str(len(body)))
    handler_obj.end_headers()
    handler_obj.wfile.write(body)


def handler_favicon(handler_obj):
    handler_obj.send_response(httplib.NOT_FOUND)
    handler_obj.send_header('Connection', 'close')
    handler_obj.end_headers()


def host_port_in_node_list(node_list, host_port):
    for item in node_list:
        if item['_host_port'] == host_port:
            return True
    return False


def fix_host_port(s):
    if s.find(':') == -1:
        return s + ':1080'
    return s


@auth_required
def handler_admin(handler_obj):
    if handler_obj.server.mode != 'slot':
        handler_obj.send_error(httplib.NOT_FOUND)
        # handler_obj.send_response(httplib.NOT_FOUND)
        # handler_obj.send_header('Connection', 'close')
        # handler_obj.end_headers()
        return

    parse = urlparse.urlparse(handler_obj.path)
    qs_in_d = urlparse.parse_qs(parse.query)

    if parse.path in ['/admin/node/add']:
        addr_list = [i.strip() for i in qs_in_d['addr'][0].split(',')]

        handler_obj.server.lock.acquire()

        for host_port in addr_list:
            host_port = fix_host_port(host_port)
            if parse.path == '/admin/node/add':
                if not host_port_in_node_list(handler_obj.server.node_list, host_port):
                    item = dict(
                        _status=ProxyNodeStatus.UP_AND_RUNNING,
                        _host_port=host_port,
                    )
                    handler_obj.server.node_list.append(item)
                handler_obj.log_message('Appended %s into node list' % host_port)

        handler_obj.server.lock.release()

        handler_obj.send_response(httplib.OK)
        handler_obj.send_header('Connection', 'close')
        handler_obj.end_headers()
        return

    elif parse.path == '/admin/node/delete':
        addr_list = set([i.strip() for i in qs_in_d['addr'][0].split(',')])

        handler_obj.server.lock.acquire()

        for host_port in addr_list:
            host_port = fix_host_port(host_port)
            for item in handler_obj.server.node_list:
                if item['_host_port'] == host_port:
                    handler_obj.server.node_list.remove(item)
                    handler_obj.log_message('Delete proxy node %s' % host_port)

        handler_obj.server.lock.release()

        handler_obj.send_response(httplib.OK)
        handler_obj.send_header('Connection', 'close')
        handler_obj.end_headers()
        return

    elif parse.path == '/admin/settings/update':
        k, v = qs_in_d['k'][0], qs_in_d['v'][0]

        handler_obj.server.lock.acquire()
        if k in handler_obj.server.settings_slot:
            handler_obj.server.settings_slot[k] = v
        handler_obj.server.lock.release()

        handler_obj.send_response(httplib.OK)
        handler_obj.send_header('Connection', 'close')
        handler_obj.end_headers()
        return

    handler_obj.send_error(httplib.NOT_FOUND)


@auth_required
def handler_stat(handler_obj):
    handler_obj.server.lock.acquire()

    migrated = dict(
        server_info=handler_obj.server.server_info,
    )

    if handler_obj.server.mode == 'slot':
        total_up_nodes = 0
        for item in handler_obj.server.node_list:
            if item['_status'] == ProxyNodeStatus.UP_AND_RUNNING:
                total_up_nodes += 1

        migrated.update(dict(
            stat_slot=handler_obj.server.stat_slot,

            settings_slot=handler_obj.server.settings_slot,
            node_list_idx=handler_obj.server.node_list_idx.value,
            total_up_nodes=total_up_nodes,

            total_nodes=len(handler_obj.server.node_list),
            node_list=handler_obj.server.node_list,
        ))
    else:
        migrated.update(dict(
            stat_node=handler_obj.server.stat_node,
        ))

    body = json.dumps(copy.deepcopy(migrated), indent=2) + "\n"

    handler_obj.server.lock.release()

    handler_obj.send_response(httplib.OK)
    handler_obj.send_header('Content-Type', 'application/json')
    handler_obj.send_header('Content-Length', str(len(body)))
    handler_obj.send_header('Access-Control-Allow-Origin', '*')
    handler_obj.end_headers()
    if handler_obj.command != 'HEAD':
        handler_obj.wfile.write(body)


non_proxy_req_handler_list = (
    ('^$', handler_home),
    ('^favicon.ico$', handler_favicon),

    ('^stat/', handler_stat),
    ('^admin/', handler_admin),
)


class HandlerClass(BaseHTTPServer.BaseHTTPRequestHandler):
    server_version = "POPS/" + __version__
    protocol_version = "HTTP/1.1"
    sys_version = ""

    def setup(self):
        BaseHTTPServer.BaseHTTPRequestHandler.setup(self)

        # If client doesn't send request in 3 seconds,
        # server will auto terminate it.
        # See also: http://yyz.us/bitcoin/poold.py
        self.request.settimeout(SERVER_RECV_TEIMOUT)

        self.headers_case_sensitive = None

    def handle(self):
        try:
            BaseHTTPServer.BaseHTTPRequestHandler.handle(self)
        except IOError:
            self.close_connection = 1
            self.connection.close()

    @property
    def client_address_string(self):
        return '%s:%d' % (self.client_address[0], self.client_address[1])

    def send_error(self, code, message=None):
        try:
            short, long = self.responses[code]
        except KeyError:
            short, long = '???', '???'
        if message is None:
            message = short
        explain = long

        # using _quote_html to prevent Cross Site Scripting attacks (see bug #1100201)
        content = (self.error_message_format %
                   {'code': code, 'message': BaseHTTPServer._quote_html(message), 'explain': explain})
        self.send_response(code, message)
        self.send_header("Content-Type", self.error_content_type)
        self.send_header('Connection', 'close')
        self.end_headers()
        if self.command != 'HEAD' and code >= 200 and code not in (204, 304):
            self.wfile.write(content)

    def is_valid_proxy_req(self):
        parses = urlparse.urlparse(self.path) # self.path => 'http://baidu.com'
        if parses.scheme and parses.netloc: # parses.scheme => 'http://', parses.netloc => 'baidu.com'
            OTHERS_DROP_HEADERS = ('Proxy-Connection', )
            self.headers_case_sensitive = HTTPHeadersCaseSensitive(
                lines=self.headers.headers,
                ignores=HTTPHeadersCaseSensitive.HOP_BY_HOP_HEADERS + OTHERS_DROP_HEADERS)

            # We always rewrite Host field.
            # http://tools.ietf.org/html/rfc2616#section-14.23
            self.headers_case_sensitive.add_header('Host', parses.netloc, override=True)
            return True
        else:
            self._do_GET_for_non_proxy_req()
            return False

    def _get_or_put_free_node(self, top_domain_name, node_host_port=None):
        free_node_host_port = None

        self.server.lock.acquire()
        # NOTICE: http://docs.python.org/2/library/multiprocessing.html#multiprocessing.managers.SyncManager.list

        if not self.server.node_list:
            self.server.lock.release()
            return

        try:
            if (self.server.node_list_idx.value + 1) > len(self.server.node_list):
                self.server.node_list_idx.value = 0
            offset = self.server.node_list_idx.value

            for idx in range(len(self.server.node_list[offset:])):
                item = self.server.node_list[offset + idx]

                concurrency = item.get(top_domain_name, 0)
                # this proxy allow to crawl records from this domain name in concurrency mode
                if not node_host_port:
                    if (concurrency < int(self.server.settings_slot['node_per_domain_max_concurrency'])) and \
                            (int(item['_status']) > ProxyNodeStatus.DELETED_OR_DOWN):
                        if top_domain_name in item:
                            item[top_domain_name] += 1
                        else:
                            item.update({top_domain_name: 1})
                        free_node_host_port = item['_host_port']
                        self.server.node_list_idx.value += 1
                        break
                else:
                    if item['_host_port'] == node_host_port:
                        if top_domain_name in item:
                            item[top_domain_name] += -1
                        else:
                            item[top_domain_name] = 0

                        if item[top_domain_name] < 0: # reset it's concurrency count for exception
                            item[top_domain_name] = 0
                        break

                self.server.node_list[offset + idx] = item
        finally:
            self.server.lock.release()

        return free_node_host_port

    def _do_GET_for_non_proxy_req(self):
        map = dict(non_proxy_req_handler_list)
        for path_in_re in map.keys():
            left_slash_stripped = self.path[1:]
            if re.compile(path_in_re).match(left_slash_stripped):
                return map[path_in_re](self)
        self.send_error(httplib.NOT_FOUND)

    def do_HEAD(self):
        return self.do_GET()

    def do_GET(self):
        if not self.is_valid_proxy_req():
            return

        self._forward_req()

    def do_POST(self):
        if not self.is_valid_proxy_req():
            return

        body_length = int(self.headers.get('content-length', 0))
        body = self.rfile.read(body_length)
        self._forward_req(body=body)

    @stat_request
    @proxy_auth_required
    @auto_slot_connect
    def do_CONNECT(self, sock=None):
        """
        FIXME: node doesn't response in China network, re-product with
            curl -i --proxy localhost https://twitter.com
        """
        if sock:
            sock_dst = sock
        else:
            host, port = self.path.split(':')
            port = int(port)

            hostname, aliaslist, ipaddrlist = socket.gethostbyname_ex(host)
            ip_addr = random.choice(ipaddrlist)

            sock_dst = socket.socket()
            try:
                sock_dst.connect((ip_addr, port))
            except socket.timeout:
                return self.send_error(httplib.GATEWAY_TIMEOUT, message='Forwarding failure')
            except socket.error, ex:
                err_no = ex.args[0]
                if err_no == errno.ECONNREFUSED:
                    return self.send_error(httplib.SERVICE_UNAVAILABLE, message='Forwarding failure')
                raise ex

            self.send_response(httplib.OK, message='Connection established')
            self.send_header('Proxy-Agent', self.server_version)
            self.end_headers()


        sock_src_shutdown, sock_dst_shutdown = False, False
        while (not sock_src_shutdown) and (not sock_dst_shutdown):
            read_list = []
            if not sock_dst_shutdown:
                read_list.append(sock_dst)
            if not sock_src_shutdown:
                read_list.append(self.connection)
            ready_rlist, ready_wlist, ready_elist = select.select(read_list, [], read_list)
            assert not ready_elist
            for sock in ready_rlist:
                if sock == self.connection:
                    try:
                        data = self.connection.recv(RECV_BUF_SIZE)
                    except socket.error, ex:
                        data = None
                        err_no = ex.args[0]
                        if err_no == errno.ECONNRESET:
                            sock_src_shutdown = True
                        else:
                            raise ex
                    if data:
                        remain = SocketHelper.send(sock_dst, data)
                        if remain:
                            msg = 'Client sent %d bytes to target, remain %d bytes' % (len(data), remain)
                            self.log_message(msg)
                    else:
                        msg = 'Client sent nothing, it seems has disconnected'
                        self.log_message(msg)
                        sock_src_shutdown = True
                elif sock == sock_dst:
                    try:
                        data = sock_dst.recv(RECV_BUF_SIZE)
                    except socket.error, ex:
                        data = None
                        err_no = ex.args[0]
                        if err_no == errno.ECONNRESET:
                            sock_dst_shutdown = True
                        else:
                            raise ex
                    if data:
                        self.wfile.write(data)
                        # remain = SocketHelper.send(self.connection, data)
                        # if remain:
                        #     msg = 'Target sent %d bytes to client, remain %d bytes' % (len(data), remain)
                        #     self.log_message(msg)
                    else:
                        msg = 'Target sent nothing, it seems has disconnected'
                        self.log_message(msg)
                        sock_dst_shutdown = True

    @stat_request
    @proxy_auth_required
    @auto_slot
    def _forward_req(self, body=None, free_node_host_port=None):
        sock = socket.socket()
        sock.settimeout(PROXY_SEND_RECV_TIMEOUT)

        if self.server.mode == 'slot':
            splits = free_node_host_port.split(':')
            if len(splits) == 2:
                host, port = splits[0], int(splits[1])
            else:
                host, port = splits[0], 1080

            try:
                sock.connect((host, port))
            except socket.timeout:
                return self.send_error(httplib.GATEWAY_TIMEOUT)
            except socket.error, ex:
                err_no = ex.args[0]
                if err_no == errno.ECONNREFUSED:
                    return self.send_error(httplib.BAD_GATEWAY)
                raise ex

            sock_addr = free_node_host_port
            request_uri = self.path
        else:
            parses = urlparse.urlparse(self.path)
            sock_addr = parses.netloc

            splits = sock_addr.split(':')
            if len(splits) == 2:
                host, port = splits[0], int(splits[1])
            else:
                host, port = splits[0], 80

            hostname, aliaslist, ipaddrlist = socket.gethostbyname_ex(host)
            ip_addr = random.choice(ipaddrlist)
            try:
                sock.connect((ip_addr, port))
            except socket.timeout:
                return self.send_error(httplib.GATEWAY_TIMEOUT)
            except socket.error, ex:
                err_no = ex.args[0]
                if err_no == errno.ECONNREFUSED:
                    return self.send_error(httplib.BAD_GATEWAY)
                raise ex

            request_uri = parses.path or '/'
            if parses.query:
                request_uri += '?' + parses.query
            if parses.fragment:
                request_uri += '#' + parses.fragment

        request_line = '%s %s %s\r\n' % (self.command, request_uri, self.request_version)

        SocketHelper.send(sock, request_line)

        for item in self.headers_case_sensitive.headers:
            line = '%s: %s\r\n' % (item[0], item[1])
            SocketHelper.send(sock, line)

        if self.server.mode == 'slot' and self.server.proxy_node_auth_base64:
            line = 'Proxy-Authorization: Basic %s\r\n' % self.server.proxy_node_auth_base64
            SocketHelper.send(sock, line)

        SocketHelper.send(sock, '\r\n')

        if body:
            SocketHelper.send(sock, body)

        self._forward_resp(sock, sock_addr)

    def _forward_resp(self, sock, sock_addr):
        s = SocketHelper.recv_until(sock, '\r\n\r\n')
        msg_resp = HTTPResponse(msg=s)

        line = msg_resp.first_line + '\r\n'
        self.wfile.write(line)

        self.log_request(msg_resp.status_code)

        if self.command != 'HEAD' and \
                        msg_resp.status_code >= httplib.OK and \
                        msg_resp.status_code not in (httplib.NO_CONTENT, httplib.NOT_MODIFIED):
            cl = msg_resp.headers.get_value('Content-Length')

            if cl is not None:
                self._forward_resp_with_content_length(sock, sock_addr, msg_resp, int(cl))
            elif msg_resp.is_chunked():
                msg = "Target server response body in chunked"
                self.log_message(msg)

                if self.request_version >= "HTTP/1.1":
                    self._forward_resp_in_chunked_for_ge_http11(sock, msg_resp)
                else:
                    self._forward_resp_in_chunked_for_lt_http11(sock, msg_resp)
            else:
                self._forward_resp_no_content_length_and_no_chunked(sock, sock_addr, msg_resp)
        else:
            for item in msg_resp.headers.headers:
                k, v = item[0], item[1]
                self.send_header(k, v)
            self.end_headers()

    def _forward_resp_with_content_length(self, sock, sock_addr, msg_resp, cl):
        body = SocketHelper.recv_all(sock, cl)

        ts_ce = msg_resp.headers.get_value('Content-Encoding', default='')
        ua_ce = self.headers_case_sensitive.get_value('Accept-Encoding', default='')

        if ts_ce.find('gzip') != -1 and ua_ce.find('gzip') == -1:
            gz = gzip.GzipFile(fileobj=StringIO.StringIO(body))
            body = gz.read()
            msg_resp.headers.add_header('Content-Length', str(len(body)), override=True)

            msg = "Target server response body in gzip, but client doesn't supports gzip"
            self.log_message(msg)

        msg_resp.headers.filter_headers(HTTPHeadersCaseSensitive.HOP_BY_HOP_HEADERS)

        for item in msg_resp.headers.headers:
            k, v = item[0], item[1]
            self.send_header(k, v)
        self.end_headers()

        self.wfile.write(body)

    def _forward_resp_in_chunked_for_ge_http11(self, sock, msg_resp):
        msg_resp.headers.add_header('Transfer-Encoding', 'chunked', override=True)

        ts_ce = msg_resp.headers.get_value('Content-Encoding', default='')
        ua_ce = self.headers_case_sensitive.get_value('Accept-Encoding', default='')

        using_gzip = True
        if ts_ce.find('gzip') != -1 and ua_ce.find('gzip') == -1:
            using_gzip = False
            msg_resp.headers.filter_headers(('Content-Encoding', ))

            msg = "Target server response body in gzip, and client doesn't supports gzip"
            self.log_message(msg)

        for item in msg_resp.headers.headers:
            k, v = item[0], item[1]
            self.send_header(k, v)
        self.end_headers()

        for line in HTTPMessage.read_chunks(sock):
            if not using_gzip:
                gz = gzip.GzipFile(fileobj=StringIO.StringIO(line))
                line = gz.read()

            chunk_size = len(line)
            self.wfile.write(hex(chunk_size)[2:] + '\r\n')
            self.wfile.write(line + '\r\n')
        self.wfile.write('0\r\n')
        self.wfile.write('\r\n')

    def _forward_resp_in_chunked_for_lt_http11(self, sock, msg_resp):
        msg_resp.headers.filter_headers(('Transfer-Encoding', ))

        ts_ce = msg_resp.headers.get_value('Content-Encoding', default='')
        ua_ce = self.headers_case_sensitive.get_value('Accept-Encoding', default='')

        using_gzip = True
        if ts_ce.find('gzip') != -1 and ua_ce.find('gzip') == -1:
            using_gzip = False
            msg_resp.headers.filter_headers(('Content-Encoding', ))

            msg = "Target server response body in gzip, and client doesn't supports gzip"
            self.log_message(msg)

        chunk_data_list = []
        for line in HTTPMessage.read_chunks(sock):
            chunk_data_list.append(line)
        body = ''.join(chunk_data_list)

        if not using_gzip:
            gz = gzip.GzipFile(fileobj=StringIO.StringIO(body))
            body = gz.read()

        msg_resp.headers.add_header('Content-Length', str(len(body)), override=True)

        for item in msg_resp.headers.headers:
            k, v = item[0], item[1]
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def _forward_resp_no_content_length_and_no_chunked(self, sock, sock_addr, msg_resp):
        for item in msg_resp.headers.headers:
            k, v = item[0], item[1]
            line = '%s: %s\r\n' % (item[0], item[1])
            self.send_header(k, v)
        self.end_headers()

        while True:
            buf = sock.recv(RECV_BUF_SIZE)
            if not buf:
                break
            self.wfile.write(buf)


def serve_forever(httpd_inst):
    try:
        print >> sys.stdout, '%s started' % multiprocessing.current_process().name
        httpd_inst.serve_forever()
    finally:
        httpd_inst.server_close()


class POPServer(BaseHTTPServer.HTTPServer):
    allow_reuse_address = True
    args = None
    auth_base64 = None
    proxy_auth_base64 = None

    @property
    def server_address_string(self):
        return '%s:%d' % (self.server_address[0], self.server_address[1])


def main(args):
    server_address = (args.addr, args.port)
    pid = os.getpid()
    processes = int(args.processes)

    if hasattr(args.error_log, 'name'):
        error_log_path = getattr(args.error_log, 'name')
    else:
        error_log_path = args.error_log or '/dev/stdout'

    httpd_inst = POPServer(server_address, HandlerClass)
    httpd_inst.mode = args.mode

    if args.auth:
        httpd_inst.auth_base64 = base64.encodestring(args.auth).strip()

    if args.proxy_auth:
        httpd_inst.proxy_auth_base64 = base64.encodestring(args.proxy_auth).strip()

    if args.proxy_node_auth:
        httpd_inst.proxy_node_auth_base64 = base64.encodestring(args.proxy_node_auth).strip()

    httpd_inst.mp_manager = multiprocessing.Manager()
    httpd_inst.node_list = httpd_inst.mp_manager.list()
    httpd_inst.lock = multiprocessing.Lock()
    httpd_inst.node_list_idx = multiprocessing.Value('i', 0)

    httpd_inst.stat_node = httpd_inst.mp_manager.dict(dict(
        requests=0,
        processing=0,
        proxy_requests=0,
    ))

    httpd_inst.stat_slot = httpd_inst.mp_manager.dict(dict(
        requests=0,
        processing=0,
        proxy_requests=0,
    ))

    # READ-ONLY info
    httpd_inst.server_info = httpd_inst.mp_manager.dict(dict(
        service_mode=httpd_inst.mode,
        cpu_count=multiprocessing.cpu_count(),
        processes=processes,
        serving_on="%s:%d" % (server_address[0], server_address[1]),
        pid=pid,
        error_log=error_log_path,
    ))

    httpd_inst.settings_slot = httpd_inst.mp_manager.dict(dict(
        node_per_domain_max_concurrency=1,
        node_check_interval=60,
        node_kick_slow_than=5,
        node_test_max_concurrency=50,
    ))

    for i in range(processes):
        p = multiprocessing.Process(target=serve_forever, args=(httpd_inst,))
        if args.daemon:
            p.daemon = args.daemon
        p.start()

    if httpd_inst.mode == 'slot':
        p = multiprocessing.Process(target=update_node_status, name='UpdateNodeStatusProcess', args=(httpd_inst,))
        if args.daemon:
            p.daemon = args.daemon
        p.start()

    if httpd_inst.mode == 'node':
        srv_name = 'node'
    else:
        srv_name = 'slot'
    print >> sys.stdout, "POPS %s started, listen on %s:%s, pid %d" % (srv_name, server_address[0], server_address[1], pid)

    serve_forever(httpd_inst)


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


class MyDaemonRunner(runner.DaemonRunner):
    def __init__(self, app, action):
        self.action = action
        runner.DaemonRunner.__init__(self, app)

    def parse_args(self, *args, **kwargs): pass


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

    parser.add_argument('--processes',
                        default=multiprocessing.cpu_count(),
                        help='default cat /proc/cpuinfo | grep processor | wc -l')

    parser.add_argument('--error_log',
                        help='default /dev/null')

    parser.add_argument('--pid')

    parser.add_argument('--daemon', action='store_true')

    parser.add_argument('--stop',
                        action='store_true',
                        help='default start')

    args = parser.parse_args()

    if args.daemon or args.stop:
        if not args.pid:
            sys.stderr.write("You must set `--pid /path/to/pid` for `--daemon`.\n")
            sys.exit(1)

        if args.stop:
            action = 'stop'
        else:
            action = 'start'

        d_runner = MyDaemonRunner(MyDaemon(args), action)
        d_runner.do_action()
    else:
        main(args)
