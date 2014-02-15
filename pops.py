#!/usr/bin/env python
import argparse
import base64
import cgi
import copy
import errno
import functools
import logging
import mimetools
import re
import threading
import time
import json
import os
import BaseHTTPServer
import httplib
import multiprocessing
import socket
import sys
import StringIO
import traceback
import urlparse

from daemon import runner
import requests
import requests.auth
import requests.exceptions
import select


__version__ = "201401"


logging.basicConfig(format='%(asctime)s [%(levelname)s] [%(process)d] %(message)s',
                    datefmt='%Y-%m-%d %I:%M:%S',
                    level=logging.DEBUG)
logger = logging.getLogger(__name__)


class SocketHelper(object):

    @staticmethod
    def send(sock, data):
        total = len(data)
        sent = 0
        while sent < total:
            count = sock.send(data[sent:])
            sent += count
        return total - sent

    @staticmethod
    def recv_until(sock, until, BUFF_SIZE=4096):
        data = ''
        while data.find(until) == -1:
            buf = sock.recv(BUFF_SIZE)
            if not buf:
                break
            data += buf
        return data


class ProxyNodeStatus(object):

    DELETED_OR_DOWN = 0
    UP_AND_RUNNING = 1


def auth_required(func):
    def check_authorization(handler_obj):
        value = handler_obj.headers.getheader('authorization')
        if value:
            if value.replace('Basic ', '').strip() == handler_obj.server.auth_base64:
                return True
        return False

    @functools.wraps(func)
    def _wrapped(handler_obj, *args, **kwargs):          
        if handler_obj.server.auth and not check_authorization(handler_obj):
            handler_obj.send_response(httplib.UNAUTHORIZED)
            handler_obj.send_header('WWW-Authenticate', 'Basic realm="HelloWorld"')
            handler_obj.end_headers()
            return
        else:
            return func(handler_obj, *args, **kwargs)
    return _wrapped

def proxy_auth_required(func):
    def check_proxy_authorization(handler_obj):
        value = handler_obj.headers.getheader('proxy-authorization')
        if value:
            if value.replace('Basic ', '').strip() == handler_obj.server.proxy_auth_base64:
                return True
        return False

    @functools.wraps(func)
    def _wrapped(handler_obj, *args, **kwargs):          
        if handler_obj.server.proxy_auth and not check_proxy_authorization(handler_obj):                    
            handler_obj.send_response(httplib.PROXY_AUTHENTICATION_REQUIRED)
            handler_obj.send_header('Proxy-Authenticate', 'Basic realm="HelloWorld"')
            handler_obj.end_headers()
            return
        else:
            return func(handler_obj, *args, **kwargs)
    return _wrapped


def local_net_required(func):
    @functools.wraps(func)
    def _wrapped_view(handler_obj):
        ALLOW_HOSTS = ('127.0.0.1', 'localhost', socket.gethostname())

        if handler_obj.server.server_name in ALLOW_HOSTS:
            return func(handler_obj)
        else:
            handler_obj.send_error(code=httplib.FORBIDDEN, message='allow local net only')
            return
    return _wrapped_view

def request_stat_required(func):
    @functools.wraps(func)
    def _wrapped(handler_obj, *args, **kwargs):
        handler_obj.server.lock.acquire()
        handler_obj.server.server_stat['requests'] += 1
        handler_obj.server.server_stat['waiting_requests'] += 1
        handler_obj.server.lock.release()

        try:
            r = func(handler_obj, *args, **kwargs)
        except Exception:
            r = None
            traceback.print_exc(file=sys.stderr)
            handler_obj.send_error(httplib.INTERNAL_SERVER_ERROR)

        handler_obj.server.lock.acquire()
        handler_obj.server.server_stat['waiting_requests'] -= 1
        handler_obj.server.lock.release()
        return r
    return _wrapped

def default_body(handler_obj):
    handler_obj.send_response(httplib.OK)
    handler_obj.send_header('Content-Type', 'text/html; charset=utf-8')
    handler_obj.end_headers()

    entry_body = "<html><head><title>Welcome to POPS!</title></head><body>" \
                   "<h1>Welcome to POPS!</h1>" \
                    "</html>\n"
    handler_obj.wfile.write(entry_body)

def favicon(handler_obj):
    handler_obj.send_error(httplib.NOT_FOUND)


@auth_required
def stat(handler_obj):
    handler_obj.send_response(httplib.OK)
    handler_obj.send_header('Content-Type', 'application/json')
    handler_obj.end_headers()


    handler_obj.server.lock.acquire()
    proxy_list_d = copy.deepcopy(handler_obj.server.proxy_list)
    handler_obj.server.lock.release()

    total_up_nodes = 0
    for proxy_node_addr in proxy_list_d.keys():
        if proxy_list_d[proxy_node_addr]['_status'] == ProxyNodeStatus.UP_AND_RUNNING:
            total_up_nodes += 1

    server_stat_d = copy.deepcopy(handler_obj.server.server_stat)
    server_stat_d['total_up_nodes'] = total_up_nodes

    server_stat_d['total_nodes'] = len(proxy_list_d.keys())


    server_info_d = copy.deepcopy(handler_obj.server.server_info)

    server_settings_d = copy.deepcopy(handler_obj.server.server_settings)


    migrated = {
        'server_info': server_info_d,
        'server_stat': server_stat_d,
        'server_settings': server_settings_d,
        'proxy_list': proxy_list_d,
    }
    entry_body = json.dumps(migrated, indent=2) + "\n"

    if handler_obj.command != 'HEAD':
        handler_obj.wfile.write(entry_body)


@local_net_required
@auth_required
def admin(handler_obj):
    parse = urlparse.urlparse(handler_obj.path)
    qs_in_d = urlparse.parse_qs(parse.query)

    if handler_obj.server.server_info['service_mode'] != 'slot':
        handler_obj.send_error(httplib.NOT_FOUND)
        return

    if parse.path in ['/admin/node/add', '/admin/node/reset']:
        addr_list = [i.strip() for i in qs_in_d['addr'][0].split(',')]

        handler_obj.server.lock.acquire()
        my_proxy_list = copy.deepcopy(handler_obj.server.proxy_list)

        for new_proxy_sever in addr_list:
            if parse.path == '/admin/node/add':
                if new_proxy_sever not in my_proxy_list:
                    my_proxy_list[new_proxy_sever] = {
                        '_status': ProxyNodeStatus.UP_AND_RUNNING,
                    }
                handler_obj.log_message('Appended %s into proxy list' % new_proxy_sever)
            elif parse.path == '/admin/node/reset':
                if new_proxy_sever in my_proxy_list:
                    my_proxy_list[new_proxy_sever] = {
                        '_status': ProxyNodeStatus.UP_AND_RUNNING,
                    }
                handler_obj.log_message('Appended %s into proxy list' % new_proxy_sever)

        handler_obj.server.proxy_list.clear()
        handler_obj.server.proxy_list.update(my_proxy_list)
        handler_obj.server.lock.release()

        handler_obj.send_response(httplib.OK)
        return


    elif parse.path == '/admin/node/delete':
        addr_list = set([i.strip() for i in qs_in_d['addr'][0].split(',')])

        handler_obj.server.lock.acquire()
        my_proxy_list = copy.deepcopy(handler_obj.server.proxy_list)

        for addr_ip_port in addr_list:
            if addr_ip_port in my_proxy_list:
                my_proxy_list.pop(addr_ip_port)
                handler_obj.log_message('Delete proxy node %s' % addr_ip_port)

        handler_obj.server.proxy_list.clear()
        handler_obj.server.proxy_list.update(my_proxy_list)
        handler_obj.server.lock.release()

        handler_obj.send_response(httplib.OK)
        return

    elif parse.path == '/admin/server_settings/update':
        k, v = qs_in_d['k'][0], qs_in_d['v'][0]

        handler_obj.server.lock.acquire()
        if k in handler_obj.server.server_settings:
            handler_obj.server.server_settings[k] = v
        handler_obj.server.lock.release()

        handler_obj.send_response(httplib.OK)
        return

    handler_obj.send_error(httplib.NOT_FOUND)


def ping(handler_obj):
    handler_obj.send_response(httplib.OK)
    handler_obj.send_header('Content-Type', 'text/plain')
    handler_obj.end_headers()

    if handler_obj.command != 'HEAD':
        handler_obj.wfile.write('pong')

def test(handler_obj):
    handler_obj.send_response(httplib.NOT_FOUND)


handler_list = (
    ('^$', default_body),
    ('^favicon.ico$', favicon),
    ('^stat/', stat),
    ('^admin/', admin),
    ('^ping/', ping),
    ('^test/', test),
)

def get_top_domain_name(s):
    if s.count('.') == 1:
        return s
    elif s.count('.') > 1:
        return s[s.index('.') + 1:]
    else:
        raise ValueError

def filter_hop_by_hop_headers(headers, ignore_header_list=None):
    # http://www.mnot.net/blog/2011/07/11/what_proxies_must_do
    HOP_BY_HOP_HEADERS = (
        'TE',
        'Transfer-Encoding',
        'Keep-Alive',
        'Proxy-Authorization',
        'Proxy-Authentication',
        'Trailer',
        'Upgrade',
    )
    drop_headers_in_lower_list = set(i.lower() for i in HOP_BY_HOP_HEADERS)
    if ignore_header_list:
        ignore_header_in_lower_list = set(i.lower() for i in ignore_header_list)
        drop_headers_in_lower_list = drop_headers_in_lower_list.union(ignore_header_in_lower_list)
    headers_filtered = {}
    for k in headers.keys():
        if k.lower() not in drop_headers_in_lower_list:
            headers_filtered[k] = headers[k]
    return headers_filtered

def drop_header_by_name(headers_filtered, name):
    drop_list = []
    for i in headers_filtered:
        if i.lower() == name.lower():
            drop_list.append(i)
    new_headers = {}
    for k in headers_filtered.keys():
        if k not in drop_list:
            new_headers[k] = headers_filtered[k]
    return new_headers


class HandlerClass(BaseHTTPServer.BaseHTTPRequestHandler):

    server_version = "POPS/" + __version__
    sys_version = ""

    def setup(self):
        BaseHTTPServer.BaseHTTPRequestHandler.setup(self)

        # If client doesn't send request in 3 seconds,
        # server will auto terminate it.
        # See also: http://yyz.us/bitcoin/poold.py
        self.request.settimeout(3)

    @property
    def client_address_string(self):
        return '%s:%d' % (self.client_address[0], self.client_address[1])

    def log_message(self, format, *args):
        logger.debug(format % args)

    def helper_print_request(self):
        print '*' * 40
        print self.requestline
        print self.headers
        print '*' * 40

    def do_HEAD(self):
        return self.do_GET()

    def do_GET(self):
        parses = urlparse.urlparse(self.path)
        if parses.scheme and parses.netloc:
            # self.requestline => 'GET http://baidu.com HTTP/1.1'
            # self.path => 'http://baidu.com'
            # parses.scheme => 'http://'
            # parses.netloc => 'baidu.com'
            self._do_GET_no_admin()
        else:
            # self.requestline => 'GET /stat/ HTTP/1.1'
            self._do_GET_admin()

    @request_stat_required
    @proxy_auth_required
    def _do_GET_no_admin(self):
        if self.server.server_info['service_mode'] == 'slot':
            request_target = self.path
            parses = urlparse.urlparse(request_target)
            top_domain_name = get_top_domain_name(parses.netloc)
            # foo.bar.com => bar.com, abc.foo.bar.com => bar.com

            free_proxy_node_addr = self._proxy_server_incr_concurrency('http://' + top_domain_name, step=1)
            if free_proxy_node_addr:
                msg = 'Using free proxy node: ' + free_proxy_node_addr
                logger.debug(msg)
                self._do_OTHERS_node_mode(free_proxy_node_addr=free_proxy_node_addr)
            else:
                msg = 'Free proxy node not found'
                logger.debug(msg)
                self.send_response(httplib.SERVICE_UNAVAILABLE)
                self.end_headers()
            self._proxy_server_incr_concurrency('http://' + top_domain_name, step=-1)
        else:
            self._do_OTHERS_node_mode()

    @auth_required
    def _do_GET_admin(self):
        map = dict(handler_list)
        for path_in_re in map.keys():
            left_slash_stripped = self.path[1:]
            if re.compile(path_in_re).match(left_slash_stripped):
                return map[path_in_re](self)
        self.send_error(httplib.NOT_FOUND)

    @request_stat_required
    @proxy_auth_required
    def do_POST(self):
        entry_body_length = int(self.headers.getheader('content-length', 0))
        content_type, ct_parameters_dict = cgi.parse_header(self.headers.getheader('content-type'))
        if entry_body_length:
            ignore_header_list = set(['Host'])
            filtered_headers_in_d = filter_hop_by_hop_headers(self.headers, ignore_header_list)

            # always rewrite it
            # http://tools.ietf.org/html/rfc2616#section-14.23
            # http://tools.ietf.org/html/rfc2616#section-5.2
            # http://tools.ietf.org/html/rfc2616#section-19.6.1.1
            request_target = self.path
            parses = urlparse.urlparse(request_target)
            filtered_headers_in_d['Host'] = parses.netloc

            if content_type == 'application/x-www-form-urlencoded':
                entry_body = self.rfile.read(entry_body_length)
                post_vars = urlparse.parse_qs(entry_body, keep_blank_values=1)
                self._do_OTHERS_node_mode(data=post_vars, headers=filtered_headers_in_d)
                return
            elif content_type == 'multipart/form-data':
                # post_vars = cgi.parse_multipart(self.rfile, ct_parameters_dict)
                # print 'post_vars', post_vars
                # self._do_OTHERS_node_mode(data=post_vars, headers=filtered_headers_in_d)
                # return
                self.send_error(httplib.NOT_IMPLEMENTED)
                return
        self._do_OTHERS_node_mode()

    @request_stat_required
    @proxy_auth_required
    def do_CONNECT(self):
        request_target = self.path
        host = request_target.split(':')[0]
        top_domain_name = get_top_domain_name(host)

        free_proxy_node_addr = self._proxy_server_incr_concurrency('https://' + top_domain_name, step=1)
        if free_proxy_node_addr:
            msg = 'Using free proxy node: ' + free_proxy_node_addr
            logger.debug(msg)

            if self.server.server_info['service_mode'] == 'slot':
                self._do_CONNECT_slot_mode(free_proxy_node_addr)
            else:
                self._do_CONNECT_node_mode()
        else:
            self.send_response(httplib.SERVICE_UNAVAILABLE)
            self.end_headers()

        conn_type = self.headers.get('Connection', "")
        if (conn_type.lower() != 'keep-alive' and self.protocol_version < "HTTP/1.1"):
            self.connection.close()

        self._proxy_server_incr_concurrency('https://' + top_domain_name, step=-1)

    def _do_CONNECT_slot_mode(self, free_proxy_node_addr):
        host, port = free_proxy_node_addr.split(':')
        port = int(port)

        sock_dst = socket.socket()
        try:
            sock_dst.connect((host, port))
        except socket.error, ex:
            err_no, err_msg = ex.args
            if err_no == errno.ECONNREFUSED:
                self.send_error(httplib.SERVICE_UNAVAILABLE)
                return
            raise ex

        handler_obj = self.raw_requestline + str(self.headers) + '\r\n'
        msg = 'Forward request from client %s to target %s: ' % (self.client_address_string, free_proxy_node_addr) + repr(handler_obj)
        logger.debug(msg)
        sock_dst.sendall(handler_obj)

        data = SocketHelper.recv_until(sock_dst, '\r\n' * 2)
        msg = 'Forward request from target %s to client %s: ' % (free_proxy_node_addr, self.client_address_string) + repr(data)
        logger.debug(msg)

        splits = data.rstrip('\r\n').split('\r\n')
        status_line = splits[0]
        splits = status_line.split(' ')
        status_code = int(splits[1])

        if status_code != httplib.OK:
            headers_in_str = '\r\n'.join(splits[1:])
            self.send_response(status_code)
            sio = StringIO.StringIO(headers_in_str)
            msg = mimetools.Message(sio)
            for k in msg.dict.keys():
                v = msg.dict[k]
                self.send_header(k, v)
            self.end_headers()
            return

        self._do_CONNECT_node_mode(sock_dst=sock_dst)
        sock_dst.close()
        
    def _do_CONNECT_node_mode(self, sock_dst=None):
        if not sock_dst:
            request_target = self.path
            host, port = request_target.split(':')
            port = int(port)

            sock_dst = socket.socket()
            try:
                sock_dst.connect((host, port))
            except socket.error, ex:
                err_no, err_msg = ex.args
                if err_no == errno.ECONNREFUSED:
                    self.send_error(httplib.SERVICE_UNAVAILABLE, message='Forwarding failure')
                    return
                elif err_no == errno.ETIMEDOUT:
                    self.send_error(httplib.SERVICE_UNAVAILABLE, message='Forwarding failure')
                    return
                raise ex

        self.send_response(httplib.OK, message='Connection established')
        self.send_header('Proxy-Agent', self.server_version)
        self.end_headers()

        BUFF_SIZE = 4096
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
                        data = self.connection.recv(BUFF_SIZE)
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
                            logger.debug(msg)
                    else:
                        msg = 'Client sent nothing, it seems has disconnected'
                        logger.debug(msg)
                        sock_src_shutdown = True
                elif sock == sock_dst:
                    try:
                        data = sock_dst.recv(BUFF_SIZE)
                    except socket.error, ex:
                        data = None
                        err_no = ex.args[0]
                        if err_no == errno.ECONNRESET:
                            sock_dst_shutdown = True
                        else:
                            raise ex
                    if data:
                        remain = SocketHelper.send(self.connection, data)
                        if remain:
                            msg = 'Target sent %d bytes to client, remain %d bytes' % (len(data), remain)
                            logger.debug(msg)
                    else:
                        msg = 'Target sent nothing, it seems has disconnected'
                        logger.debug(msg)
                        sock_dst_shutdown = True

        self.server.lock.acquire()
        self.server.server_stat['forward_requests'] += 1
        self.server.lock.release()

    def _proxy_server_incr_concurrency(self, top_domain_name, step=1):
        free_proxy_node_addr = None

        self.server.lock.acquire()
        # NOTICE: We have to do deepcopy and modify it, then re-assign it back,
        # see this for more detail http://docs.python.org/2/library/multiprocessing.html#multiprocessing.managers.SyncManager.list
        my_proxy_list = copy.deepcopy(self.server.proxy_list)
        try:
            for proxy_node_addr in my_proxy_list.keys():
                domain_name_map = my_proxy_list[proxy_node_addr]
                concurrency = domain_name_map.get(top_domain_name, 0)
                # this proxy allow to crawl records from this domain name in concurrency mode
                if step > 0:
                    if (concurrency < int(self.server.server_settings['node_per_domain_max_concurrency'])) and \
                            (int(domain_name_map['_status']) > ProxyNodeStatus.DELETED_OR_DOWN):
                        if top_domain_name in domain_name_map:
                            my_proxy_list[proxy_node_addr][top_domain_name] += step
                        else:
                            my_proxy_list[proxy_node_addr].update({top_domain_name: 1})
                        free_proxy_node_addr = proxy_node_addr
                        break
                else:
                    if top_domain_name in domain_name_map:
                        my_proxy_list[proxy_node_addr][top_domain_name] += step
                        if my_proxy_list[proxy_node_addr][top_domain_name] < 0:
                            my_proxy_list[proxy_node_addr][top_domain_name] = 0
                    else:
                        my_proxy_list[proxy_node_addr].update({top_domain_name: 0})

            self.server.proxy_list.clear()
            self.server.proxy_list.update(my_proxy_list)
        finally:
            self.server.lock.release()

        return free_proxy_node_addr

    def _do_OTHERS_node_mode(self, free_proxy_node_addr=None, data=None, headers=None):
        proxies = None
        auth = None
        if free_proxy_node_addr:
            proxies = {"http" : "http://" + free_proxy_node_addr}

            value = self.headers.getheader('proxy-authorization')
            if value:
                proxy_auth =  base64.decodestring(value.replace('Basic ', '').strip()).split(':')
                auth = requests.auth.HTTPProxyAuth(*proxy_auth)
            else:
                auth = None

        request_target = self.path
        url = request_target

        try:
            r = getattr(requests, self.command.lower())(
                url=url,
                data=data,
                proxies=proxies,
                headers=headers,
                timeout=float(self.server.server_settings['node_send_timeout_in_seconds']),
                auth=auth)

        except requests.exceptions.Timeout:
            self.log_error('Request %s timeout' % self.path)

            self.send_response(httplib.SERVICE_UNAVAILABLE)
            self.end_headers()
            return

        except requests.exceptions.ConnectionError:
            self.log_error('Request %s connection refused' % self.path)

            self.send_response(httplib.SERVICE_UNAVAILABLE)
            self.end_headers()
            return

        except socket.timeout:
            self.log_error('Request %s timeout' % self.path)

            self.send_response(httplib.SERVICE_UNAVAILABLE)
            self.end_headers()
            return


        entry_body = r.content
        status_code = r.status_code


        headers_filtered = filter_hop_by_hop_headers(r.headers)

        # TODO: We should not modified header 'Content-Encoding', fixed this in future.
        # because IETF standard said you should not, see also
        # http://tools.ietf.org/html/draft-ietf-httpbis-p1-messaging-14#section-7.1.3.2
        if len(entry_body):
            headers_filtered_in_lower_list = set(i.lower() for i in headers_filtered)
            if 'Content-Encoding'.lower() in headers_filtered_in_lower_list:
                headers_filtered = drop_header_by_name(headers_filtered, 'Content-Encoding')

            headers_filtered = drop_header_by_name(headers_filtered, 'Content-Length')
            headers_filtered['Content-Length'] = len(entry_body)

        # FIXME: filter duplicated headers
        # TODO: filter duplicated headers
        self.send_response(status_code)
        for k in headers_filtered.keys():
            self.send_header(k, headers_filtered[k])
        self.end_headers()

        if self.command != 'HEAD' and \
                        status_code >= httplib.OK and \
                        status_code not in (httplib.NO_CONTENT, httplib.NOT_MODIFIED):
            self.wfile.write(entry_body)

        self.server.lock.acquire()
        self.server.server_stat['proxy_requests'] += 1
        self.server.lock.release()


def test_http_proxy(down_node_list, proxy_node_addr, proxy_auth, timeout, lock=None):
    proxies = {'http': 'http://' + proxy_node_addr}

    try:
        r = requests.get(url='http://baidu.com/',
                         proxies=proxies,
                         timeout=timeout,
                         auth=proxy_auth)
        if r.status_code == httplib.OK or r.content.find('http://www.baidu.com/') != -1:
            return True

    except requests.exceptions.Timeout:
        lock.acquire()
        down_node_list[proxy_node_addr] = 'requests.exceptions.Timeout'
        lock.release()
        return False

    except requests.exceptions.ConnectionError:
        lock.acquire()
        down_node_list[proxy_node_addr] = 'requests.exceptions.ConnectionError'
        lock.release()
        return False

    except socket.timeout:
        lock.acquire()
        down_node_list[proxy_node_addr] = 'socket.Timeout'
        lock.release()
        return False

    except socket.error, ex:
        if ex[0] == errno.ECONNRESET:

            lock.acquire()
            down_node_list[proxy_node_addr] = 'socket errno.ECONNRESET'
            lock.release()

            return False

    if lock and hasattr(lock, 'acquire'):
        lock.acquire()
        down_node_list[proxy_node_addr] = 'unknown'
        lock.release()

    return False


def check_proxy_list(httpd_inst):
    thread_lock = threading.Lock()

    try:
        logger.info('%s started' % multiprocessing.current_process().name)

        while True:
            httpd_inst.lock.acquire()
            my_proxy_list = copy.deepcopy(httpd_inst.proxy_list)
            httpd_inst.lock.release()


            down_node_list = dict()
            node_test_max_concurrency = int(httpd_inst.server_settings['node_test_max_concurrency'])

            time_s = time.time()
            logger.debug('Test proxy nodes started, node_test_max_concurrency = %d' % node_test_max_concurrency)

            for range_start in range(0, len(my_proxy_list), node_test_max_concurrency):
                proxy_node_parts = list(my_proxy_list)[range_start:range_start + int(node_test_max_concurrency)]

                thread_list = []
                for idx in range(len(proxy_node_parts)):
                    kwargs = dict(lock=thread_lock,
                                  down_node_list=down_node_list,
                                  proxy_node_addr=proxy_node_parts[idx],
                                  proxy_auth=httpd_inst.proxy_auth,
                                  timeout=float(httpd_inst.server_settings['node_kick_slow_than']))
                    t = threading.Thread(target=test_http_proxy, kwargs=kwargs)
                    thread_list.append(t)
                [t.start() for t in thread_list]
                [t.join() for t in thread_list]

            time_e = time.time()
            logger.debug('Test proxy nodes finished, total nodes %d in %f seconds' % (len(my_proxy_list), time_e - time_s))

            httpd_inst.lock.acquire()

            for proxy_node_addr in my_proxy_list.keys():
                if proxy_node_addr in down_node_list:
                    my_proxy_list[proxy_node_addr]['_status'] = ProxyNodeStatus.DELETED_OR_DOWN
                    logger.debug('Test %s got %s, kick it from proxy list' % (proxy_node_addr, down_node_list[proxy_node_addr]))
                else:
                    my_proxy_list[proxy_node_addr]['_status'] = ProxyNodeStatus.UP_AND_RUNNING

            httpd_inst.proxy_list.clear()
            httpd_inst.proxy_list.update(my_proxy_list)

            httpd_inst.lock.release()

            time.sleep(float(httpd_inst.server_settings['node_check_interval']))

    except KeyboardInterrupt:
        pass

    except IOError:
        pass

    finally:
        httpd_inst.server_close()


def serve_forever(httpd_inst):
    try:
        logger.info('%s started' % multiprocessing.current_process().name)
        httpd_inst.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd_inst.server_close()


class POPServer(BaseHTTPServer.HTTPServer):

    allow_reuse_address = True
    protocol_version = "HTTP/1.1"

    lock = None
    proxy_list = None
    server_stat = None
    server_info = None
    server_settings = None

    auth = None
    auth_base64 = None

    proxy_auth = None
    proxy_auth_base64 = None



def main(args):
    server_address = (args.addr, args.port)
    httpd_inst = POPServer(server_address, HandlerClass)

    pid = os.getpid()
    processes = int(args.processes)
    if hasattr(args.error_log, 'name'):
        error_log_path = getattr(args.error_log, 'name')
    else:
        error_log_path = args.error_log or '/dev/stdout'

    if args.auth:
        splits = args.auth.split(':')
        httpd_inst.auth = requests.auth.HTTPBasicAuth(*splits)
        httpd_inst.auth_base64 = base64.encodestring(args.auth).strip()
    if args.proxy_auth:
        splits = args.proxy_auth.split(':')
        httpd_inst.proxy_auth = requests.auth.HTTPProxyAuth(*splits)
        httpd_inst.proxy_auth_base64 = base64.encodestring(args.proxy_auth).strip()


    mp_manager = multiprocessing.Manager()
    httpd_inst.mp_manager = mp_manager
    httpd_inst.lock = multiprocessing.Lock()

    httpd_inst.proxy_list = mp_manager.dict()

    httpd_inst.server_stat = mp_manager.dict({
        'waiting_requests': 0,
        'proxy_requests': 0,
        'forward_requests': 0,
        'requests': 0,
    })

    # READ-ONLY info
    httpd_inst.server_info = mp_manager.dict({
        'service_mode': args.mode,
        'cpu_count': multiprocessing.cpu_count(),
        'processes': processes,
        'serving_on': "%s:%d" % (server_address[0], server_address[1]),
        'pid': pid,
        'error_log': error_log_path,
    })


    srv_settings = dict(
        node_per_domain_max_concurrency = 1,
        node_send_timeout_in_seconds = 30.0,
        node_check_interval = 60.0,
        node_kick_slow_than = 5.0,
        node_test_max_concurrency = 50,
    )
    httpd_inst.server_settings = mp_manager.dict(srv_settings)

    for i in range(processes):
        p = multiprocessing.Process(target=serve_forever, args=(httpd_inst,))
        if args.daemon:
            p.daemon = args.daemon
        p.start()

    if httpd_inst.server_info['service_mode'] == 'slot':
        p = multiprocessing.Process(target=check_proxy_list, name='CheckProxyListProcess', args=(httpd_inst,))
        if args.daemon:
            p.daemon = args.daemon
        p.start()


    logger.info('POPS started pid %d' % pid)
    if httpd_inst.server_info['service_mode'] == "slot":
        srv_name = "HTTP proxy slot server"
    else:
        srv_name = "HTTP proxy server"
    logger.info("Serving %s on %s port %s ..."  % (srv_name, server_address[0], server_address[1]))


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

    def parse_args(self, *args, **kwargs):
        """
        We parse arguments by ourselves.
        """
        pass


if __name__ == "__main__":
    parser = argparse.ArgumentParser(prog=sys.argv[0], description='POPS')

    parser.add_argument('--auth',
                        default='god:hidemyass',
                        help='default god:hidemyass')

    parser.add_argument('--proxy_auth',
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

