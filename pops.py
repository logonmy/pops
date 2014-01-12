#!/usr/bin/env python
"""
Proxy of Proxy Sever

    client(s) ---> pops ---> HTTP proxy server A
                   |
                   +---> HTTP proxy server B
                   |
                   +---> HTTP proxy server C
                   |
                   +...
"""
import argparse
import base64
import copy
import functools
import logging
import re
import time
import json
import os
import BaseHTTPServer
import httplib
import multiprocessing
import socket
import sys
import traceback
import urlparse

from daemon import runner
import requests
import requests.auth
import requests.exceptions


__version__ = "201401"


PROXY_SERVER_PER_DOMAIN_MAX_CONCURRENCY = 1
PROXY_SERVER_SEND_TIMEOUT_IN_SECONDS = 5.0
LOGGING_USES_PROCESS_NAME_PREFIX = False
PROXY_SERVER_CHECK_INTERVAL_IN_SECONDS = 30.0
PROXY_SERVER_KICK_SLOW_THAN_IN_SECONDS = 5.0



logging.basicConfig(format='%(asctime)s [%(levelname)s] [%(process)d] %(message)s',
                    datefmt='%Y-%m-%d %I:%M:%S',
                    level=logging.DEBUG)
logger = logging.getLogger(__name__)


def www_auth_required(func):
    @functools.wraps(func)
    def _wrapped_view(req):
        value = req.headers.getheader('authorization')
        if value:
            basic_credentials = value.replace('Basic ', '').strip()
            if basic_credentials == req.server.args.auth_base64:
                return func(req)

        message, explain = req.responses[httplib.UNAUTHORIZED]
        entry_body = explain + "\n"

        req.send_response(httplib.UNAUTHORIZED)
        req.send_header('Content-Type', 'text/html; charset=utf-8')
        req.send_header('WWW-Authenticate', 'Basic realm="HelloWorld"')
        req.end_headers()

        if req.command != 'HEAD':
            req.wfile.write(entry_body)
        return
    return _wrapped_view


def default_body(req):
    req.send_response(httplib.OK)
    req.send_header('Content-Type', 'text/html; charset=utf-8')
    req.end_headers()

    entry_body = "<html><head><title>Welcome to POPS!</title></head><body>" \
                   "<h1>Welcome to POPS!</h1>" \
                    "</html>\n"
    req.wfile.write(entry_body)

def favicon(req):
    req.send_error(httplib.NOT_FOUND)


@www_auth_required
def stat(req):
    req.send_response(httplib.OK)
    req.send_header('Content-Type', 'application/json')
    req.end_headers()

    info_d = {
        'service_mode': req.server.args.mode,
        'cpu_count': multiprocessing.cpu_count(),
    }

    stat_info_d = {}
    for k in req.server.stat_info.keys():
        stat_info_d[k] = req.server.stat_info[k]

    proxy_list_d = {}
    for proxy_server_addr in req.server.proxy_list.keys():
        domain_name_map = req.server.proxy_list[proxy_server_addr]

        proxy_list_d[proxy_server_addr] = {}

        for domain_name in domain_name_map.keys():
            item = {
                domain_name: domain_name_map[domain_name]
            }
            proxy_list_d[proxy_server_addr].update(item)

    stat_info_d['total_nodes'] = len(proxy_list_d.keys())

    migrated = {
        'info': info_d,
        'stat': stat_info_d,
        'proxy_list': proxy_list_d,
    }
    entry_body = json.dumps(migrated, indent=2) + "\n"

    if req.command != 'HEAD':
        req.wfile.write(entry_body)


@www_auth_required
def admin(req):
    ALLOW_HOSTS = ('127.0.0.1', 'localhost')

    if req.server.server_name not in ALLOW_HOSTS:
        req.send_error(httplib.FORBIDDEN)
        return

    parse = urlparse.urlparse(req.path)
    qs_in_d = urlparse.parse_qs(parse.query)
    addr = qs_in_d['addr']

    if parse.path == '/admin/proxy/add':
        req.server.lock.acquire()
        my_proxy_list = copy.deepcopy(req.server.proxy_list)
        for new_proxy_sever in addr:
            if new_proxy_sever in my_proxy_list:
                pass
            else:
                my_proxy_list[new_proxy_sever] = {}
                req.log_message('Added %s into proxy list' % new_proxy_sever)

        req.server.proxy_list.clear()
        req.server.proxy_list.update(my_proxy_list)
        req.server.lock.release()

        req.send_response(httplib.OK)
        return


    elif parse.path == '/admin/proxy/delete':
        req.server.lock.acquire()
        my_proxy_list = copy.deepcopy(req.server.proxy_list)
        for proxy_sever in addr:
            try:
                my_proxy_list.pop(proxy_sever)
            except KeyError:
                pass
            req.log_message('Delete %s from proxy list' % proxy_sever)

        req.server.proxy_list.clear()
        req.server.proxy_list.update(my_proxy_list)
        req.server.lock.release()

        req.send_response(httplib.OK)
        return

    req.send_error(httplib.NOT_FOUND)


def ping(req):
    req.send_response(httplib.OK)
    req.send_header('Content-Type', 'text/plain')
    req.end_headers()

    if req.command != 'HEAD':
        req.wfile.write('pong')

def test(req):
    req.send_response(httplib.NOT_FOUND)


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


class HandlerClass(BaseHTTPServer.BaseHTTPRequestHandler):

    server_version = "POPS/" + __version__
    sys_version = ""

    def setup(self):
        BaseHTTPServer.BaseHTTPRequestHandler.setup(self)

        # If client doesn't send request in 3 seconds,
        # server will auto terminate it.
        # See also: http://yyz.us/bitcoin/poold.py
        self.request.settimeout(3)

    def log_message(self, format, *args):
        logger.debug(format % args)

    def do_HEAD(self):
        return self.do_GET()

    def do_GET(self):
        self.server.lock.acquire()
        self.server.stat_info['requests'] += 1
        self.server.lock.release()

        parses = urlparse.urlparse(self.path)
        if parses.scheme and parses.netloc:

            self.server.lock.acquire()
            self.server.stat_info['waiting_requests'] += 1
            self.server.lock.release()

            if self.server.args.proxy_auth:
                if self._do_proxy_auth():
                    if self.server.args.mode == 'slot_proxy':
                        self._do_slot_proxy()
                    else:
                        self._do_proxy()
                else:
                    self.send_response(httplib.PROXY_AUTHENTICATION_REQUIRED)
                    self.send_header('Proxy-Authenticate', 'Basic realm="HelloWorld"')
                    self.end_headers()
            else:
                if self.server.args.mode == 'slot_proxy':
                    self._do_slot_proxy()
                else:
                    self._do_proxy()

            self.server.lock.acquire()
            self.server.stat_info['waiting_requests'] -= 1
            self.server.lock.release()

        else:
            map = dict(handler_list)
            for path_in_re in map.keys():
                left_slash_stripped = self.path[1:]
                if re.compile(path_in_re).match(left_slash_stripped):
                    try:
                        map[path_in_re](self)
                    except Exception:
                        traceback.print_exc(file=sys.stderr)
                        self.send_error(httplib.INTERNAL_SERVER_ERROR)
                    return

            self.send_error(httplib.NOT_FOUND)


    def _proxy_server_incr_concurrency(self, top_domain_name, step=1):
        free_proxy_server_addr = None

        self.server.lock.acquire()

        # NOTICE: We have to do deepcopy and modify it, then re-assign it back,
        # see this for more detail http://docs.python.org/2/library/multiprocessing.html#multiprocessing.managers.SyncManager.list
        my_proxy_list = copy.deepcopy(self.server.proxy_list)
        try:
            for proxy_server_addr in my_proxy_list.keys():
                domain_name_map = my_proxy_list[proxy_server_addr]
                concurrency = domain_name_map.get(top_domain_name, 0)
                # this proxy allow to crawl records from this domain name in concurrency mode
                if step > 0:
                    if concurrency < PROXY_SERVER_PER_DOMAIN_MAX_CONCURRENCY:
                        if top_domain_name in domain_name_map:
                            my_proxy_list[proxy_server_addr][top_domain_name] += step
                        else:
                            my_proxy_list[proxy_server_addr] = {top_domain_name: 1}
                        free_proxy_server_addr = proxy_server_addr
                        break
                else:
                    if top_domain_name in domain_name_map:
                        my_proxy_list[proxy_server_addr][top_domain_name] += step
                        if my_proxy_list[proxy_server_addr][top_domain_name] < 0:
                            my_proxy_list[proxy_server_addr][top_domain_name] = 0
                    else:
                        my_proxy_list[proxy_server_addr] = {top_domain_name: 0}
            self.server.proxy_list.clear()
            self.server.proxy_list.update(my_proxy_list)
        finally:
            self.server.lock.release()

        return free_proxy_server_addr

    def _do_proxy_req(self, proxies=None, proxy_auth=None):
        url = self.path

        if proxy_auth:
            auth = requests.auth.HTTPBasicAuth(*proxy_auth)
        else:
            auth = None

        try:
            r = getattr(requests, self.command.lower())(
                url=url,
                proxies=proxies,
                timeout=PROXY_SERVER_SEND_TIMEOUT_IN_SECONDS,
                auth=auth)
            entry_body = r.content
            status_code = r.status_code

            # http://www.mnot.net/blog/2011/07/11/what_proxies_must_do
            hop_by_hop_headers_drop = (
                'TE',
                'Transfer-Encoding',
                'Keep-Alive',
                'Proxy-Authorization',
                'Proxy-Authentication',
                'Trailer',
                'Upgrade',
            )

            headers_filtered = {}
            for k in r.headers.keys():
                if k.lower() not in (i.lower() for i in hop_by_hop_headers_drop):
                    headers_filtered[k] = r.headers[k]

            # TODO: we should not modified header 'Content-Encoding',
            # because IETF standard said you should not, see also
            # http://tools.ietf.org/html/draft-ietf-httpbis-p1-messaging-14#section-7.1.3.2
            if len(entry_body):
                if 'content-encoding' in headers_filtered:
                    headers_filtered.pop('content-encoding')
                headers_filtered['content-length'] = len(entry_body)


            self.send_response(status_code)
            for k in headers_filtered.keys():
                self.send_header(k, headers_filtered[k])
            self.end_headers()

            if self.command != 'HEAD' and \
                            status_code >= 200 and \
                            status_code not in (204, 304):
                self.wfile.write(entry_body)


            self.server.lock.acquire()
            self.server.stat_info['proxy_requests'] += 1
            self.server.lock.release()

        except requests.exceptions.Timeout:
            self.log_error('Request %s timeout' % self.path)

            self.send_response(httplib.GATEWAY_TIMEOUT)
            self.end_headers()

        except requests.exceptions.ConnectionError:
            self.log_error('Request %s connection refused' % self.path)

            self.send_response(httplib.SERVICE_UNAVAILABLE)
            self.end_headers()

        except socket.timeout:
            self.log_error('Request %s timeout' % self.path)

            self.send_response(httplib.GATEWAY_TIMEOUT)
            self.end_headers()

        finally:
            pass

    def _do_proxy(self):
        self._do_proxy_req()

    def _do_slot_proxy(self):
        url = self.path

        parse = urlparse.urlparse(url)
        top_domain_name = get_top_domain_name(parse.netloc)

        free_proxy_server_addr = None
        while not free_proxy_server_addr:
            free_proxy_server_addr = self._proxy_server_incr_concurrency(top_domain_name, step=1)

            # if not free_proxy_server_addr:
            #     try:
            #         time.sleep(random.random() * PROXY_SERVER_SEND_TIMEOUT)
            #     except KeyboardInterrupt:
            #         pass

            if not free_proxy_server_addr:
                self.send_response(httplib.SERVICE_UNAVAILABLE)
                self.end_headers()
                return

        proxies = {"http" : "http://" + free_proxy_server_addr}

        value = self.headers.getheader('authorization')
        if value:
            proxy_auth =  base64.decodestring(value.replace('Basic ', '').strip()).split(':')
        else:
            proxy_auth = None

        self._do_proxy_req(proxies=proxies, proxy_auth=proxy_auth)

        self._proxy_server_incr_concurrency(top_domain_name, step=-1)

    def _do_proxy_auth(self):
        value = self.headers.getheader('authorization')
        if value:
            if value.replace('Basic ', '').strip() == self.server.args.proxy_auth_base64:
                return True
        return False



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
    protocol_version = "HTTP/1.0"

    lock = None
    proxy_list = None
    stat_info = None


def check_proxy_list(httpd_inst):
    if httpd_inst.args.proxy_auth:
        splits = httpd_inst.args.proxy_auth.split(':')
        proxy_auth = requests.auth.HTTPBasicAuth(splits[0], splits[1])
    else:
        proxy_auth = None

    try:
        logger.info('%s started' % multiprocessing.current_process().name)

        while True:
            time.sleep(PROXY_SERVER_CHECK_INTERVAL_IN_SECONDS)

            httpd_inst.lock.acquire()

            my_proxy_list = copy.deepcopy(httpd_inst.proxy_list)
            new_proxy_list = {}

            for proxy_server_addr in my_proxy_list.keys():
                proxies = {'http': 'http://' + proxy_server_addr}

                try:
                    r = requests.get(url='http://baidu.com/',
                                     proxies=proxies,
                                     timeout=PROXY_SERVER_KICK_SLOW_THAN_IN_SECONDS,
                                     auth=proxy_auth)

                    if r.status_code == httplib.OK and r.content.find('http://www.baidu.com/') != -1:
                        new_proxy_list[proxy_server_addr] = my_proxy_list[proxy_server_addr]
                except requests.exceptions.Timeout:
                    logger.debug('Test %s timeout, kick it from proxy list' % proxy_server_addr)
                except requests.exceptions.ConnectionError:
                    logger.debug('Test %s connection error, kick it from proxy list' % proxy_server_addr)
                except socket.timeout:
                    logger.debug('Test %s socket timeout, kick it from proxy list' % proxy_server_addr)

            httpd_inst.proxy_list.clear()
            httpd_inst.proxy_list.update(new_proxy_list)

            httpd_inst.lock.release()

    except KeyboardInterrupt:
        pass

    except IOError:
        pass

    finally:
        httpd_inst.server_close()


def main(args):
    server_address = (args.addr, args.port)
    httpd_inst = POPServer(server_address, HandlerClass)
    httpd_inst.args = args

    mp_manager = multiprocessing.Manager()
    httpd_inst.mp_manager = mp_manager
    httpd_inst.lock = multiprocessing.Lock()
    httpd_inst.proxy_list = mp_manager.dict()
    """
    proxy_list = {
        'proxy_host:proxy_port': {
                'domain_name1': count,
                'domain_name2': count,
                # ...
            }
    }
    """
    httpd_inst.stat_info = mp_manager.dict({
        'waiting_requests': 0,
        'proxy_requests': 0,
        'requests': 0,
        'total_nodes': 0,
    })

    sa = httpd_inst.socket.getsockname()
    logger.info('POPS started pid %d' % os.getpid())
    if args.mode == "slot_proxy":
        srv_name = "HTTP slot proxy"
    else:
        srv_name = "HTTP proxy"
    logger.info("Serving %s on %s port %s ..."  % (srv_name, sa[0], sa[1]))

    for i in range((multiprocessing.cpu_count() * 2)):
        p = multiprocessing.Process(target=serve_forever, args=(httpd_inst,))
        if args.daemon:
            p.daemon = args.daemon
        p.start()

    if args.mode == 'slot_proxy':
        p = multiprocessing.Process(target=check_proxy_list, name='CheckProxyListProcess', args=(httpd_inst,))
        if args.daemon:
            p.daemon = args.daemon
        p.start()

    serve_forever(httpd_inst)


class MyDaemon(object):

    def __init__(self, args):
        self.args = args

        self.stdin_path = '/dev/null'
        self.stdout_path = '/dev/stdout'
        self.stderr_path = args.error_log
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
                        choices=['slot_proxy', 'proxy'],
                        default='proxy',
                        help='default proxy')

    parser.add_argument('--error_log',
                        default=sys.stderr,
                        help='default /dev/stderr')

    parser.add_argument('--pid')

    parser.add_argument('--daemon', action='store_true')

    parser.add_argument('--stop',
                        action='store_true',
                        help='default start')

    args = parser.parse_args()

    if args.auth:
        args.auth_base64 = base64.encodestring(args.auth).strip()
    if args.proxy_auth:
        args.proxy_auth_base64 = base64.encodestring(args.proxy_auth).strip()

    if args.daemon or args.stop:
        if args.stop:
            action = 'stop'
        else:
            action = 'start'

        d_runner = MyDaemonRunner(MyDaemon(args), action)
        d_runner.do_action()
    else:
        main(args)

