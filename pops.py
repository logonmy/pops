#!/usr/bin/env python
import argparse
import base64
import copy
import errno
import functools
import logging
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
import traceback
import urlparse

from daemon import runner
import requests
import requests.auth
import requests.exceptions


__version__ = "201401"



logging.basicConfig(format='%(asctime)s [%(levelname)s] [%(process)d] %(message)s',
                    datefmt='%Y-%m-%d %I:%M:%S',
                    level=logging.DEBUG)
logger = logging.getLogger(__name__)


class ProxyNodeStatus(object):

    DELETED_OR_DOWN = 0
    UP_AND_RUNNING = 1


def www_auth_required(func):
    @functools.wraps(func)
    def _wrapped_view(req):
        value = req.headers.getheader('authorization')
        if not req.server.auth:
            return func(req)

        if value:
            basic_credentials = value.replace('Basic ', '').strip()
            if basic_credentials == req.server.auth_base64:
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

def local_net_required(func):
    @functools.wraps(func)
    def _wrapped_view(req):
        ALLOW_HOSTS = ('127.0.0.1', 'localhost')

        if req.server.server_name in ALLOW_HOSTS:
            return func(req)
        else:
            req.send_error(code=httplib.FORBIDDEN, message='allow local net only')
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


    req.server.lock.acquire()
    proxy_list_d = copy.deepcopy(req.server.proxy_list)
    req.server.lock.release()

    total_up_nodes = 0
    for proxy_node_addr in proxy_list_d.keys():
        if proxy_list_d[proxy_node_addr]['_status'] == ProxyNodeStatus.UP_AND_RUNNING:
            total_up_nodes += 1

    server_stat_d = copy.deepcopy(req.server.server_stat)
    server_stat_d['total_up_nodes'] = total_up_nodes

    server_stat_d['total_nodes'] = len(proxy_list_d.keys())


    server_info_d = copy.deepcopy(req.server.server_info)

    server_settings_d = copy.deepcopy(req.server.server_settings)


    migrated = {
        'server_info': server_info_d,
        'server_stat': server_stat_d,
        'server_settings': server_settings_d,
        'proxy_list': proxy_list_d,
    }
    entry_body = json.dumps(migrated, indent=2) + "\n"

    if req.command != 'HEAD':
        req.wfile.write(entry_body)


@local_net_required
@www_auth_required
def admin(req):
    parse = urlparse.urlparse(req.path)
    qs_in_d = urlparse.parse_qs(parse.query)

    if parse.path == '/admin/proxy/add':
        addr = [i.strip() for i in qs_in_d['addr']]

        req.server.lock.acquire()
        my_proxy_list = copy.deepcopy(req.server.proxy_list)

        for new_proxy_sever in addr:
            if new_proxy_sever not in my_proxy_list:
                my_proxy_list[new_proxy_sever] = {
                    '_status': ProxyNodeStatus.UP_AND_RUNNING,
                }
            req.log_message('Appended %s into proxy list' % new_proxy_sever)

        req.server.proxy_list.clear()
        req.server.proxy_list.update(my_proxy_list)
        req.server.lock.release()

        req.send_response(httplib.OK)
        return


    elif parse.path == '/admin/proxy/delete':
        addr = [i.strip() for i in qs_in_d['addr']]

        req.server.lock.acquire()
        my_proxy_list = copy.deepcopy(req.server.proxy_list)

        for proxy_sever in addr:
            if proxy_sever not in my_proxy_list:
                continue

            if my_proxy_list[proxy_sever]['_status'] == ProxyNodeStatus.UP_AND_RUNNING:
                my_proxy_list[proxy_sever]['_status'] = ProxyNodeStatus.DELETED_OR_DOWN

            req.log_message('Switch proxy node %s status to %d' %
                                proxy_sever,
                                ProxyNodeStatus.DELETED_OR_DOWN)

        req.server.proxy_list.clear()
        req.server.proxy_list.update(my_proxy_list)
        req.server.lock.release()

        req.send_response(httplib.OK)
        return

    elif parse.path == '/admin/server_settings/update':
        k, v = qs_in_d['k'][0], qs_in_d['v'][0]

        req.server.lock.acquire()
        if k in req.server.server_settings:
            req.server.server_settings[k] = v
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
        self.server.server_stat['requests'] += 1
        self.server.lock.release()

        parses = urlparse.urlparse(self.path)
        if parses.scheme and parses.netloc:

            self.server.lock.acquire()
            self.server.server_stat['waiting_requests'] += 1
            self.server.lock.release()

            if self.server.proxy_auth:
                if self._do_proxy_auth():
                    if self.server.server_info['service_mode'] == 'slot_proxy':
                        self._do_slot_proxy()
                    else:
                        self._do_proxy()
                else:
                    self.send_response(httplib.PROXY_AUTHENTICATION_REQUIRED)
                    self.send_header('Proxy-Authenticate', 'Basic realm="HelloWorld"')
                    self.end_headers()
            else:
                if self.server.server_info['service_mode'] == 'slot_proxy':
                    self._do_slot_proxy()
                else:
                    self._do_proxy()

            self.server.lock.acquire()
            self.server.server_stat['waiting_requests'] -= 1
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
                    if concurrency < int(self.server.server_settings['node_per_domain_max_concurrency']):
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
                timeout=float(self.server.server_settings['node_send_timeout_in_seconds']),
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
            self.server.server_stat['proxy_requests'] += 1
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

        free_proxy_node_addr = None
        while not free_proxy_node_addr:
            free_proxy_node_addr = self._proxy_server_incr_concurrency(top_domain_name, step=1)

            # if not free_proxy_node_addr:
            #     try:
            #         time.sleep(random.random() * PROXY_SERVER_SEND_TIMEOUT)
            #     except KeyboardInterrupt:
            #         pass

            if not free_proxy_node_addr:
                self.send_response(httplib.SERVICE_UNAVAILABLE)
                self.end_headers()
                return

        proxies = {"http" : "http://" + free_proxy_node_addr}

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
            if value.replace('Basic ', '').strip() == self.server.proxy_auth_base64:
                return True
        return False


def test_http_proxy(lock, down_node_list, proxy_node_addr, proxy_auth, timeout):
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


            down_node_list = {}
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
    protocol_version = "HTTP/1.0"

    lock = None
    proxy_list = None
    server_stat = None
    server_info = None
    server_settings = None

    proxy_auth = None
    auth = None
    proxy_auth_base64 = None
    auth_base64 = None


def main(args):
    server_address = (args.addr, args.port)
    httpd_inst = POPServer(server_address, HandlerClass)

    pid = os.getpid()
    processes = int(args.processes)
    if hasattr(args.error_log, 'name'):
        error_log_path = getattr(args.error_log, 'name')
    else:
        error_log_path = args.error_log

    if args.auth:
        splits = args.auth.split(':')
        httpd_inst.auth = requests.auth.HTTPBasicAuth(*splits)
        httpd_inst.auth_base64 = base64.encodestring(args.auth).strip()
    if args.proxy_auth:
        splits = args.proxy_auth.split(':')
        httpd_inst.proxy_auth = requests.auth.HTTPBasicAuth(*splits)
        httpd_inst.proxy_auth_base64 = base64.encodestring(args.proxy_auth).strip()


    mp_manager = multiprocessing.Manager()
    httpd_inst.mp_manager = mp_manager    
    httpd_inst.lock = multiprocessing.Lock()
    
    httpd_inst.proxy_list = mp_manager.dict()
    
    httpd_inst.server_stat = mp_manager.dict({
        'waiting_requests': 0,
        'proxy_requests': 0,
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
        node_send_timeout_in_seconds = 15.0,
        node_check_interval = 60.0,
        node_kick_slow_than = 5.0,
        node_test_max_concurrency = 20,
    )
    httpd_inst.server_settings = mp_manager.dict(srv_settings)

    for i in range(processes):
        p = multiprocessing.Process(target=serve_forever, args=(httpd_inst,))
        if args.daemon:
            p.daemon = args.daemon
        p.start()

    if httpd_inst.server_info['service_mode'] == 'slot_proxy':
        p = multiprocessing.Process(target=check_proxy_list, name='CheckProxyListProcess', args=(httpd_inst,))
        if args.daemon:
            p.daemon = args.daemon
        p.start()


    logger.info('POPS started pid %d' % pid)
    if httpd_inst.server_info['service_mode'] == "slot_proxy":
        srv_name = "HTTP slot proxy server"
    else:
        srv_name = "HTTP proxy node"
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
                        choices=['slot_proxy', 'proxy'],
                        default='proxy',
                        help='default proxy')

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

