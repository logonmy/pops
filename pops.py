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
import copy
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
import urlparse

import requests
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


def default_body(httpd_inst):
    httpd_inst.send_response(httplib.OK)
    httpd_inst.send_header('Content-Type', 'text/html; charset=utf-8')
    httpd_inst.end_headers()

    default_body = "<html><head><title>Welcome to POPS!</title></head><body>" \
                   "<h1>Welcome to POPS!</h1>" \
                    '</html>'
    httpd_inst.wfile.write(default_body)

def favicon(httpd_inst):
    httpd_inst.send_response(httplib.NOT_FOUND)

def stat(httpd_inst):
    httpd_inst.send_response(httplib.OK)
    httpd_inst.send_header('Content-Type', 'application/json')
    httpd_inst.end_headers()

    stat_info_d = {}
    for k in httpd_inst.server.stat_info.keys():
        stat_info_d[k] = httpd_inst.server.stat_info[k]

    proxy_list_d = {}
    for proxy_server_addr in httpd_inst.server.proxy_list.keys():
        domain_name_map = httpd_inst.server.proxy_list[proxy_server_addr]

        proxy_list_d[proxy_server_addr] = {}

        for domain_name in domain_name_map.keys():
            item = {
                domain_name: domain_name_map[domain_name]
            }
            proxy_list_d[proxy_server_addr].update(item)

    stat_info_d['total_nodes'] = len(proxy_list_d.keys())

    migrated = {
        'stat': stat_info_d,
        'proxy_list': proxy_list_d,
    }
    default_body = json.dumps(migrated)
    httpd_inst.wfile.write(default_body)

def admin(httpd_inst):
    parse = urlparse.urlparse(httpd_inst.path)

    if parse.path == '/admin/proxy/add':
        qs_in_d = urlparse.parse_qs(parse.query)

        httpd_inst.server.lock.acquire()
        my_proxy_list = copy.deepcopy(httpd_inst.server.proxy_list)
        for new_proxy_sever in qs_in_d['ip_addr']:
            if new_proxy_sever in my_proxy_list:
                pass
            else:
                my_proxy_list[new_proxy_sever] = {}
                httpd_inst.log_message('Added %s into proxy list' % new_proxy_sever)

        httpd_inst.server.proxy_list.clear()
        httpd_inst.server.proxy_list.update(my_proxy_list)
        httpd_inst.server.lock.release()

        httpd_inst.send_response(httplib.OK)

    elif parse.path == '/admin/proxy/delete':
        qs_in_d = urlparse.parse_qs(parse.query)

        httpd_inst.server.lock.acquire()
        my_proxy_list = copy.deepcopy(httpd_inst.server.proxy_list)
        for proxy_sever in qs_in_d['ip_addr']:
            try:
                my_proxy_list.pop(proxy_sever)
            except KeyError:
                pass
            httpd_inst.log_message('Delete %s from proxy list' % proxy_sever)

        httpd_inst.server.proxy_list.clear()
        httpd_inst.server.proxy_list.update(my_proxy_list)
        httpd_inst.server.lock.release()

        httpd_inst.send_response(httplib.OK)
    else:
        httpd_inst.send_error(httplib.NOT_FOUND)

def ping(httpd_inst):
    httpd_inst.send_response(httplib.OK)
    httpd_inst.send_header('Content-Type', 'text/plain')
    httpd_inst.end_headers()

    httpd_inst.wfile.write('pong')

def test(httpd_inst):
    httpd_inst.send_response(httplib.NOT_FOUND)

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
        # if LOGGING_USES_PROCESS_NAME_PREFIX:
        #     sys.stderr.write('[%s] %s\n' % (multiprocessing.current_process().name,
        #                                     format % args))
        # else:
        #     BaseHTTPServer.BaseHTTPRequestHandler.log_message(self, format, *args)

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

            self._do_proxy()

            self.server.lock.acquire()
            self.server.stat_info['waiting_requests'] -= 1
            self.server.lock.release()

            return
        else:
            map = dict(handler_list)
            for path_in_re in map.keys():
                left_slash_stripped = self.path[1:]
                if re.compile(path_in_re).match(left_slash_stripped):
                    handler = map[path_in_re]
                    handler(self)
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

    def _do_proxy(self):
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

        try:
            r = getattr(requests, self.command.lower())(
                url=url,
                proxies=proxies,
                timeout=PROXY_SERVER_SEND_TIMEOUT_IN_SECONDS)
            entry_body = r.content

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


            self.send_response(r.status_code)
            for k in headers_filtered.keys():
                self.send_header(k, headers_filtered[k])
            self.end_headers()

            if self.command != "HEAD":
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
            self._proxy_server_incr_concurrency(top_domain_name, step=-1)

def serve_forever(httpd_inst):
    try:
        logger.info('%s started' % multiprocessing.current_process().name)
        httpd_inst.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd_inst.server_close()


def serve_forever_main(httpd_inst):
    try:
        logger.info('%s started' % multiprocessing.current_process().name)
        # while True:
        #     httpd_inst.handle_request()
        httpd_inst.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd_inst.server_close()

    # leave some time for children quit by themselves,
    # and release sharing resources
    time.sleep(0.5)

    for p in multiprocessing.active_children():
        p.terminate()
        logger.info('%s PID %s terminated' % (p.name, p.pid))


class POPServer(BaseHTTPServer.HTTPServer):

    allow_reuse_address = True
    protocol_version = "HTTP/1.0"

    lock = None
    proxy_list = None
    stat_info = None


def check_proxy_list(httpd_inst):
    try:
        logger.info('%s started' % multiprocessing.current_process().name)

        while True:
            httpd_inst.lock.acquire()

            my_proxy_list = copy.deepcopy(httpd_inst.proxy_list)
            new_proxy_list = {}

            for proxy_server_addr in my_proxy_list.keys():
                proxies = {'http': 'http://' + proxy_server_addr}

                try:
                    r = requests.get(url='http://baidu.com/',
                                     proxies=proxies,
                                     timeout=PROXY_SERVER_KICK_SLOW_THAN_IN_SECONDS)

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

            time.sleep(PROXY_SERVER_CHECK_INTERVAL_IN_SECONDS)

    except KeyboardInterrupt:
        pass
    finally:
        httpd_inst.server_close()


def main(port):
    server_address = ('', port)
    httpd_inst = POPServer(server_address, HandlerClass)

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
    logger.info("Serving HTTP on %s port %s ..."  % (sa[0], sa[1]))

    for i in range((multiprocessing.cpu_count() * 2)):
        multiprocessing.Process(target=serve_forever, args=(httpd_inst,)).start()

    multiprocessing.Process(target=check_proxy_list, name='CheckProxyListProcess', args=(httpd_inst,)).start()

    serve_forever_main(httpd_inst)


if __name__ == "__main__":
    args = sys.argv[1:]
    port = 1080
    if args:
       port = args[0]

    main(port)