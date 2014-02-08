import socket
import threading
import daemon

import httplib
import urllib2
import argparse
import sys

import requests
import requests.auth
import requests.exceptions

proxies = {'http':'http://127.0.0.1:1080'}


def test_http_proxy(lock, down_node_list, proxy_node_addr, proxy_auth, timeout=5.0):
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

    lock.acquire()
    down_node_list[proxy_node_addr] = 'unknown'
    lock.release()

    return False

down_node_list = {}
proxy_node_list = set()
with open('proxy_server_list.txt') as f:
    for line in f.readlines():
        s = line.strip()
        if s:
            proxy_node_list.add(s)

with open('proxy_server_list_tmp.txt') as f:
    for line in f.readlines():
        s = line.strip()
        if s:
            proxy_node_list.add(s)


MAX_CONCURRENCY_THREADS = 40

proxy_auth = requests.auth.HTTPBasicAuth('god', 'hidemyass')
thread_lock = threading.Lock()

for range_start in range(0, len(proxy_node_list), MAX_CONCURRENCY_THREADS):
    proxy_node_parts = list(proxy_node_list)[range_start:range_start + MAX_CONCURRENCY_THREADS]

    thread_list = []
    for idx in range(len(proxy_node_parts)):
        t = threading.Thread(target=test_http_proxy, args=(thread_lock, down_node_list, proxy_node_parts[idx], proxy_auth))
        thread_list.append(t)
    [t.start() for t in thread_list]
    [t.join() for t in thread_list]

print down_node_list

