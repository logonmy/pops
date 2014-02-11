import httplib
import os
import socket
import threading
import errno

import netaddr
import pymongo
import requests
import requests.exceptions
import sys

mgo = pymongo.MongoClient(host='127.0.0.1', port=27017)


NODE_TEST_MAX_CONCURRENCY = 1
NODE_KICK_SLOW_THAN = 2.0


STATUS_NODE_DELETED_OR_DOWN = 1 << 0
STATUS_NODE_FREE = 1 << 1
STATUS_NODE_TESTING = 1 << 2
STATUS_NODE_USING = 1 << 3

STATUS_NODE_DOMAIN_FREE = 1 << 0
STATUS_NODE_DOMAIN_USING = 1 << 1


def test_http_proxy(proxy_node_addr, timeout=NODE_KICK_SLOW_THAN, proxy_auth=None):
    proxies = {'http': 'http://' + proxy_node_addr}

    try:
        r = requests.get(url='http://baidu.com/',
                         proxies=proxies,
                         timeout=timeout,
                         auth=proxy_auth)
        if r.status_code == httplib.OK or r.content.find('http://www.baidu.com/') != -1:
            return True

    except requests.exceptions.Timeout:
        return False

    except requests.exceptions.ConnectionError:
        return False

    except requests.exceptions.TooManyRedirects:
        return False

    except socket.timeout:
        return False
    except socket.error, ex:
        if ex[0] == errno.ECONNRESET:
            return False

        print str(ex)
        return False

    except Exception, ex:
        print str(ex)

        return False

    return False


def add_node_info(addr):
    doc = {
        'addr': addr,
        'status': STATUS_NODE_FREE,
        'domains': []
    }

    ret = mgo.pops.node.find_and_modify(
        query={'addr': addr},
        update={'$setOnInsert': doc},
        new=True,
        upsert=True)
    # print ret
    return ret


def update_node_status(lock, ip_addr_obj, timeout):
    HTTP_PROXY_PORTS_GUESS = (
        80,
        1080, # HTTP proxy default
        # 1984, # Puff
        # 3998, # PaperBus
        # 4001, # JAP
        8000, # GPass, GAppProxy
        8080, # Toonel, Your Freedom
        8081,
        # 8087, # GoAgent
        # 8580, # Free Gate
        # 9666, # Wu Jie
    )
    for port in HTTP_PROXY_PORTS_GUESS:
        addr = str(ip_addr_obj) + ':' + str(port)
        # print 'testing %s' % addr
        if test_http_proxy(proxy_node_addr=addr, timeout=timeout):

            lock.acquire()
            sys.stderr.write(addr + '\n')
            lock.release()

            add_node_info(addr)


def main(concurrency=NODE_TEST_MAX_CONCURRENCY):
    if not os.path.exists('delegated-apnic-latest'):
        r = requests.get('http://ftp.apnic.net/apnic/stats/apnic/delegated-apnic-latest')
        body = r.text
    else:
        with open('delegated-apnic-latest') as f:
            body = f.read()

    lock = threading.Lock()

    for line in body.split():
        if line.find('apnic|CN|ipv4|') == -1:
            continue

        splits = line.split('|')
        ip_addr_in_str, count = splits[3], int(splits[4])

        ip_addr_obj = netaddr.IPAddress(ip_addr_in_str)

        for range_start in xrange(int(ip_addr_obj), int(ip_addr_obj) + count, concurrency):
            thread_list = []

            print 'range_start', netaddr.IPAddress(range_start)

            for ip_addr_in_int in xrange(range_start, range_start + concurrency):
                kwargs = dict(lock=lock,
                              ip_addr_obj=netaddr.IPAddress(ip_addr_in_int),
                              timeout=float(NODE_KICK_SLOW_THAN))
                t = threading.Thread(target=update_node_status, kwargs=kwargs)
                thread_list.append(t)
            [t.start() for t in thread_list]
            [t.join() for t in thread_list]

if __name__ ==  '__main__':
    main(int(sys.argv[1]))