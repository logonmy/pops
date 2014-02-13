# About

POPS is a simple HTTP proxy server and HTTP proxy slot server.


HTTP proxy server

    client(s) ---> HTTP proxy server


HTTP proxy slot server

    client(s) ---> pops A (acts as HTTP proxy slot server)
                   |
                   +---> pops B (acts as HTTP proxy server node)
                   |
                   +---> pops C (acts as HTTP proxy server node)
                   |
                   +---> pops D (acts as HTTP proxy server node)
                   |
                   +...

Features

 - supports method HEAD/GET/CONNECT
 - supports slot proxy, per domain per node, or multiple domains per node
    - it works with Web crawl spider perfectly.


## Install and Usage

Install

    sudo python setup.py install


### HTTP proxy server

    pops.py --port 1080
    curl -v --proxy-basic --proxy-user 'god:hidemyass' --proxy 127.0.0.1:1080  http://www.imdb.com/title/tt0108778/

Show stat info

    curl -v --basic --user 'god:hidemyass' 'http://127.0.0.1:1080/stat/'


### HTTP proxy slot server

    pops.py --mode slot --port 1080


Add nodes

    curl --basic -u 'god:hidemyass' http://127.0.0.1:1080/admin/proxy/add?addr=127.0.0.1:3128
    curl --basic -u 'god:hidemyass' http://127.0.0.1:1080/admin/proxy/add?addr=192.168.1.100:9090


Update settings

    curl -v --basic --user 'god:hidemyass' 'http://127.0.0.1:1080/admin/server_settings/update?k=node_test_max_concurrency&v=50'


Use it as HTTP proxy server, it will auto slot same domain into different nodes.

    curl -v --proxy-basic --proxy-user 'god:hidemyass' --proxy 127.0.0.1:1080  http://www.imdb.com/title/tt0108778/


### Others

Start it as daemon

    python pops.py \
        --processes `python -c "import multiprocessing; multiprocessing.cpu_count()"` \
        --error_log `pwd`/pops.log  \
        --pid `pwd`/pops.pid  \
        --mode slot \
        --addr 0.0.0.0 \
        --port 1080 \
        --daemon


Start it without authentication requirement

    python pops.py  --proxy_auth= --auth=


## See also

RFC 1945 - Hypertext Transfer Protocol -- HTTP/1.0
http://tools.ietf.org/html/rfc1945

RFC 2616 - Hypertext Transfer Protocol -- HTTP/1.1
http://tools.ietf.org/html/rfc2616

RFC 2817 - Upgrading to TLS Within HTTP/1.1
http://tools.ietf.org/html/rfc2817

Tunneling TCP based protocols through Web proxy servers
https://tools.ietf.org/html/draft-luotonen-web-proxy-tunneling-01

RFC 1867 - Form-based File Upload in HTML
http://tools.ietf.org/html/rfc1867
