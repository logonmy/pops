# About

POPS is a HTTP proxy server and HTTP proxy slot server.


HTTP proxy server

    user-agent(s) ---> HTTP proxy server


HTTP proxy slot server

    user-agent(s) ---> pops A (acts as HTTP proxy slot server)
                      |
                      |
                      +-------> pops B (acts as HTTP proxy server node)
                     |
                     +---> pops C (acts as HTTP proxy server node)
                     |
                     +---> pops D (acts as HTTP proxy server node)
                     |
                     +...

Features

   - supports any standard methods
   - supports transfer-coding in chunked
   - supports content-encoding in gzip
   - supports HTTP authentication
   - supports slot proxy for auto-throttle
    - one domain per node, or multiple domains per node, it works with Web spider perfectly
    - auto check and kick node base on its up or down status


## Installation


Install it via pip/easy_install

    sudo pip install pypops
    # or
    sudo easy_install pypops


Install it from source code

    git clone https://github.com/shuge/pops.git
    cd pops

    sudo pip install -r requirements.txt
    sudo python setup.py install


## Usage


### POPS service mode: node

HTTP proxy server

    pops.py --port 1080 --proxy_auth=user:123 --auth=admin:123 --mode node


Test it

    curl --verbose --proxy-user user:123 --proxy 127.0.0.1:1080 http://tools.ietf.org/html/rfc1945.html


Test HTTPS, it should be works as expected

    curl --verbose --proxy-user user:123 --proxy 127.0.0.1:1080 https://tools.ietf.org/html/rfc1945.html


Show stat info

    curl --verbose --user admin:123 http://127.0.0.1:1080/stat/


Start it without authentication requirement

    pops.py --proxy_auth= --auth= --mode node


### POPS service mode: slot

HTTP proxy slot server

    pops.py --port 1080 --proxy_auth=user:123 --auth=admin:123 --proxy_node_auth=user_bot:123 --mode slot


Launch nodes

    pops.py --port 8080 --proxy_auth=user_bot:123 --mode node
    pops.py --port 8081 --proxy_auth=user_bot:123 --mode node


Add proxy nodes

    curl --verbose --user admin:123 http://127.0.0.1:1080/admin/node/add?addr=127.0.0.1:8080,127.0.0.1:8081


Update slot settings

    curl --verbose --user 'admin:123' 'http://127.0.0.1:1080/admin/settings/update?k=node_check_interval&v=600'


Use it as normal HTTP proxy server, it will auto slot same domain into different nodes

    curl --verbose --proxy-user 'user:123' --proxy 127.0.0.1:1080 http://tools.ietf.org/html/rfc1945.html


### Deployment in production

Start

    pops.py \
        --processes `python -c "import multiprocessing; multiprocessing.cpu_count()"` \
        --error_log `pwd`/pops.log  \
        --pid `pwd`/pops.pid  \
        --mode slot \
        --addr 0.0.0.0 \
        --port 1080 \
        --daemon

Stop

    pops.py \
        --processes `python -c "import multiprocessing; multiprocessing.cpu_count()"` \
        --error_log `pwd`/pops.log  \
        --pid `pwd`/pops.pid  \
        --mode slot \
        --addr 0.0.0.0 \
        --port 1080 \
        --daemon \
        --stop


### Setup POPS dashboard(beta) for slot

    git clone https://github.com/shuge/pops.git
    cp -r pops/html /var/www/
    cd /var/www/

    bower install # require node.js and bower install third-party JavaScript libraries

    # configure web server virtual-host instance and reload it
    # open http://virtual-host/dashboard.html


![](https://raw.githubusercontent.com/shuge/pops/master/html/dashboard.gif)


NOTICE: update settings doesn't works right now.

