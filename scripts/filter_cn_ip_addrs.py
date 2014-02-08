import os
import math

import netaddr
import requests


"""
delegated-apnic-latest
http://ftp.apnic.net/apnic/stats/apnic/delegated-apnic-latest

For more information see:
  http://www.apnic.net/db/rir-stats-format.html
"""


if not os.path.exists('delegated-apnic-latest'):
    r = requests.get('http://ftp.apnic.net/apnic/stats/apnic/delegated-apnic-latest')
    body = r.text
else:
    with open('delegated-apnic-latest') as f:
        body = f.read()

for line in body.split():
    if line.find('apnic|CN|ipv4|') == -1:
        continue

    splits = line.split('|')
    ip_addr, count = splits[3], int(splits[4])

    cidr = math.log(count, 2)
    ipn = netaddr.IPNetwork('%s/%d' % (ip_addr, 32 - cidr))
    print ipn
    # for ip_addr in ipn:
    #     print ip_addr