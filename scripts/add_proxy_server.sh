#!/usr/bin/env bash

slot_addr=$1
node_addr=$2

if [ "$slot_addr" = "" ] || [ "$node_addr" = "" ] ;then
	echo "Usage $0: <slot_addr> <node_addr file or string>"
	exit 0
fi

if [ -f $node_addr ]; then
    for i in `cat $node_addr |grep -v ^$|grep -v '#'`;do
        curl --basic --user 'god:hidemyass' "http://$slot_addr/admin/node/add?addr=$i"
    done
else
    curl --basic --user 'god:hidemyass' "http://$slot_addr/admin/node/add?addr=$node_addr"
fi

exit 0
