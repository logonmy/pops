#!/usr/bin/env bash

DEFAULT_ADMIN_AUTH='god:hidemyass'

slot_host_port=$1
node_host_port=$2

if [ "$ADMIN_AUTH" = "" ]; then
  ADMIN_AUTH=$DEFAULT_ADMIN_AUTH
fi

if [ "$slot_host_port" = "" ] || [ "$node_host_port" = "" ] ;then
	echo "Usage $0: <slot host_port> <node host_port file or string>"
	exit 0
fi

if [ -f "$node_host_port" ]; then
    host_addr_port_list=`cat "$node_host_port" |grep -v ^$ | grep -v '#' | sort | uniq | tr "\\n" "," | sed 's/\(.*\),/\1/'`
    curl --user $ADMIN_AUTH "http://$slot_host_port/admin/node/add?addr=$host_addr_port_list"
else
    curl --user $ADMIN_AUTH "http://$slot_host_port/admin/node/add?addr=$node_host_port"
fi

exit 0
