#!/usr/bin/env bash

config_path=$1

if [ "$config_path" = "" ];then
	echo "Usage $0: <config_path>"
	exit 0
fi

for i in `cat $config_path |grep -v ^$|grep -v '#'`;do
    curl --basic -u 'god:hidemyass' "http://127.0.0.1:1080/admin/proxy/add?addr=$i"
done 

exit 0
