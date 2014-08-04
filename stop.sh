#!/usr/bin/env bash

if [ -f "/var/run/pops.pid" ]; then
	python pops.py --error_log=/dev/stderr --pid /var/run/pops.pid --stop
else
	for i in `ps aux |grep pops | grep -v grep | awk '{print $2}'  `;do 
		kill $i;
	done
fi
