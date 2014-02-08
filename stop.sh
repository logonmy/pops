#!/usr/bin/env bash

if [ -f '/home/lee/code/pops/pops.pid' ]; then
	python pops.py --error_log=/dev/stderr --pid /home/lee/code/pops/pops.pid --stop
else
	for i in `ps aux |grep pops | grep -v grep | awk '{print $2}'  `;do 
		kill $i;
	done
fi
