#!/usr/bin/env bash

python pops.py \
	# --processes `python -c "import multiprocessing; print multiprocessing.cpu_count()"` \
	--processes 64 \
	--error_log /var/log/pops.log \
	--pid /var/run/pops.pid \
	--mode slot \
	--daemon

