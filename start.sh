#!/usr/bin/env bash

#python pops.py \
#	--processes `python -c "import multiprocessing; print multiprocessing.cpu_count()"` \
#	--error_log `pwd`/pops.log \
#	--pid `pwd`/pops.pid \
#	--mode slot \
#	--daemon

python pops.py \
	--processes 64 \
	--error_log `pwd`/pops.log \
	--pid `pwd`/pops.pid \
	--mode slot \
	--daemon

