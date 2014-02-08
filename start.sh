python pops.py --processes `python -c "import multiprocessing; multiprocessing.cpu_count()"` --error_log `pwd`/pops.log  --pid `pwd`/pops.pid  --mode slot_proxy --daemon
