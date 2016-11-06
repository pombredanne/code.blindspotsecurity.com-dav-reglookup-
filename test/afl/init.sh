#!/bin/sh

AFL_DIR=/usr/local/src/afl-2.35b

( cd ../../trunk && scons -c && LDFLAGS= CFLAGS= CC=$AFL_DIR/afl-gcc scons )

sudo /bin/sh -c 'cd /sys/devices/system/cpu && echo performance | tee cpu*/cpufreq/scaling_governor'

echo 'Be sure to copy small test cases in to the testcases directory'
