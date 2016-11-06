#!/bin/sh

AFL_DIR=/usr/local/src/afl-2.35b

TERMINAL='urxvt -geometry 80x25+0+0 -rv -hold -e /bin/sh -c'

$TERMINAL "LD_LIBRARY_PATH=../../trunk/lib $AFL_DIR/afl-fuzz -i testcases -o findings -M master ../../trunk/src/reglookup -s @@"  &
$TERMINAL "LD_LIBRARY_PATH=../../trunk/lib $AFL_DIR/afl-fuzz -i testcases -o findings -S slave1 ../../trunk/src/reglookup -s @@"  &
$TERMINAL "LD_LIBRARY_PATH=../../trunk/lib $AFL_DIR/afl-fuzz -i testcases -o findings -S slave2 ../../trunk/src/reglookup -s @@"  &
