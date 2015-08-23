#!/bin/sh

TERMINAL='urxvt -geometry 80x25+0+0 -rv -e'

$TERMINAL /usr/local/src/afl-1.86b/afl-fuzz -i testcases -o findings -M master ../../trunk/src/reglookup -s @@ &
$TERMINAL /usr/local/src/afl-1.86b/afl-fuzz -i testcases -o findings -S slave1 ../../trunk/src/reglookup -s @@ &
$TERMINAL /usr/local/src/afl-1.86b/afl-fuzz -i testcases -o findings -S slave2 ../../trunk/src/reglookup -s @@ &
