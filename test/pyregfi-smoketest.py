#!/usr/bin/env python3

import sys
import gc
import pyregfi

def usage():
    sys.stderr.write("USAGE: pyregfi-smoketest.py hive1 [hive2 ...]\n")


# Uses the HiveIterator to walk all keys
# Gathers various (meaningless) statistics to exercise simple attribute access
# and to hopefully smoke out any bugs that can be identified by changing stats
def iterTally(hive):
    key_count = 0
    key_lens = 0
    key_rawlens = 0
    value_count = 0
    value_lens = 0
    value_rawlens = 0

    for k in hive:
        key_count += 1
        if k.name != None:
            key_lens += len(k.name)
        if k.name_raw != None:
            key_rawlens += len(k.name_raw)

        for v in k.values:
            value_count += 1
            if v.name != None:
                value_lens += len(v.name)
            if v.name_raw != None:
                value_rawlens += len(v.name_raw)

    print("  Counts: keys=%d, values=%d\n" % (key_count, value_count))
    print("  Total name length: keys=%d, values=%d\n" % (key_lens, value_lens))
    print("  Total raw name lengths: keys=%d, values=%d\n" % (key_rawlens, value_rawlens))



if len(sys.argv) < 2:
    usage()
    sys.exit(1)

files = []
for f in sys.argv[1:]:
    files.append((f, open(f,"r+b")))

tests = [("iterTally",iterTally),]

for hname,fh in files:
    hive = pyregfi.Hive(fh)
    for tname,t in tests:
        tstr = "'%s' on '%s'" % (tname,hname)
        print("##BEGIN %s:" % tstr)
        t(hive)
        print("##END %s; messages:" % tstr)
        print(pyregfi.GetLogMessages())
        print
    hive = None
    gc.collect()

files = None
tests = None
gc.collect()
print gc.garbage
