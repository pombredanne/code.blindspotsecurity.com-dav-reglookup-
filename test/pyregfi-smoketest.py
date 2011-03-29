#!/usr/bin/env python3

import sys
import gc
import time
import pyregfi

def usage():
    sys.stderr.write("USAGE: pyregfi-smoketest.py hive1 [hive2 ...]\n")


# helper function
def getCurrentPath(key):
    if key == None:
        return ''
    path = []
    p = key
    while p != None:
        path.append(p.name)
        if p.is_root():
            break
        else:
            p = p.get_parent()
    path.reverse()
    del path[0]

    return path


# Uses the HiveIterator to walk all keys
# Gathers various (meaningless) statistics to exercise simple attribute access
# and to hopefully smoke out any bugs that can be identified by changing stats
def iterTallyNames(hive):
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

    print("  Counts: keys=%d, values=%d" % (key_count, value_count))
    print("  Total name length: keys=%d, values=%d" % (key_lens, value_lens))
    print("  Total raw name lengths: keys=%d, values=%d" % (key_rawlens, value_rawlens))


# For each key in the hive, this traverses the parent links up to the root, 
# recording the path as it goes, and then uses the subtree/descend method
# to find the same key again, verifying it is the same.  This test is currently
# very slow because no key caching is used.
def iterParentWalk(hive):
    i = 1
    for k in hive:
        path = getCurrentPath(k)
        try:
            hive_iter = hive.subtree(path)
            if hive_iter.current_key() != k:
                print("WARNING: k != current_key for path '%s'." % path)
            else:
                i += 1
        except Exception as e:
            print("WARNING: Could not decend to path '%s'.\nError:\n %s\n%s" % (path,e.args,e))
    print("   Successfully tested paths on %d keys." % i)


# Uses the HiveIterator to walk all keys
# Gathers various (meaningless) statistics about data/data_raw attributes
def iterTallyData(hive):
    data_stat = 0.0
    dataraw_stat = 0.0
    
    for k in hive:
        for v in k.values:
            d = v.data
            if d == None:
                data_stat += 0.1
            elif hasattr(d, "__len__"):
                data_stat += len(d)
            else:
                data_stat += d/2.0**64

            d = v.data_raw
            if d == None:
                dataraw_stat += 0.1
            else:
                dataraw_stat += len(d)

    print("  Data stat: %f" % data_stat)
    print("  Raw data stat: %f" % dataraw_stat)



if len(sys.argv) < 2:
    usage()
    sys.exit(1)


#tests = [("iterTallyNames",iterTallyNames),("iterParentWalk",iterParentWalk),]
tests = [("iterTallyData",iterTallyData),]

files = []
for f in sys.argv[1:]:
    files.append((f, open(f,"r+b")))


start_time = time.time()
for hname,fh in files:
    hive = pyregfi.Hive(fh)
    for tname,t in tests:
        teststart = time.time()
        tstr = "'%s' on '%s'" % (tname,hname)
        print("##BEGIN %s:" % tstr)
        t(hive)
        print("##END %s; runtime=%f; messages:" % (tstr, time.time() - teststart))
        print(pyregfi.GetLogMessages())
        print
        sys.stdout.flush()

hive = None
files = None
tests = None
gc.collect()
print("### Tests Completed, runtime: %f ###" % (time.time() -  start_time))
#print(gc.garbage)
