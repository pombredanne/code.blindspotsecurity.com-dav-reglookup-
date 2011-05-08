#!/usr/bin/env python3

import sys
import gc
import io
import time
import threading
import pyregfi



pyregfi.setLogMask((pyregfi.LOG_TYPES.INFO, pyregfi.LOG_TYPES.WARN, pyregfi.LOG_TYPES.ERROR))

# Uses the HiveIterator to walk all keys
# Gathers various (meaningless) statistics to exercise simple attribute access
# and to hopefully smoke out any bugs that can be identified by changing stats
def iterTallyNames(hive, fh):
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


# walks up parents to obtain path, rather than using downward links like iterator
def getCurrentPath(key):
    if key == None:
        return ''
    path = []
    p = key
    while p != None:
        path.append(p.name)
        p = p.get_parent()
    path.reverse()
    del path[0]

    return path

# For each key in the hive, this traverses the parent links up to the root, 
# recording the path as it goes, and then uses the subtree/descend method
# to find the same key again, verifying it is the same.  This test is currently
# very slow because no key caching is used.
def iterParentWalk(hive, fh):
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
            print("WARNING: Could not descend to path '%s'.\nError:\n %s\n%s" % (path,e.args,e))
    print("   Successfully tested paths on %d keys." % i)


# Uses the HiveIterator to walk all keys
# Gathers various (meaningless) statistics about data/data_raw attributes
def iterTallyData(hive, fh):
    data_stat = 0.0
    dataraw_stat = 0.0
    
    for k in hive:
        for v in k.values:
            d = v.fetch_data()
            if d == None:
                data_stat += 0.1
            elif hasattr(d, "__len__"):
                data_stat += len(d)
            else:
                data_stat += d/2.0**64

            d = v.fetch_raw_data()
            if d == None:
                dataraw_stat += 0.1
            else:
                dataraw_stat += len(d)

    print("  Data stat: %f" % data_stat)
    print("  Raw data stat: %f" % dataraw_stat)


recurseKey_stat = 0.0
recurseValue_stat = 0.0
def checkValues(key):
    global recurseKey_stat
    global recurseValue_stat
    recurseKey_stat += (key.mtime.low^key.mtime.high - key.max_bytes_subkeyname) * key.flags
    for v in key.values:
        recurseValue_stat += (v.data_off - v.data_size) / (1.0 + v.flags) + v.data_in_offset
        value = key.values[v.name]
        if v != value:
            print("WARNING: iterator value '%s' does not match dictionary value '%s'." 
                  % (v.name, value.name))

def recurseTree(cur, operation):
    for k in cur.subkeys:
        key = cur.subkeys[k.name]
        if k != key:
            print("WARNING: iterator subkey '%s' does not match dictionary subkey '%s'." 
                  % (k.name, key.name))
        del key
        operation(k)
        recurseTree(k, operation)

# Retrieves all keys by recursion, rather than the iterator, and validates
# list dictionary access.  Also builds nonsensical statistics as an excuse
# to access various base structure attributes.
def recurseKeyTally(hive, fh):
    checkValues(hive.root)
    recurseTree(hive.root, checkValues)
    print("  Key stat: %f" % recurseKey_stat)
    print("  Value stat: %f" % recurseValue_stat)


# Iterates hive gathering stats about security and classname records
def iterFetchRelated(hive, fh):
    security_stat = 0.0
    classname_stat = 0.0
    modified_stat = 0.0

    for k in hive:
        cn = k.fetch_classname()
        if cn == None:
            classname_stat += 0.000001
        elif type(cn) == bytearray:
            classname_stat += len(cn)/2**32
        else:
            classname_stat += len(cn)

        modified_stat += k.modified
        
    print("  Security stat: %f" % security_stat)
    print("  Classname stat: %f" % classname_stat)
    print("  Modified stat: %f" % modified_stat)



def iterIterWalk(hive, fh):
    sk_stat = 0.0
    v_stat = 0.0
    iter = pyregfi.HiveIterator(hive)
    for k in iter:
        path = iter.current_path()
        try:
            hive_iter = hive.subtree(path[1:])
            sk = hive_iter.first_subkey()
            while sk != None:
                ssk = hive_iter.find_subkey(sk.name)
                if ssk != None:
                    sk_stat += len(ssk.name)
                else:
                    print("WARNING: ssk was None")
                sk = hive_iter.next_subkey()

            v = hive_iter.first_value()
            while v != None:
                vv = hive_iter.find_value(v.name)
                if vv != None:
                    v_stat += len(vv.name)
                else:
                    print("WARNING: vv was None")
                v = hive_iter.next_value()

        except Exception as e:
            print("WARNING: Could not descend to path '%s'.\nError:\n %s\n%s" % (path[1:],e.args,e))
    print("   Subkey stat: %f" % sk_stat)
    print("   Value stat: %f" % v_stat)


def iterCallbackIO(hive, fh):
    fh.seek(0)
    new_fh = io.BytesIO(fh.read())
    new_hive = pyregfi.Hive(new_fh)
    for k in new_hive:
        pass


def threadIterMain(iter):
    x = 0
    try:
        for k in iter:
            #x += len(k.name) + len(k.subkeys)
            pass
    except Exception as e:
        print("%s dying young: %s" % (threading.current_thread().name, repr(e)))
        # Exceptions are thrown on iteration because python state gets out of 
        # whack.  That's fine, because we're really just interested in finding
        # segfaults.  People should not use iterators without locks, but it 
        # should at least not segfault on them.
        pass
    print("%s finished" % threading.current_thread().name)

def iterMultithread(hive, fh):
    num_threads = 10
    iter = pyregfi.HiveIterator(hive)
    threads = []
    for t in range(0,num_threads):
        threads.append(threading.Thread(target=threadIterMain, args=(iter,)))
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    

tests = {
    "iterTallyNames":iterTallyNames,
    "iterParentWalk":iterParentWalk,
    "iterTallyData":iterTallyData,
    "recurseKeyTally":recurseKeyTally,
    "iterFetchRelated":iterFetchRelated,
    "iterIterWalk":iterIterWalk,
    "iterCallbackIO":iterCallbackIO,
    "iterMultithread":iterMultithread,
    }

def usage():
    sys.stderr.write("USAGE: pyregfi-smoketest.py test1[,test2[,...]] hive1 [hive2 ...]\n")
    sys.stderr.write("\tAvailable tests:\n")
    for t in tests.keys():
        sys.stderr.write("\t\t%s\n" % t)


if len(sys.argv) < 3:
    usage()
    sys.exit(1)

selected_tests = sys.argv[1].split(',')
for st in selected_tests:
    if st not in tests:
        usage()
        sys.stderr.write("ERROR: %s not a valid test type" % st)
        sys.exit(1)

files = []
for f in sys.argv[2:]:
    files.append((f, open(f,"rb")))


start_time = time.time()
for hname,fh in files:
    hive = pyregfi.Hive(fh)
    for tname in selected_tests:
        t = tests[tname]
        teststart = time.time()
        tstr = "'%s' on '%s'" % (tname,hname)
        print("##BEGIN %s:" % tstr)
        t(hive, fh)
        print("##END %s; runtime=%f; messages:" % (tstr, time.time() - teststart))
        print(pyregfi.getLogMessages())
        print
        sys.stdout.flush()
    fh.close()

hive = None
files = None
tests = None
gc.collect()
print("### Tests Completed, runtime: %f ###" % (time.time() -  start_time))
#print(gc.garbage)
