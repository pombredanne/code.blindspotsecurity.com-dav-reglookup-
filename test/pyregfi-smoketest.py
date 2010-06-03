#!/usr/bin/env python

import sys
import pyregfi

files = sys.argv[1:]


def iter_values(iter):
    i = 0
    for value in iter.list_values():
        i += 1
        
    return i


for f in files:
    rf = pyregfi.RegistryFile(f)
    iter = rf.get_key()

    num_keys = 0
    num_values = 0
    # The iterator now walks the entire registry hive, depth-first
    for key in iter:
        #print key.keyname
        num_keys +=1
        num_values += iter_values(iter)

    print "keys: %d" % num_keys
    print "values: %d" % num_values
