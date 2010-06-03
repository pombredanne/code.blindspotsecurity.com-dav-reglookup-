#!/usr/bin/env python

import sys
import pyregfi

files = sys.argv[1:]


def iter_values(iter):
    i = 0
    for value in iter.list_values():
        i += 1
        
    return i


def walk_tree(iter):
    total_keys = 1
    total_values = iter_values(iter)
    print "total_values:", total_values
    
    for sub_key in iter:
        print sub_key.keyname
        
        print iter.down()
        num_keys,num_values = walk_tree(iter)
        total_keys += num_keys
        total_values += num_values
        iter.up()

    return (total_keys, total_values)


for f in files:
    rf = pyregfi.RegistryFile(f)
    iter = rf.get_key()
    print walk_tree(iter)
