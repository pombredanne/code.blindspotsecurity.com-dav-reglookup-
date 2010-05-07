#!/usr/bin/env python

import sys
import pyregfi

files = sys.argv


def iter_values(iter):
    i = 0
    for value in iter.list_values():
        i += 1

def walk_tree(iter):
    total_keys = 0
    total_values = 0

    for sub_key in iter:        
        num_keys,num_values = walk_tree(sub_key)
        total_keys += num_keys + 1
        total_values += num_values

        num_values += iter_values(iter)

    return (total_keys, total_values)


for f in files:
    rf = pyregfi.RegistryFile(f)
    iter = r.get_key()
    print walk_tree(iter)
    
