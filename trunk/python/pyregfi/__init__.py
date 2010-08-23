#!/usr/bin/env python

import sys
from pyregfi.structures import *

import ctypes
import ctypes.util
from ctypes import c_char,c_char_p,c_int,c_uint16,c_bool,POINTER

regfi = ctypes.CDLL(ctypes.util.find_library('regfi'), use_errno=True)


regfi.regfi_alloc.argtypes = [c_int]
regfi.regfi_alloc.restype = POINTER(REGFI_FILE)

regfi.regfi_alloc_cb.argtypes = [POINTER(REGFI_RAW_FILE)]
regfi.regfi_alloc_cb.restype = POINTER(REGFI_FILE)

regfi.regfi_free.argtypes = [POINTER(REGFI_FILE)]
regfi.regfi_free.restype = None

regfi.regfi_log_get_str.argtypes = []
regfi.regfi_log_get_str.restype = c_char_p

regfi.regfi_log_set_mask.argtypes = [c_uint16]
regfi.regfi_log_set_mask.restype = c_bool

regfi.regfi_free_record.argtypes = [c_void_p]
regfi.regfi_free_record.restype = None

regfi.regfi_iterator_new.argtypes = [POINTER(REGFI_FILE), REGFI_ENCODING]
regfi.regfi_iterator_new.restype = POINTER(REGFI_ITERATOR)

regfi.regfi_iterator_free.argtypes = [POINTER(REGFI_ITERATOR)]
regfi.regfi_iterator_free.restype = None

regfi.regfi_iterator_down.argtypes = [POINTER(REGFI_ITERATOR)]
regfi.regfi_iterator_down.restype = c_bool

regfi.regfi_iterator_up.argtypes = [POINTER(REGFI_ITERATOR)]
regfi.regfi_iterator_up.restype = c_bool

regfi.regfi_iterator_to_root.argtypes = [POINTER(REGFI_ITERATOR)]
regfi.regfi_iterator_to_root.restype = c_bool

regfi.regfi_iterator_walk_path.argtypes = [POINTER(REGFI_ITERATOR)]
regfi.regfi_iterator_walk_path.restype = c_bool

regfi.regfi_iterator_cur_key.argtypes = [POINTER(REGFI_ITERATOR)]
regfi.regfi_iterator_cur_key.restype = POINTER(REGFI_NK)

regfi.regfi_iterator_cur_sk.argtypes = [POINTER(REGFI_ITERATOR)]
regfi.regfi_iterator_cur_sk.restype = POINTER(REGFI_SK)

regfi.regfi_iterator_first_subkey.argtypes = [POINTER(REGFI_ITERATOR)]
regfi.regfi_iterator_first_subkey.restype = c_bool

regfi.regfi_iterator_cur_subkey.argtypes = [POINTER(REGFI_ITERATOR)]
regfi.regfi_iterator_cur_subkey.restype = POINTER(REGFI_NK)

regfi.regfi_iterator_next_subkey.argtypes = [POINTER(REGFI_ITERATOR)]
regfi.regfi_iterator_next_subkey.restype = c_bool

regfi.regfi_iterator_find_subkey.argtypes = [POINTER(REGFI_ITERATOR), c_char_p]
regfi.regfi_iterator_find_subkey.restype = c_bool

regfi.regfi_iterator_first_value.argtypes = [POINTER(REGFI_ITERATOR)]
regfi.regfi_iterator_first_value.restype = c_bool

regfi.regfi_iterator_cur_value.argtypes = [POINTER(REGFI_ITERATOR)]
regfi.regfi_iterator_cur_value.restype = POINTER(REGFI_VK)

regfi.regfi_iterator_next_value.argtypes = [POINTER(REGFI_ITERATOR)]
regfi.regfi_iterator_next_value.restype = c_bool

regfi.regfi_iterator_find_value.argtypes = [POINTER(REGFI_ITERATOR), c_char_p]
regfi.regfi_iterator_find_value.restype = c_bool

# XXX: possibly move REGFI_ENCODING to file object and eliminate need for ITERATOR here.
regfi.regfi_iterator_fetch_classname.argtypes = [POINTER(REGFI_ITERATOR), POINTER(REGFI_NK)]
regfi.regfi_iterator_fetch_classname.restype = POINTER(REGFI_CLASSNAME)

regfi.regfi_iterator_fetch_data.argtypes = [POINTER(REGFI_ITERATOR), POINTER(REGFI_VK)]
regfi.regfi_iterator_fetch_data.restype = POINTER(REGFI_DATA)


regfi.regfi_init.argtypes = []
regfi.regfi_init.restype = None
regfi.regfi_init()


def GetLogMessages():
    return regfi.regfi_log_get_str()


class Hive():    
    file = None
    raw_file = None
    
    def __init__(self, fh):
        # The fileno method may not exist, or it may thrown an exception
        # when called if the file isn't backed with a descriptor.
        try:
            if hasattr(fh, 'fileno'):
                self.file = regfi.regfi_alloc(fh.fileno())
                return
        except:
            pass
        
        self.raw_file = structures.REGFI_RAW_FILE()
        self.raw_file.fh = fh
        self.raw_file.seek = seek_cb_type(self.raw_file.cb_seek)
        self.raw_file.read = read_cb_type(self.raw_file.cb_read)
        self.file = regfi.regfi_alloc_cb(self.raw_file)

    def __getattr__(self, name):
        return getattr(self.file.contents, name)
    
    def __del__(self):    
        regfi.regfi_free(self.file)
        if self.raw_file != None:
            regfi.regfi_free(self.file)
            

    def __iter__(self):
        return HiveIterator(self)


class HiveIterator():
    hive = None
    iter = None
    root_traversed = False

    def __init__(self, hive):
        # REGFI_ENCODING_UTF8==1
        self.iter = regfi.regfi_iterator_new(hive.file, 1)
        if self.iter == None:
            raise Exception("Could not create iterator.  Current log:\n"
                            + GetLogMessages())
        self.hive = hive
        
    def __getattr__(self, name):
        return getattr(self.file.contents, name)

    def __del__(self):    
        regfi.regfi_iterator_free(self.iter)        

    def __iter__(self):
        return self

    def __next__(self):
        if self.root_traversed:
            self.root_traversed = True
            
        elif not regfi.regfi_iterator_down(self.iter):
            up_ret = regfi.regfi_iterator_up(self.iter)
            while up_ret and not regfi.regfi_iterator_next_subkey(self.iter):
                up_ret = regfi.regfi_iterator_up(self.iter)

            if not up_ret:
                raise StopIteration('')
            
            if not regfi.regfi_iterator_down(self.iter):
                raise Exception('Error traversing iterator downward.'+
                                ' Current log:\n'+ GetLogMessages())

        regfi.regfi_iterator_first_subkey(self.iter)
        print(regfi.regfi_iterator_cur_key(self.iter).contents.keyname)
        return regfi.regfi_iterator_cur_key(self.iter)

