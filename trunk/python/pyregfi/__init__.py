#!/usr/bin/env python

import sys
from pyregfi.structures import *

import ctypes
import ctypes.util
from ctypes import c_char,c_char_p,c_int,POINTER

regfi = ctypes.CDLL(ctypes.util.find_library('regfi'), use_errno=True)


regfi.regfi_alloc.argtypes = [c_int]
regfi.regfi_alloc.restype = POINTER(REGFI_FILE)

regfi.regfi_alloc_cb.argtypes = [POINTER(REGFI_RAW_FILE)]
regfi.regfi_alloc_cb.restype = POINTER(REGFI_FILE)

regfi.regfi_log_get_str.argtypes = []
regfi.regfi_log_get_str.restype = c_char_p

regfi.regfi_init.argtypes = []
regfi.regfi_init.restype = None
regfi.regfi_init()


class Hive(ctypes.Structure):
    
    file = None
    raw_file = None
    
    def __init__(self, fh):
        
        if hasattr(fh, 'fileno') and 1==0:
            self.file = regfi.regfi_alloc(fh.fileno())
        else:
            self.raw_file = structures.REGFI_RAW_FILE()
            self.raw_file.fh = fh
            self.raw_file.seek = seek_cb_type(self.raw_file.cb_seek)
            self.raw_file.read = read_cb_type(self.raw_file.cb_read)
            self.file = regfi.regfi_alloc_cb(self.raw_file)
            print(regfi.regfi_log_get_str())

    def __getattr__(self, name):
        return getattr(self.file.contents, name)

    def test(self):
        print(self.magic)
        print(self.sequence1)
        print(self.sequence2)

