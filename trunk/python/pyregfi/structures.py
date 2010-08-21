#!/usr/bin/env python

import sys
import os
import traceback
import ctypes
import ctypes.util
from ctypes import c_char,c_int,c_uint8,c_uint16,c_uint32,c_uint64,c_int64,POINTER,c_void_p,c_char_p


class REGFI_RAW_FILE(ctypes.Structure):
    fh = None
    
    def cb_seek(self, raw_file, offset, whence):
        try:
            self.fh.seek(offset, whence)
        except Exception:
            traceback.print_exc()
            # XXX: os.EX_IOERR may not be available on Windoze
            ctypes.set_errno(os.EX_IOERR)
            return -1

        return self.fh.tell()


    def cb_read(self, raw_file, buf, count):
        try:
            # XXX: anyway to do a readinto() here?
            tmp = self.fh.read(count)
            ctypes.memmove(buf,tmp,len(tmp))

        except Exception:
            traceback.print_exc()
            # XXX: os.EX_IOERR may not be available on Windoze
            ctypes.set_errno(os.EX_IOERR)
            return -1
        return len(tmp)



# XXX: how can we know for sure the size of off_t and size_t?
seek_cb_type = ctypes.CFUNCTYPE(c_int64, POINTER(REGFI_RAW_FILE), c_uint64, c_int, use_errno=True)
read_cb_type = ctypes.CFUNCTYPE(c_int64, POINTER(REGFI_RAW_FILE), POINTER(c_char), c_uint64, use_errno=True)


REGFI_RAW_FILE._fields_ = [('seek', seek_cb_type),
                           ('read', read_cb_type),
                           ('cur_off', c_uint64),
                           ('size', c_uint64),
                           ('state', c_void_p),
                           ]


class REGFI_FILE(ctypes.Structure):
    _fields_ = [('magic', c_char * 4),
                ('sequence1', c_uint32),
                ('sequence2', c_uint32),
                ('mtime', c_uint64),
                ('major_version', c_uint32),
                ('minor_version', c_uint32),
                ('type', c_uint32),
                ('format', c_uint32),
                ('root_cell', c_uint32),
                ('last_block', c_uint32),
                ('cluster', c_uint32),
                ]



