#!/usr/bin/env python

import sys
import os
import traceback
import ctypes
import ctypes.util
from ctypes import *

# XXX: can we always be sure enums are this size?
REGFI_ENCODING = c_uint32
REGFI_ENCODING_UTF8 = 1

REGFI_DATA_TYPE = c_uint32
REGFI_REGF_SIZE = 0x1000 

# Registry value data types
REG_NONE                       =  0
REG_SZ		               =  1
REG_EXPAND_SZ                  =  2
REG_BINARY 	               =  3
REG_DWORD	               =  4
REG_DWORD_LE	               =  4 # DWORD, little endian
REG_DWORD_BE	               =  5 # DWORD, big endian
REG_LINK                       =  6
REG_MULTI_SZ  	               =  7
REG_RESOURCE_LIST              =  8
REG_FULL_RESOURCE_DESCRIPTOR   =  9
REG_RESOURCE_REQUIREMENTS_LIST = 10
REG_QWORD                      = 11 # 64-bit little endian


# Prototype everything first so we don't have to worry about reference order
class REGFI_NTTIME(Structure):
    pass

class REGFI_VK(Structure):
    pass

class REGFI_SK(Structure):
    pass

class REGFI_SUBKEY_LIST(Structure):
    pass

class REGFI_VALUE_LIST(Structure):
    pass

class REGFI_CLASSNAME(Structure):
    pass

class REGFI_DATA(Structure):
    pass

class REGFI_NK(Structure):
    pass

class REGFI_ITERATOR(Structure):
    pass

class REGFI_FILE(Structure):
    pass

class REGFI_RAW_FILE(Structure):
    fh = None
    
    def cb_seek(self, raw_file, offset, whence):
        try:
            self.fh.seek(offset, whence)
        except Exception:
            traceback.print_exc()
            # XXX: os.EX_IOERR may not be available on Windoze
            set_errno(os.EX_IOERR)
            return -1

        return self.fh.tell()


    def cb_read(self, raw_file, buf, count):
        try:
            # XXX: anyway to do a readinto() here?
            tmp = self.fh.read(count)
            memmove(buf,tmp,len(tmp))

        except Exception:
            traceback.print_exc()
            # XXX: os.EX_IOERR may not be available on Windoze
            set_errno(os.EX_IOERR)
            return -1
        return len(tmp)


# XXX: how can we know for sure the size of off_t and size_t?
seek_cb_type = CFUNCTYPE(c_int64, POINTER(REGFI_RAW_FILE), c_uint64, c_int, use_errno=True)
read_cb_type = CFUNCTYPE(c_int64, POINTER(REGFI_RAW_FILE), POINTER(c_char), c_uint64, use_errno=True)


REGFI_NTTIME._fields_ = [('low', c_uint32),
                         ('high', c_uint32)]

REGFI_VK._fields_ = [('offset', c_uint32),
                     ('cell_size', c_uint32),
                     ('name', c_char_p),
                     ('name_raw', POINTER(c_char)),
                     ('name_length', c_uint16),
                     ('hbin_off', c_uint32),
                     ('data_size', c_uint32),
                     ('data_off', c_uint32),
                     ('type', REGFI_DATA_TYPE),
                     ('magic', c_char * 2),
                     ('flags', c_uint16),
                     ('unknown1', c_uint16),
                     ('data_in_offset', c_bool),
                     ]


REGFI_SK._fields_ = [('offset', c_uint32),
                     ('cell_size', c_uint32),
                     ('sec_desc', c_void_p), #XXX
                     ('hbin_off', c_uint32),
                     ('prev_sk_off', c_uint32),
                     ('next_sk_off', c_uint32),
                     ('ref_count', c_uint32),
                     ('desc_size', c_uint32),
                     ('unknown_tag', c_uint16),
                     ('magic', c_char * 2),
                     ]


REGFI_NK._fields_ = [('offset', c_uint32),
                     ('cell_size', c_uint32),
                     ('values', POINTER(REGFI_VALUE_LIST)),
                     ('subkeys', POINTER(REGFI_SUBKEY_LIST)),
                     ('flags', c_uint16),
                     ('magic', c_char * 2),
                     ('mtime', REGFI_NTTIME),
                     ('name_length', c_uint16),
                     ('classname_length', c_uint16),
                     ('name', c_char_p),
                     ('name_raw', POINTER(c_char)),
                     ('parent_off', c_uint32),
                     ('classname_off', c_uint32),
                     ('max_bytes_subkeyname', c_uint32),
                     ('max_bytes_subkeyclassname', c_uint32),
                     ('max_bytes_valuename', c_uint32),
                     ('max_bytes_value', c_uint32),
                     ('unknown1', c_uint32),
                     ('unknown2', c_uint32),
                     ('unknown3', c_uint32),
                     ('unk_index', c_uint32),
                     ('num_subkeys', c_uint32),
                     ('subkeys_off', c_uint32),
                     ('num_values', c_uint32),
                     ('values_off', c_uint32),
                     ('sk_off', c_uint32),
                     ]


REGFI_SUBKEY_LIST._fields_ = [('offset', c_uint32),
                              ('cell_size', c_uint32),
                              ('num_children', c_uint32),
                              ('num_keys', c_uint32),
                              ('elements', c_void_p),
                              ('magic', c_char * 2),
                              ('recursive_type', c_bool),
                              ]


REGFI_VALUE_LIST._fields_ = [('offset', c_uint32),
                             ('cell_size', c_uint32),
                             ('num_children', c_uint32),
                             ('num_values', c_uint32),
                             ('elements', c_void_p),
                             ]

REGFI_CLASSNAME._fields_ = [('offset', c_uint32),
                            ('interpreted', c_char_p),
                            ('raw', POINTER(c_char)),
                            ('size', c_uint16),
                            ]


class REGFI_DATA__interpreted(Union):
    _fields_ = [('none',POINTER(c_char)),
                ('string', c_char_p),
                ('expand_string', c_char_p),
                ('binary',POINTER(c_char)),
                ('dword', c_uint32),
                ('dword_be', c_uint32),
                ('link', c_char_p),
                ('multiple_string', POINTER(c_char_p)),
                ('qword', c_uint64),
                ('resource_list',POINTER(c_char)),
                ('full_resource_descriptor',POINTER(c_char)),
                ('resource_requirements_list',POINTER(c_char)),
                ]
REGFI_DATA._fields_ = [('offset', c_uint32),
                       ('type', REGFI_DATA_TYPE),
                       ('size', c_uint32),
                       ('raw', POINTER(c_char)),
                       ('interpreted_size', c_uint32),
                       ('interpreted', REGFI_DATA__interpreted),
                       ]


REGFI_FILE._fields_ = [('magic', c_char * 4),
                       ('sequence1', c_uint32),
                       ('sequence2', c_uint32),
                       ('mtime', REGFI_NTTIME),
                       ('major_version', c_uint32),
                       ('minor_version', c_uint32),
                       ('type', c_uint32),
                       ('format', c_uint32),
                       ('root_cell', c_uint32),
                       ('last_block', c_uint32),
                       ('cluster', c_uint32),
                       ]


REGFI_RAW_FILE._fields_ = [('seek', seek_cb_type),
                           ('read', read_cb_type),
                           ('cur_off', c_uint64),
                           ('size', c_uint64),
                           ('state', c_void_p),
                           ]


# Load libregfi and define function prototypes
regfi = ctypes.CDLL(ctypes.util.find_library('regfi'), use_errno=True)

regfi.regfi_alloc.argtypes = [c_int, REGFI_ENCODING]
regfi.regfi_alloc.restype = POINTER(REGFI_FILE)

regfi.regfi_alloc_cb.argtypes = [POINTER(REGFI_RAW_FILE), REGFI_ENCODING]
regfi.regfi_alloc_cb.restype = POINTER(REGFI_FILE)

regfi.regfi_free.argtypes = [POINTER(REGFI_FILE)]
regfi.regfi_free.restype = None

regfi.regfi_log_get_str.argtypes = []
regfi.regfi_log_get_str.restype = c_char_p

regfi.regfi_log_set_mask.argtypes = [c_uint16]
regfi.regfi_log_set_mask.restype = c_bool

regfi.regfi_get_rootkey.argtypes = [POINTER(REGFI_FILE)]
regfi.regfi_get_rootkey.restype = POINTER(REGFI_NK)

regfi.regfi_free_record.argtypes = [c_void_p]
regfi.regfi_free_record.restype = None

regfi.regfi_fetch_num_subkeys.argtypes = [POINTER(REGFI_NK)]
regfi.regfi_fetch_num_subkeys.restype = c_uint32

regfi.regfi_fetch_num_values.argtypes = [POINTER(REGFI_NK)]
regfi.regfi_fetch_num_values.restype = c_uint32

regfi.regfi_fetch_classname.argtypes = [POINTER(REGFI_FILE), POINTER(REGFI_NK)]
regfi.regfi_fetch_classname.restype = POINTER(REGFI_CLASSNAME)

regfi.regfi_fetch_sk.argtypes = [POINTER(REGFI_FILE), POINTER(REGFI_NK)]
regfi.regfi_fetch_sk.restype = POINTER(REGFI_SK)

regfi.regfi_fetch_data.argtypes = [POINTER(REGFI_FILE), POINTER(REGFI_VK)]
regfi.regfi_fetch_data.restype = POINTER(REGFI_DATA)

regfi.regfi_find_subkey.argtypes = [POINTER(REGFI_FILE), POINTER(REGFI_NK),
                                    c_char_p, POINTER(c_uint32)]
regfi.regfi_find_subkey.restype = c_bool

regfi.regfi_find_value.argtypes = [POINTER(REGFI_FILE), POINTER(REGFI_NK),
                                    c_char_p, POINTER(c_uint32)]
regfi.regfi_find_value.restype = c_bool

regfi.regfi_get_subkey.argtypes = [POINTER(REGFI_FILE), POINTER(REGFI_NK),
                                   c_uint32]
regfi.regfi_get_subkey.restype = POINTER(REGFI_NK)

regfi.regfi_get_value.argtypes = [POINTER(REGFI_FILE), POINTER(REGFI_NK),
                                   c_uint32]
regfi.regfi_get_value.restype = POINTER(REGFI_VK)

regfi.regfi_get_parentkey.argtypes = [POINTER(REGFI_FILE), POINTER(REGFI_NK)]
regfi.regfi_get_parentkey.restype = POINTER(REGFI_NK)

regfi.regfi_nt2unix_time.argtypes = [POINTER(REGFI_NTTIME)]
regfi.regfi_nt2unix_time.restype = c_double

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


regfi.regfi_init.argtypes = []
regfi.regfi_init.restype = None
regfi.regfi_init()
