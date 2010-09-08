#!/usr/bin/env python

import sys
from pyregfi.structures import *

import ctypes
import ctypes.util
from ctypes import c_char,c_char_p,c_int,c_uint16,c_uint32,c_bool,POINTER

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



regfi.regfi_get_value

regfi.regfi_init.argtypes = []
regfi.regfi_init.restype = None
regfi.regfi_init()


def GetLogMessages():
    msgs = regfi.regfi_log_get_str()
    if msgs == None:
        return ''
    return msgs.decode('ascii')


def _buffer2bytearray(char_pointer, length):
    if length == 0 or char_pointer == None:
        return None
    
    ret_val = bytearray(length)
    for i in range(0,length):
        ret_val[i] = char_pointer[i][0]

    return ret_val




class _StructureWrapper():
    "Handles memory management and proxies attribute access to base structures"
    hive = None
    base = None

    def __init__(self, hive, base):
        self.hive = hive
        # XXX: check for NULL here, throw an exception if so.
        self.base = base

    def __del__(self):
        regfi.regfi_free_record(self.base)

    def __getattr__(self, name):
        return getattr(self.base.contents, name)

    def __eq__(self, other):
        return (type(self) == type(other)) and (self.offset == other.offset)

    def __ne__(self, other):
        return (not self.__eq__(other))


class Key(_StructureWrapper):
    pass

class Value(_StructureWrapper):
    pass

class Data(_StructureWrapper):
    pass

class Security(_StructureWrapper):
    pass


class _GenericList():
    hive = None
    key = None
    length = None
    current = None

    # implementation-specific functions
    fetch_num = None
    find_element = None
    get_element = None
    constructor = None

    def __init__(self, key):
        self.hive = key.hive
        # XXX: check for NULL here, throw an exception if so.
        self.key = key
        self.length = self.fetch_num(key.base)
    
    def __len__(self):
        return self.length

    def __getitem__(self, name):
        index = c_uint32()
        if isinstance(name, str):
            name = name.encode('utf-8')

        if self.find_element(self.hive.file, self.key.base,
                             create_string_buffer(name), byref(index)):
            return self.constructor(self.hive, self.get_element(self.hive.file,
                                                                self.key.base,
                                                                index))
        raise KeyError('')


    def __iter__(self):
        self.current = 0
        return self
    
    def __next__(self):
        if self.current >= self.length:
            raise StopIteration('')

        elem = self.get_element(self.hive.file, self.key.base,
                                c_uint32(self.current))
        self.current += 1
        return elem.contents
    

class _SubkeyList(_GenericList):
    fetch_num = regfi.regfi_fetch_num_subkeys
    find_element = regfi.regfi_find_subkey
    get_element = regfi.regfi_get_subkey


class _ValueList(_GenericList):
    fetch_num = regfi.regfi_fetch_num_values
    find_element = regfi.regfi_find_value
    get_element = regfi.regfi_get_value


class Key(_StructureWrapper):
    values = None
    subkeys = None

    def __init__(self, hive, base):
        super(Key, self).__init__(hive, base)
        self.values = _ValueList(self)
        self.subkeys = _SubkeyList(self)

    def __getattr__(self, name):
        ret_val = super(Key, self).__getattr__(name)
        if ret_val == None:
            return None
        
        if name == "name":
            ret_val = ret_val.decode('utf-8')
        elif name == "name_raw":
            length = super(Key, self).__getattr__('name_length')
            ret_val = _buffer2bytearray(ret_val, length)
        
        return ret_val


    def fetch_security(self):
        return Security(self.hive,
                        regfi.regfi_fetch_sk(self.hive.file, self.base))


class Value(_StructureWrapper):
    def __getattr__(self, name):
        ret_val = super(Value, self).__getattr__(name)
        if ret_val == None:
            return None

        if name == "name":
            ret_val = ret_val.decode('utf-8')
        elif name == "name_raw":
            length = super(Value, self).__getattr__('name_length')
            ret_val = _buffer2bytearray(ret_val, length)
        
        return ret_val


# Avoids chicken/egg class definitions.
# Also makes for convenient code reuse in these lists' parent classes.
_SubkeyList.constructor = Key
_ValueList.constructor = Value



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

    def subtree(self, path):
        hi = HiveIterator(self)
        hi.descend(path)
        return hi


class HiveIterator():
    hive = None
    iter = None
    iteration_root = None

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
        self.iteration_root = None
        return self

    def __next__(self):
        if self.iteration_root == None:
            self.iteration_root = self.current_key()            
        elif not regfi.regfi_iterator_down(self.iter):
            up_ret = regfi.regfi_iterator_up(self.iter)
            while (up_ret and
                   not regfi.regfi_iterator_next_subkey(self.iter)):
                if self.iteration_root == self.current_key():
                    self.iteration_root = None
                    raise StopIteration('')
                up_ret = regfi.regfi_iterator_up(self.iter)

            if not up_ret:
                raise StopIteration('')
            
            if not regfi.regfi_iterator_down(self.iter):
                raise Exception('Error traversing iterator downward.'+
                                ' Current log:\n'+ GetLogMessages())

        regfi.regfi_iterator_first_subkey(self.iter)
        return self.current_key()

    def down(self):
        pass

    def up(self):
        pass

    def descend(self, path):
        #set up generator
        cpath = (bytes(p,'ascii') for p in path) 

        # evaluate generator and create char* array
        apath = (c_char_p*len(path))(*cpath)

        if not regfi.regfi_iterator_walk_path(self.iter,apath):
            raise Exception('Could not locate path.\n'+GetLogMessages())

    def current_key(self):
        return Key(self.hive, regfi.regfi_iterator_cur_key(self.iter))
