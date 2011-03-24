#!/usr/bin/env python

## @package pyregfi
# Python interface to the regfi library.
#

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


regfi.regfi_init.argtypes = []
regfi.regfi_init.restype = None
regfi.regfi_init()


## Retrieves messages produced by regfi during parsing and interpretation
#
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


def _charss2strlist(chars_pointer):
    ret_val = []
    i = 0
    s = chars_pointer[i]
    while s != None:
        ret_val.append(s.decode('utf-8'))
        i += 1
        s = chars_pointer[i]

    return ret_val


## Abstract class which Handles memory management and proxies attribute
#  access to base structures  
class _StructureWrapper(object):

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

## Registry key 
class Key(_StructureWrapper):
    pass

class Value(_StructureWrapper):
    pass

## Registry value data
class Data(_StructureWrapper):
    pass

## Registry security record/permissions
class Security(_StructureWrapper):
    pass


class _GenericList(object):
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

        if name != None:
            name = create_string_buffer(bytes(name))

        if self.find_element(self.hive.file, self.key.base, name, byref(index)):
            return self.constructor(self.hive, self.get_element(self.hive.file,
                                                                self.key.base,
                                                                index))
        raise KeyError('')

    def get(self, name, default):
        try:
            return self[name]
        except KeyError:
            return default
    
    def __iter__(self):
        self.current = 0
        return self
    
    def __next__(self):
        if self.current >= self.length:
            raise StopIteration('')

        elem = self.get_element(self.hive.file, self.key.base,
                                c_uint32(self.current))
        self.current += 1
        return self.constructor(self.hive, elem)
    
    # For Python 2.x
    def next(self):
        return self.__next__()


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
        
        if name == "name":
            if ret_val == None:
                ret_val = self.name_raw
            else:
                ret_val = ret_val.decode('utf-8')
                
        elif name == "name_raw":
            length = super(Key, self).__getattr__('name_length')
            ret_val = _buffer2bytearray(ret_val, length)
        
        return ret_val


    def fetch_security(self):
        return Security(self.hive,
                        regfi.regfi_fetch_sk(self.hive.file, self.base))


## Registry value (metadata)
#
# These represent registry values (@ref REGFI_VK records) and provide
# access to their associated data.
# 
class Value(_StructureWrapper):
    def __getattr__(self, name):
        ret_val = None
        if name == "data":
            data_p = regfi.regfi_fetch_data(self.hive.file, self.base)
            try:
                data_struct = data_p.contents
            except Exception:
                return None

            if data_struct.interpreted_size == 0:
                ret_val = None
            elif data_struct.type in (REG_SZ, REG_EXPAND_SZ, REG_LINK):
                # Unicode strings
                ret_val = data_struct.interpreted.string.decode('utf-8')
            elif data_struct.type in (REG_DWORD, REG_DWORD_BE):
                # 32 bit integers
                ret_val = data_struct.interpreted.dword
            elif data_struct.type == REG_QWORD:
                # 64 bit integers
                ret_val = data_struct.interpreted.qword
            elif data_struct.type == REG_MULTI_SZ:
                ret_val = _charss2strlist(data_struct.interpreted.multiple_string)
            elif data_struct.type in (REG_NONE, REG_RESOURCE_LIST,
                                      REG_FULL_RESOURCE_DESCRIPTOR,
                                      REG_RESOURCE_REQUIREMENTS_LIST,
                                      REG_BINARY):
                ret_val = _buffer2bytearray(data_struct.interpreted.none,
                                            data_struct.interpreted_size)

            regfi.regfi_free_record(data_p)
            
        elif name == "data_raw":
            # XXX: should we load the data without interpretation instead?
            data_p = regfi.regfi_fetch_data(self.hive.file, self.base)
            try:
                data_struct = data_p.contents
            except Exception:
                return None

            ret_val = _buffer2bytearray(data_struct.raw,
                                        data_struct.size)
            regfi.regfi_free_record(data_p)            
            
        else:
            ret_val = super(Value, self).__getattr__(name)
            if name == "name":
                if ret_val == None:
                    ret_val = self.name_raw
                else:
                    ret_val = ret_val.decode('utf-8')

            elif name == "name_raw":
                length = super(Value, self).__getattr__('name_length')
                ret_val = _buffer2bytearray(ret_val, length)

        return ret_val


# Avoids chicken/egg class definitions.
# Also makes for convenient code reuse in these lists' parent classes.
_SubkeyList.constructor = Key
_ValueList.constructor = Value



## Represents a single registry hive (file)
#
class Hive():
    file = None
    raw_file = None
    
    def __init__(self, fh):
        # The fileno method may not exist, or it may throw an exception
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

    ## Creates a @ref HiveIterator initialized at the specified path in
    #  the hive. 
    #
    # Raises an Exception if the path could not be found/traversed.
    def subtree(self, path):
        hi = HiveIterator(self)
        hi.descend(path)
        return hi


## A special purpose iterator for registry hives
#
# Iterating over an object of this type causes all keys in a specific
# hive subtree to be returned in a depth-first manner. These iterators
# are typically created using the @ref Hive.subtree() function on a @ref Hive
# object.
#
# HiveIterators can also be used to manually traverse up and down a
# registry hive as they retain information about the current position in
# the hive, along with which iteration state for subkeys and values for
# every parent key.  See the @ref up and @ref down methods for more
# information.
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
            
            # XXX: Use non-generic exception
            if not regfi.regfi_iterator_down(self.iter):
                raise Exception('Error traversing iterator downward.'+
                                ' Current log:\n'+ GetLogMessages())

        regfi.regfi_iterator_first_subkey(self.iter)
        return self.current_key()

    # For Python 2.x
    def next(self):
        return self.__next__()

    def down(self):
        pass

    def up(self):
        pass

    def descend(self, path):
        #set up generator
        cpath = (bytes(p,'ascii') for p in path) 

        # evaluate generator and create char* array
        apath = (c_char_p*len(path))(*cpath)

        # XXX: Use non-generic exception
        if not regfi.regfi_iterator_walk_path(self.iter,apath):
            raise Exception('Could not locate path.\n'+GetLogMessages())

    def current_key(self):
        return Key(self.hive, regfi.regfi_iterator_cur_key(self.iter))

    #XXX Add subkey/value search accessor functions (?)
