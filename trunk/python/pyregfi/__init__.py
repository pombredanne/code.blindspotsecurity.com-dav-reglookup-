#!/usr/bin/env python

## @package pyregfi
# Python interface to the regfi library.
#

import sys
import time
import weakref
from pyregfi.structures import *

import ctypes
import ctypes.util


## Retrieves messages produced by regfi during parsing and interpretation
#
def GetLogMessages():
    msgs = regfi.regfi_log_get_str()
    if msgs == None:
        return ''
    return msgs.decode('utf-8')


def _buffer2bytearray(char_pointer, length):
    if length == 0 or char_pointer == None:
        return None
    
    ret_val = bytearray(length)
    for i in range(0,length):
        ret_val[i] = char_pointer[i][0]

    return ret_val


def _strlist2charss(str_list):
    ret_val = []
    for s in str_list:
        ret_val.append(s.encode('utf-8', 'replace'))

    ret_val = (ctypes.c_char_p*(len(str_list)+1))(*ret_val)
    # Terminate the char** with a NULL pointer
    ret_val[-1] = 0

    return ret_val


def _charss2strlist(chars_pointer):
    ret_val = []
    i = 0
    s = chars_pointer[i]
    while s != None:
        ret_val.append(s.decode('utf-8', 'replace'))
        i += 1
        s = chars_pointer[i]

    return ret_val


## Abstract class which Handles memory management and proxies attribute
#  access to base structures  
class _StructureWrapper(object):
    _hive = None
    _base = None

    def __init__(self, hive, base):
        if not hive:
            raise Exception("Could not create _StructureWrapper,"
                            + " hive is NULL.  Current log:\n"
                            + GetLogMessages())
        if not base:
            raise Exception("Could not create _StructureWrapper,"
                            + " base is NULL.  Current log:\n"
                            + GetLogMessages())
        self._hive = hive
        self._base = base

    def __del__(self):
        regfi.regfi_free_record(self._base)

    def __getattr__(self, name):
        return getattr(self._base.contents, name)

    def __eq__(self, other):
        return (type(self) == type(other)) and (self.offset == other.offset)

    def __ne__(self, other):
        return (not self.__eq__(other))

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
    _hive = None
    _key = None
    _length = None
    _current = None

    # implementation-specific functions for _SubkeyList and _ValueList
    _fetch_num = None
    _find_element = None
    _get_element = None
    _constructor = None

    def __init__(self, key):
        self._hive = key._hive

        # Normally it's good to avoid cyclic references like this 
        # (key.list.key...) but in this case it makes ctypes memory
        # management easier to reference the Key instead of the base
        # structure.  We use a weak reference in order to allow for garbage 
        # collection, since value/subkey lists should not be usable if their
        # parent Key is freed anyway.

        # XXX: check for NULL here, throw an exception if so.
        self._key = weakref.proxy(key)
        self._length = self._fetch_num(key._base)

    
    def __len__(self):
        return self._length

    def __getitem__(self, name):
        index = ctypes.c_uint32()
        if isinstance(name, str):
            name = name.encode('utf-8')

        if name != None:
            name = create_string_buffer(bytes(name))

        if self._find_element(self._hive.file, self._key._base, 
                              name, byref(index)):
            return self._constructor(self._hive,
                                     self._get_element(self._hive.file,
                                                       self._key._base,
                                                       index))
        raise KeyError('')

    def get(self, name, default):
        try:
            return self[name]
        except KeyError:
            return default
    
    def __iter__(self):
        self._current = 0
        return self
    
    def __next__(self):
        if self._current >= self._length:
            raise StopIteration('')

        elem = self._get_element(self._hive.file, self._key._base,
                                 ctypes.c_uint32(self._current))
        self._current += 1
        return self._constructor(self._hive, elem)
    
    # For Python 2.x
    next = __next__


class _SubkeyList(_GenericList):
    _fetch_num = regfi.regfi_fetch_num_subkeys
    _find_element = regfi.regfi_find_subkey
    _get_element = regfi.regfi_get_subkey


class _ValueList(_GenericList):
    _fetch_num = regfi.regfi_fetch_num_values
    _find_element = regfi.regfi_find_value
    _get_element = regfi.regfi_get_value


## Registry key 
class Key(_StructureWrapper):
    values = None
    subkeys = None

    def __init__(self, hive, base):
        super(Key, self).__init__(hive, base)
        self.values = _ValueList(self)
        self.subkeys = _SubkeyList(self)

    def __getattr__(self, name):
        if name == "name":
            ret_val = super(Key, self).__getattr__(name)

            if ret_val == None:
                ret_val = self.name_raw
            else:
                ret_val = ret_val.decode('utf-8', 'replace')
                
        elif name == "name_raw":
            ret_val = super(Key, self).__getattr__(name)
            length = super(Key, self).__getattr__('name_length')
            ret_val = _buffer2bytearray(ret_val, length)
        
        elif name == "modified":
            ret_val = regfi.regfi_nt2unix_time(byref(self._base.contents.mtime))

        else:
            ret_val = super(Key, self).__getattr__(name)

        return ret_val

    def fetch_security(self):
        return Security(self._hive,
                        regfi.regfi_fetch_sk(self._hive.file, self._base))

    def fetch_classname(self):
        ret_val = None
        cn_p = regfi.regfi_fetch_classname(self._hive.file, self._base)
        if cn_p:
            cn_struct = cn_p.contents
            if cn_struct.interpreted:
                ret_val = cn_struct.interpreted.decode('utf-8', 'replace')
            else:
                ret_val = _buffer2bytearray(cn_struct.raw,
                                            cn_struct.size)
            regfi.regfi_free_record(cn_p)

        return ret_val

    def get_parent(self):
        if self.is_root():
            return None
        parent_base = regfi.regfi_get_parentkey(self._hive.file, self._base)
        if parent_base:
            return Key(self._hive, parent_base)
        return None

    def is_root(self):
        return (self._hive.root == self)


## Registry value (metadata)
#
# These represent registry values (@ref REGFI_VK records) and provide
# access to their associated data.
# 
class Value(_StructureWrapper):
    def fetch_data(self):
        ret_val = None
        data_p = regfi.regfi_fetch_data(self._hive.file, self._base)
        if not data_p:
            return None
        data_struct = data_p.contents

        if data_struct.interpreted_size == 0:
            ret_val = None
        elif data_struct.type in (REG_SZ, REG_EXPAND_SZ, REG_LINK):
            # Unicode strings
            ret_val = data_struct.interpreted.string.decode('utf-8', 'replace')
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
        return ret_val
        
    def fetch_raw_data(self):
        ret_val = None

        # XXX: should we load the data without interpretation instead?
        data_p = regfi.regfi_fetch_data(self._hive.file, self._base)
        if not data_p:
            return None

        data_struct = data_p.contents
        ret_val = _buffer2bytearray(data_struct.raw,
                                    data_struct.size)
        regfi.regfi_free_record(data_p)

        return ret_val

    def __getattr__(self, name):
        ret_val = super(Value, self).__getattr__(name)
        if name == "name":
            if ret_val == None:
                ret_val = self.name_raw
            else:
                ret_val = ret_val.decode('utf-8', 'replace')

        elif name == "name_raw":
            length = super(Value, self).__getattr__('name_length')
            ret_val = _buffer2bytearray(ret_val, length)

        return ret_val


# Avoids chicken/egg class definitions.
# Also makes for convenient code reuse in these lists' parent classes.
_SubkeyList._constructor = Key
_ValueList._constructor = Value



## Represents a single registry hive (file)
#
class Hive():
    file = None
    raw_file = None
    _root = None

    def __init__(self, fh):
        # The fileno method may not exist, or it may throw an exception
        # when called if the file isn't backed with a descriptor.
        try:
            if hasattr(fh, 'fileno'):
                self.file = regfi.regfi_alloc(fh.fileno(), REGFI_ENCODING_UTF8)
                return
        except:
            pass
        
        self.raw_file = structures.REGFI_RAW_FILE()
        self.raw_file.fh = fh
        self.raw_file.seek = seek_cb_type(self.raw_file.cb_seek)
        self.raw_file.read = read_cb_type(self.raw_file.cb_read)
        self.file = regfi.regfi_alloc_cb(self.raw_file, REGFI_ENCODING_UTF8)

    def __getattr__(self, name):
        if name == "root":
            if self._root == None:
                self._root = Key(self, regfi.regfi_get_rootkey(self.file))
            return self._root

        return getattr(self.file.contents, name)
    
    def __del__(self):
        regfi.regfi_free(self.file)
        if self.raw_file != None:
            self.raw_file = None

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
    _hive = None
    _iter = None
    _iteration_root = None

    def __init__(self, hive):
        self._iter = regfi.regfi_iterator_new(hive.file, REGFI_ENCODING_UTF8)
        if self._iter == None:
            raise Exception("Could not create iterator.  Current log:\n"
                            + GetLogMessages())
        self._hive = hive
        
    def __getattr__(self, name):
        return getattr(self.file.contents, name)

    def __del__(self):    
        regfi.regfi_iterator_free(self._iter)

    def __iter__(self):
        self._iteration_root = None
        return self

    def __next__(self):
        if self._iteration_root == None:
            self._iteration_root = self.current_key()
        elif not regfi.regfi_iterator_down(self._iter):
            up_ret = regfi.regfi_iterator_up(self._iter)
            while (up_ret and
                   not regfi.regfi_iterator_next_subkey(self._iter)):
                if self._iteration_root == self.current_key():
                    self._iteration_root = None
                    raise StopIteration('')
                up_ret = regfi.regfi_iterator_up(self._iter)

            if not up_ret:
                raise StopIteration('')
            
            # XXX: Use non-generic exception
            if not regfi.regfi_iterator_down(self._iter):
                raise Exception('Error traversing iterator downward.'+
                                ' Current log:\n'+ GetLogMessages())

        regfi.regfi_iterator_first_subkey(self._iter)
        return self.current_key()

    # For Python 2.x
    next = __next__

    def down(self, subkey_name=None):
        if subkey_name == None:
            return regfi.regfi_iterator_down(self._iter)
        else:
            if name != None:
                name = name.encode('utf-8')
            return (regfi.regfi_iterator_find_subkey(self._iter, name) 
                    and regfi.regfi_iterator_down(self._iter))

    def up(self):
        return regfi.regfi_iterator_up(self._iter)

    def first_subkey(self):
        if regfi.regfi_iterator_first_subkey(self._iter):
            return self.current_subkey()
        return None

    def first_value(self):
        if regfi.regfi_iterator_first_value(self._iter):
            return self.current_value()
        return None

    def next_subkey(self):
        if regfi.regfi_iterator_next_subkey(self._iter):
            return self.current_subkey()
        return None

    def next_value(self):
        if regfi.regfi_iterator_next_value(self._iter):
            return self.current_value()
        return None

    def find_subkey(self, name):
        if name != None:
            name = name.encode('utf-8')
        if regfi.regfi_iterator_find_subkey(self._iter, name):
            return self.current_subkey()
        return None

    def find_value(self, name):
        if name != None:
            name = name.encode('utf-8')
        if regfi.regfi_iterator_find_value(self._iter, name):
            return self.current_value()
        return None

    def current_subkey(self):
        return Key(self._hive, regfi.regfi_iterator_cur_subkey(self._iter))

    def current_value(self):
        return Value(self._hive, regfi.regfi_iterator_cur_value(self._iter))

    def current_key(self):
        return Key(self._hive, regfi.regfi_iterator_cur_key(self._iter))

    def descend(self, path):
        cpath = _strlist2charss(path)

        # XXX: Use non-generic exception
        if not regfi.regfi_iterator_walk_path(self._iter, cpath):
            raise Exception('Could not locate path.\n'+GetLogMessages())
