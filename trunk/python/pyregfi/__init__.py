#!/usr/bin/env python

## @package pyregfi
# Python interface to the regfi library.
#

## @mainpage API Documentation
#
# The pyregfi module provides a Python interface to the @ref regfi Windows 
# registry library.  
#
# The library operates on registry hives, each of which is contained within a
# single file.  To get started, one must first open the registry hive file with
# the open() or file() Python built-in functions (or equivalent) and then pass
# the resulting file object to pyregfi. For example:
# @code
# >>> import pyregfi
# >>> fh = open('/mnt/win/c/WINDOWS/system32/config/system', 'rb')
# >>> myHive = pyregfi.Hive(fh)
# @endcode
#
# Using this Hive object, one can begin investigating what top-level keys
# exist by starting with the root Key attribute:
# @code
# >>> for key in myHive.root.subkeys:
# ...   print(key.name)
# ControlSet001
# ControlSet003
# LastKnownGoodRecovery
# MountedDevices
# Select
# Setup
# WPA
# @endcode
#
# From there, accessing subkeys and values by name is a simple matter of:
# @code
# >>> myKey = myHive.root.subkeys['Select']
# >>> myValue = myKey.values['Current']
# @endcode
#
# The data associated with a Value can be obtained through the fetch_data()
# method:
# @code
# >>> print(myValue.fetch_data())
# 1
# @endcode
# 
# While useful for simple exercises, using the subkeys object for deeply nested
# paths is not efficient and doesn't make for particularly attractive code.  
# Instead, a special-purpose HiveIterator class is provided for simplicity of
# use and fast access to specific known paths:
# @code
# >>> myIter = pyregfi.HiveIterator(myHive)
# >>> myIter.descend(['ControlSet001','Control','NetworkProvider','HwOrder'])
# >>> myKey = myIter.current_key()
# >>> print(myKey.values['ProviderOrder'].fetch_data())
# RDPNP,LanmanWorkstation,WebClient
# @endcode
# 
# The first two lines above can be simplified in some "syntactic sugar" provided
# by the Hive.subtree() method.  Also, as one might expect, the HiveIterator 
# also acts as an iterator, producing keys in a depth-first order.
# For instance, to traverse all keys under the ControlSet003\\Services key, 
# printing their names as we go, we could do:
# @code
# >>> for key in Hive.subtree(['ControlSet003','Services']):
# >>>   print(key.name)
# Services
# Abiosdsk
# abp480n5
# Parameters
# PnpInterface
# ACPI
# [...]
# @endcode
#
# Note that "Services" was printed first, since the subtree is traversed as a 
# "preordering depth-first" search starting with the HiveIterator's current_key().  
# As one might expect, traversals of subtrees stops when all elements in a 
# specific subtree (and none outside of it) have been traversed.
#
# For more information, peruse the various attributes and methods available on 
# the Hive, HiveIterator, Key, Value, and Security classes.
#
# @note @ref regfi is a read-only library by design and there 
# are no plans to implement write support.
# 
# @note At present, pyregfi has been tested with Python versions 2.6 and 3.1
#
# @note Developers strive to make pyregfi thread-safe.
# 
# @note Key and Value names are case-sensitive in regfi and pyregfi
#
import sys
import time
import ctypes
import ctypes.util
import threading
from pyregfi.structures import *


## An enumeration of registry Value data types
#
# @note This is a static class, there is no need to instantiate it. 
#       Just access its attributes directly as DATA_TYPES.SZ, etc
class DATA_TYPES(object):
    ## None / Unknown
    NONE                       =  0
    ## String
    SZ                         =  1
    ## String with %...% expansions
    EXPAND_SZ                  =  2
    ## Binary buffer
    BINARY                     =  3
    ## 32 bit integer (little endian)
    DWORD                      =  4 # DWORD, little endian
    ## 32 bit integer (little endian)
    DWORD_LE                   =  4
    ## 32 bit integer (big endian)
    DWORD_BE                   =  5 # DWORD, big endian
    ## Symbolic link
    LINK                       =  6
    ## List of strings
    MULTI_SZ                   =  7
    ## Unknown structure
    RESOURCE_LIST              =  8
    ## Unknown structure
    FULL_RESOURCE_DESCRIPTOR   =  9
    ## Unknown structure
    RESOURCE_REQUIREMENTS_LIST = 10
    ## 64 bit integer
    QWORD                      = 11 # 64-bit little endian


## An enumeration of log message types
#
# @note This is a static class, there is no need to instantiate it. 
#       Just access its attributes directly as LOG_TYPES.INFO, etc
class LOG_TYPES(object):
    ## Informational messages, useful in debugging
    INFO  =  0x01
    ## Non-critical problems in structure parsing or intepretation
    WARN  =  0x04
    ## Major failures
    ERROR =  0x10


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


## Retrieves messages produced by regfi during parsing and interpretation
#
# The regfi C library may generate log messages stored in a special thread-safe
# global data structure.  These messages should be retrieved periodically or 
# after each major operation by callers to determine if any errors or warnings
# should be reported to the user.  Failure to retrieve these could result in 
# excessive memory consumption.
def getLogMessages():
    msgs = regfi.regfi_log_get_str()
    if not msgs:
        return ''
    return msgs.decode('utf-8')


## Sets the types of log messages to record
#
# @param log_types A sequence of message types that regfi should generate.
#                  Message types can be found in the LOG_TYPES enumeration.
#
# @return True on success, False on failure.  Failures are rare, but could
#         indicate that global logging is not operating as expected.
# 
# Example:
# @code
# setLogMask((LOG_TYPES.ERROR, LOG_TYPES.WARN, LOG_TYPES.INFO))
# @endcode
#
# The message mask is a global (all hives, iterators), thread-specific value.
# For more information, see @ref regfi_log_set_mask.
#
def setLogMask(log_types):
    mask = 0
    for m in log_types:
        mask |= m
    return regfi.regfi_log_set_mask(mask)


## Opens a file as a registry hive
#
# @param path The file path of a hive, as one would provide to the 
#             open() built-in
#
# @return A new Hive instance
def openHive(path):
    fh = open(path, 'rb')
    return Hive(fh)


## Abstract class for most objects returned by the library
class _StructureWrapper(object):
    _hive = None
    _base = None

    def __init__(self, hive, base):
        if not hive:
            raise Exception("Could not create _StructureWrapper,"
                            + " hive is NULL.  Current log:\n"
                            + getLogMessages())
        if not base:
            raise Exception("Could not create _StructureWrapper,"
                            + " base is NULL.  Current log:\n"
                            + getLogMessages())
        self._hive = hive
        self._base = base


    # Memory management for most regfi structures is taken care of here
    def __del__(self):
        regfi.regfi_free_record(self._hive.file, self._base)


    # Any attribute requests not explicitly defined in subclasses gets passed
    # to the equivalent REGFI_* structure defined in structures.py
    def __getattr__(self, name):
        return getattr(self._base.contents, name)

    
    ## Test for equality
    #
    # Records returned by pyregfi may be compared with one another.  For example:
    # @code
    #  >>> key2 = key1.subkeys['child']
    #  >>> key1 == key2
    #  False
    #  >>> key1 != key2
    #  True
    #  >>> key1 == key2.get_parent()
    #  True
    # @endcode
    def __eq__(self, other):
        return (type(self) == type(other)) and (self.offset == other.offset)


    def __ne__(self, other):
        return (not self.__eq__(other))


class Key():
    pass


class Value():
    pass


## Registry security record and descriptor
# XXX: Access to security descriptors not yet implemented
class Security(_StructureWrapper):
    pass

## Abstract class for ValueList and SubkeyList
class _GenericList(object):
    _hive = None
    _key_base = None
    _length = None
    _current = None

    # implementation-specific functions for SubkeyList and ValueList
    _fetch_num = None
    _find_element = None
    _get_element = None
    _constructor = None

    def __init__(self, key):
        if not key:
            raise Exception("Could not create _GenericList; key is NULL."
                            + "Current log:\n" + getLogMessages())
        
        if not regfi.regfi_reference_record(key._hive.file, key._base):
            raise Exception("Could not create _GenericList; memory error."
                            + "Current log:\n" + getLogMessages())
        self._key_base = key._base
        self._length = self._fetch_num(self._key_base)
        self._hive = key._hive

    
    def __del__(self):
        regfi.regfi_free_record(self._hive.file, self._key_base)


    ## Length of list
    def __len__(self):
        return self._length


    ## Retrieves a list element by name
    #
    # @return the first element whose name matches, or None if the element
    #         could not be found
    def __getitem__(self, name):
        index = ctypes.c_uint32()
        if isinstance(name, str):
            name = name.encode('utf-8')

        if name != None:
            name = create_string_buffer(bytes(name))

        if self._find_element(self._hive.file, self._key_base, 
                              name, byref(index)):
            return self._constructor(self._hive,
                                     self._get_element(self._hive.file,
                                                       self._key_base,
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

        elem = self._get_element(self._hive.file, self._key_base,
                                 ctypes.c_uint32(self._current))
        self._current += 1
        return self._constructor(self._hive, elem)
    
    # For Python 2.x
    next = __next__


## The list of subkeys associated with a Key
#
# This attribute is both iterable:
# @code
#   for k in myKey.subkeys: 
#     ...
# @endcode
# and accessible as a dictionary:
# @code
#   mySubkey = myKey.subkeys["keyName"]
# @endcode
#
# @note SubkeyLists should never be accessed directly and only exist
#       in association with a parent Key object.  Do not retain references to 
#       SubkeyLists.  Instead, access them via their parent Key at all times.
class SubkeyList(_GenericList):
    _fetch_num = regfi.regfi_fetch_num_subkeys
    _find_element = regfi.regfi_find_subkey
    _get_element = regfi.regfi_get_subkey


## The list of values associated with a Key
#
# This attribute is both iterable:
# @code
#   for v in myKey.values: 
#     ...
# @endcode
# and accessible as a dictionary:
# @code
#   myValue = myKey.values["valueName"]
# @endcode
#
# @note ValueLists should never be accessed directly and only exist
#       in association with a parent Key object.  Do not retain references to 
#       ValueLists.  Instead, access them via their parent Key at all times.
class ValueList(_GenericList):
    _fetch_num = regfi.regfi_fetch_num_values
    _find_element = regfi.regfi_find_value
    _get_element = regfi.regfi_get_value


## Registry key 
# These represent registry keys (@ref REGFI_NK records) and provide
# access to their subkeys, values, and other metadata.
#
# @note Value instances may provide access to more than the attributes
#       documented here.  However, undocumented attributes may change over time
#       and are not officially supported.  If you need access to an attribute 
#       not shown here, see pyregfi.structures.
class Key(_StructureWrapper):
    ## A @ref ValueList object representing the list of Values 
    #  stored on this Key
    values = None

    ## A @ref SubkeyList object representing the list of subkeys 
    #  stored on this Key
    subkeys = None

    ## The raw Key name as an uninterpreted bytearray
    name_raw = (b"...")
    
    ## The name of the Key as a (unicode) string
    name = "..."
    
    ## The absolute file offset of the Key record's cell in the Hive file
    offset = 0xCAFEBABE

    ## This Key's last modified time represented as the number of seconds 
    #  since the UNIX epoch in UTC; similar to what time.time() returns
    modified = 1300000000.123456

    ## The NK record's flags field
    flags = 0x10110001

    def __init__(self, hive, base):
        super(Key, self).__init__(hive, base)
        self.values = ValueList(self)
        self.subkeys = SubkeyList(self)

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


    ## Retrieves the Security properties for this key
    def fetch_security(self):
        return Security(self._hive,
                        regfi.regfi_fetch_sk(self._hive.file, self._base))


    ## Retrieves the class name for this key
    #
    # Class names are typically stored as UTF-16LE strings, so these are decoded
    # into proper python (unicode) strings.  However, if this fails, a bytearray
    # is instead returned containing the raw buffer stored for the class name.
    #
    # @return The class name as a string or bytearray.  None if a class name
    #         doesn't exist or an unrecoverable error occurred during retrieval.
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
            regfi.regfi_free_record(self._hive.file, cn_p)

        return ret_val


    ## Retrieves this key's parent key
    #
    # @return The parent's Key instance or None if current key is root 
    #         (or an error occured) 
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
# @note Value instances may provide access to more than the attributes
#       documented here.  However, undocumented attributes may change over time
#       and are not officially supported.  If you need access to an attribute
#       not shown here, see pyregfi.structures.
class Value(_StructureWrapper):
    ## The raw Value name as an uninterpreted bytearray
    name_raw = (b"...")
    
    ## The name of the Value as a (unicode) string
    name = "..."
    
    ## The absolute file offset of the Value record's cell in the Hive file
    offset = 0xCAFEBABE

    ## The length of data advertised in the VK record
    data_size = 0xCAFEBABE

    ## An integer which represents the data type for this Value's data
    # Typically this value is one of 12 types defined in @ref DATA_TYPES,
    # but in some cases (the SAM hive) it may be used for other purposes
    type = DATA_TYPES.NONE

    ## The VK record's flags field
    flags = 0x10110001

    ## Retrieves the Value's data according to advertised type
    #
    # Data is loaded from its cell(s) and then interpreted based on the data
    # type recorded in the Value.  It is not uncommon for data to be stored with
    # the wrong type or even with invalid types.  If you have difficulty 
    # obtaining desired data here, use @ref fetch_raw_data().
    #
    # @return The interpreted representation of the data as one of several
    #         possible Python types, as listed below.  None if any failure 
    #         occurred during extraction or conversion.
    #
    # @retval string for SZ, EXPAND_SZ, and LINK
    # @retval int for DWORD, DWORD_BE, and QWORD
    # @retval list(string) for MULTI_SZ
    # @retval bytearray for NONE, BINARY, RESOURCE_LIST, 
    #         FULL_RESOURCE_DESCRIPTOR, and RESOURCE_REQUIREMENTS_LIST
    #
    def fetch_data(self):
        ret_val = None
        data_p = regfi.regfi_fetch_data(self._hive.file, self._base)
        if not data_p:
            return None
        data_struct = data_p.contents

        if data_struct.interpreted_size == 0:
            ret_val = None
        elif data_struct.type in (DATA_TYPES.SZ, DATA_TYPES.EXPAND_SZ, DATA_TYPES.LINK):
            # Unicode strings
            ret_val = data_struct.interpreted.string.decode('utf-8', 'replace')
        elif data_struct.type in (DATA_TYPES.DWORD, DATA_TYPES.DWORD_BE):
            # 32 bit integers
            ret_val = data_struct.interpreted.dword
        elif data_struct.type == DATA_TYPES.QWORD:
            # 64 bit integers
            ret_val = data_struct.interpreted.qword
        elif data_struct.type == DATA_TYPES.MULTI_SZ:
            ret_val = _charss2strlist(data_struct.interpreted.multiple_string)
        elif data_struct.type in (DATA_TYPES.NONE, DATA_TYPES.RESOURCE_LIST,
                                  DATA_TYPES.FULL_RESOURCE_DESCRIPTOR,
                                  DATA_TYPES.RESOURCE_REQUIREMENTS_LIST,
                                  DATA_TYPES.BINARY):
            ret_val = _buffer2bytearray(data_struct.interpreted.none,
                                        data_struct.interpreted_size)

        regfi.regfi_free_record(self._hive.file, data_p)
        return ret_val
    

    ## Retrieves raw representation of Value's data
    #
    # @return A bytearray containing the data
    #
    def fetch_raw_data(self):
        ret_val = None
        # XXX: should we load the data without interpretation instead?
        data_p = regfi.regfi_fetch_data(self._hive.file, self._base)
        if not data_p:
            return None

        data_struct = data_p.contents
        ret_val = _buffer2bytearray(data_struct.raw,
                                    data_struct.size)
        regfi.regfi_free_record(self._hive.file, data_p)
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
SubkeyList._constructor = Key
ValueList._constructor = Value



## Represents a single registry hive (file)
class Hive():
    file = None
    raw_file = None
    _root = None

    ## The root Key of this Hive
    root = None

    ## This Hives's last modified time represented as the number of seconds 
    #  since the UNIX epoch in UTC; similar to what time.time() returns
    modified = 1300000000.123456

    ## First sequence number
    sequence1 = 12345678

    ## Second sequence number
    sequence2 = 12345678

    ## Major version
    major_version = 1

    ## Minor version
    minor_version = 5

    ## Constructor
    #
    # Initialize a new Hive based on a Python file object.  To open a file by 
    # path, see @ref openHive.
    #
    # @param fh A Python file object.  The constructor first looks for a valid
    #           fileno attribute on this object and uses it if possible.  
    #           Otherwise, the seek and read methods are used for file
    #           access.
    #
    # @note Supplied file must be seekable.  Do not perform any operation on
    #       the provided file object while a Hive is using it.  Do not 
    #       construct multiple Hive instances from the same file object.
    #       If a file must be accessed by separate code and pyregfi 
    #       simultaneously, use a separate file descriptor.  Hives are 
    #       thread-safe, so multiple threads may use a single Hive object.
    def __init__(self, fh):
        # The fileno method may not exist, or it may throw an exception
        # when called if the file isn't backed with a descriptor.
        fn = None
        try:
            # XXX: Native calls to Windows filenos don't seem to work.  
            #      Need to investigate why.
            if not is_win32 and hasattr(fh, 'fileno'):
                fn = fh.fileno()
        except:
            pass

        if fn != None:
            self.file = regfi.regfi_alloc(fn, REGFI_ENCODING_UTF8)
            if not self.file:
                # XXX: switch to non-generic exception
                raise Exception("Could not open registry file.  Current log:\n"
                                + getLogMessages())
        else:
            fh.seek(0)
            self.raw_file = structures.REGFI_RAW_FILE()
            self.raw_file.fh = fh
            self.raw_file.seek = seek_cb_type(self.raw_file.cb_seek)
            self.raw_file.read = read_cb_type(self.raw_file.cb_read)
            self.file = regfi.regfi_alloc_cb(pointer(self.raw_file), REGFI_ENCODING_UTF8)
            if not self.file:
                # XXX: switch to non-generic exception
                raise Exception("Could not open registry file.  Current log:\n"
                                + getLogMessages())


    def __getattr__(self, name):
        if name == "root":
            # XXX: This creates reference loops.  Need to cache better inside regfi
            #if self._root == None:
            #    self._root = Key(self, regfi.regfi_get_rootkey(self.file))
            #return self._root
            return Key(self, regfi.regfi_get_rootkey(self.file))

        elif name == "modified":
            return regfi.regfi_nt2unix_time(byref(self._base.contents.mtime))

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
    # @param path A list of Key names which represent an absolute path within
    #             the Hive
    #
    # @return A @ref HiveIterator which is positioned at the specified path.
    # 
    # @exception Exception If the path could not be found/traversed
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
    _lock = None

    def __init__(self, hive):
        self._iter = regfi.regfi_iterator_new(hive.file)
        if not self._iter:
            raise Exception("Could not create iterator.  Current log:\n"
                            + getLogMessages())
        self._hive = hive
        self._lock = threading.RLock()
    
    def __getattr__(self, name):
        self._lock.acquire()
        ret_val = getattr(self._iter.contents, name)
        self._lock.release()
        return ret_val

    def __del__(self):
        self._lock.acquire()
        regfi.regfi_iterator_free(self._iter)
        self._lock.release()

    def __iter__(self):
        self._lock.acquire()
        self._iteration_root = None
        self._lock.release()
        return self

    def __next__(self):
        self._lock.acquire()
        if self._iteration_root == None:
            self._iteration_root = self.current_key().offset
        elif not regfi.regfi_iterator_down(self._iter):
            up_ret = regfi.regfi_iterator_up(self._iter)
            while (up_ret and
                   not regfi.regfi_iterator_next_subkey(self._iter)):
                if self._iteration_root == self.current_key().offset:
                    self._iteration_root = None
                    self._lock.release()
                    raise StopIteration('')
                up_ret = regfi.regfi_iterator_up(self._iter)

            if not up_ret:
                self._iteration_root = None
                self._lock.release()
                raise StopIteration('')
            
            # XXX: Use non-generic exception
            if not regfi.regfi_iterator_down(self._iter):
                self._lock.release()
                raise Exception('Error traversing iterator downward.'+
                                ' Current log:\n'+ getLogMessages())

        regfi.regfi_iterator_first_subkey(self._iter)
        ret_val = self.current_key()
        self._lock.release()

        return ret_val


    # For Python 2.x
    next = __next__

    # XXX: Should add sanity checks on some of these traversal functions
    #      to throw exceptions if a traversal/retrieval *should* have worked
    #      but failed for some reason.

    ## Descends the iterator to a subkey
    #
    # Descends the iterator one level to the current subkey, or a subkey
    # specified by name.
    #
    # @param subkey_name If specified, locates specified subkey by name
    #                    (via find_subkey()) and descends to it.
    #
    # @return True if successful, False otherwise
    def down(self, subkey_name=None):
        ret_val = None
        if subkey_name == None:
            self._lock.acquire()
            ret_val = regfi.regfi_iterator_down(self._iter)
        else:
            if name != None:
                name = name.encode('utf-8')
            self._lock.acquire()
            ret_val = (regfi.regfi_iterator_find_subkey(self._iter, name) 
                       and regfi.regfi_iterator_down(self._iter))
        
        self._lock.release()
        return ret_val


    ## Causes the iterator to ascend to the current Key's parent
    #
    # @return True if successful, False otherwise
    #
    # @note The state of current subkeys and values at this level in the tree
    #       is lost as a side effect.  That is, if you go up() and then back
    #       down() again, current_subkey() and current_value() will return 
    #       default selections.
    def up(self):
        self._lock.acquire()
        ret_val = regfi.regfi_iterator_up(self._iter)
        self._lock.release()
        return ret_val


    ## Selects first subkey of current key
    #
    # @return A Key instance for the first subkey.  
    #         None on error or if the current key has no subkeys.
    def first_subkey(self):
        ret_val = None
        self._lock.acquire()
        if regfi.regfi_iterator_first_subkey(self._iter):
            ret_val = self.current_subkey()
        self._lock.release()
        return ret_val


    ## Selects first value of current Key
    #
    # @return A Value instance for the first value.  
    #         None on error or if the current key has no values.
    def first_value(self):
        ret_val = None
        self._lock.acquire()
        if regfi.regfi_iterator_first_value(self._iter):
            ret_val = self.current_value()
        self._lock.release()
        return ret_val


    ## Selects the next subkey in the current Key's list
    #
    # @return A Key instance for the next subkey.
    #         None if there are no remaining subkeys or an error occurred.
    def next_subkey(self):
        ret_val = None
        self._lock.acquire()
        if regfi.regfi_iterator_next_subkey(self._iter):
            ret_val = self.current_subkey()
        self._lock.release()
        return ret_val


    ## Selects the next value in the current Key's list
    #  
    # @return A Value instance for the next value.
    #         None if there are no remaining values or an error occurred.
    def next_value(self):
        ret_val = None
        self._lock.acquire()
        if regfi.regfi_iterator_next_value(self._iter):
            ret_val = self.current_value()
        self._lock.release()
        return ret_val


    ## Selects the first subkey which has the specified name
    #
    # @return A Key instance for the selected key. 
    #         None if it could not be located or an error occurred.
    def find_subkey(self, name):
        if name != None:
            name = name.encode('utf-8')
        ret_val = None
        self._lock.acquire()
        if regfi.regfi_iterator_find_subkey(self._iter, name):
            ret_val = self.current_subkey()
        self._lock.release()
        return ret_val


    ## Selects the first value which has the specified name
    #
    # @return A Value instance for the selected value.
    #         None if it could not be located or an error occurred.
    def find_value(self, name):
        if name != None:
            name = name.encode('utf-8')
        ret_val = None
        self._lock.acquire()
        if regfi.regfi_iterator_find_value(self._iter, name):
            ret_val = self.current_value()
        self._lock.release()
        return ret_val

    ## Retrieves the currently selected subkey
    #
    # @return A Key instance of the current subkey
    def current_subkey(self):
        self._lock.acquire()
        ret_val = Key(self._hive, regfi.regfi_iterator_cur_subkey(self._iter))
        self._lock.release()
        return ret_val

    ## Retrieves the currently selected value
    #
    # @return A Value instance of the current value
    def current_value(self):
        self._lock.acquire()
        ret_val = Value(self._hive, regfi.regfi_iterator_cur_value(self._iter))
        self._lock.release()
        return ret_val

    ## Retrieves the current key
    #
    # @return A Key instance of the current position of the iterator
    def current_key(self):
        self._lock.acquire()
        ret_val = Key(self._hive, regfi.regfi_iterator_cur_key(self._iter))
        self._lock.release()
        return ret_val


    ## Traverse downward multiple levels
    #
    # This is more efficient than calling down() multiple times
    #
    # @param path A list of Key names which represent the path to descend
    #
    # @exception Exception If path could not be located
    def descend(self, path):
        cpath = _strlist2charss(path)

        self._lock.acquire()
        result = regfi.regfi_iterator_walk_path(self._iter, cpath)
        self._lock.release()
        if not result:
            # XXX: Use non-generic exception
            raise Exception('Could not locate path.\n'+getLogMessages())


# Freeing symbols defined for the sake of documentation
del Value.name,Value.name_raw,Value.offset,Value.data_size,Value.type,Value.flags
del Key.name,Key.name_raw,Key.offset,Key.modified,Key.flags
del Hive.root,Hive.modified,Hive.sequence1,Hive.sequence2,Hive.major_version,Hive.minor_version
