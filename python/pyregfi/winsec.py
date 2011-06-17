#!/usr/bin/env python

## @package pyregfi.winsec
# Low-level data structures for winsec library
#

import sys
import os
import uuid
import ctypes
import ctypes.util
from ctypes import *
from .structures import regfi

is_win32 = hasattr(ctypes, 'windll')
WINSEC_MAX_SUBAUTHS = 15

if is_win32:
    libc = cdll.msvcrt
else:
    libc = cdll.LoadLibrary("libc.so.6")

class WINSEC_UUID(Structure):
    pass

class WINSEC_DOM_SID(Structure):
    pass

class WINSEC_ACE(Structure):
    pass

class WINSEC_ACL(Structure):
    pass

class WINSEC_DESC(Structure):
    pass

WINSEC_UUID._fields_ = [('time_low', c_uint32),
                        ('time_mid', c_uint16),
                        ('time_hi_and_version', c_uint16),
                        ('clock_seq', c_uint8*2),
                        ('node', c_uint8*6),
                        ]

WINSEC_DOM_SID._fields_ = [('sid_rev_num', c_uint8),
                           ('num_auths', c_uint8),
                           ('id_auths', c_uint8*6),
                           ('sub_auths', c_uint32*WINSEC_MAX_SUBAUTHS),
                           ]

WINSEC_ACE._fields_ = [('type', c_uint8),
                       ('flags', c_uint8),
                       ('size', c_uint16),
                       ('access_mask', c_uint32),
                       ('obj_flags', c_uint32),
                       ('obj_guid', POINTER(WINSEC_UUID)),
                       ('inh_guid', POINTER(WINSEC_UUID)),
                       ('trustee', POINTER(WINSEC_DOM_SID)),
                       ]

WINSEC_ACL._fields_ = [('revision', c_uint16),
                       ('size', c_uint16),
                       ('num_aces', c_uint32),
                       ('aces', POINTER(POINTER(WINSEC_ACE))),
                       ]

WINSEC_DESC._fields_ = [('revision', c_uint8),
                        ('sbz1', c_uint8),
                        ('control', c_uint16),
                        ('off_owner_sid', c_uint32),
                        ('off_grp_sid', c_uint32),
                        ('off_sacl', c_uint32),
                        ('off_dacl', c_uint32),
                        ('owner_sid', POINTER(WINSEC_DOM_SID)),
                        ('grp_sid', POINTER(WINSEC_DOM_SID)),
                        ('sacl', POINTER(WINSEC_ACL)),
                        ('dacl', POINTER(WINSEC_ACL)),
                        ]
regfi.winsec_sid2str.argtypes = [POINTER(WINSEC_DOM_SID)]
regfi.winsec_sid2str.restype = POINTER(c_char)


def _guid2uuid(guid):
    if not guid:
        return None
    return uuid.UUID(fields=(guid.contents.time_low,
                             guid.contents.time_mid,
                             guid.contents.time_hi_and_version,
                             guid.contents.clock_seq[0],
                             guid.contents.clock_seq[1],
                             guid.contents.node[0]<<40
                             ^ guid.contents.node[1]<<32
                             ^ guid.contents.node[2]<<24
                             ^ guid.contents.node[3]<<16
                             ^ guid.contents.node[4]<<8
                             ^ guid.contents.node[5]))

## Represents a Microsoft access control entry, which are elements of access
#  control lists.  For more information, see: 
#    http://msdn.microsoft.com/en-us/library/aa374868%28v=vs.85%29.aspx
#
#  @note
#  This interface is subject to change
class ACE(object):
    ## The type of entry as an integer
    type = 1234
    
    ## The flags as an integer
    flags = 0x1234

    ## The access mask/permissions as an integer
    access_mask = 0x1234

    ## The trustee's SID as a string
    trustee = "S-1-2..."
    
    ## The object GUID as a Python UUID
    # May be None
    object = uuid.UUID(fields=(0x12345678, 0x1234, 0x5678, 0x12, 0x34, 0x567812345678))

    ## The inherited object GUID as a Python UUID
    # May be None
    inherited_object = uuid.UUID(fields=(0x12345678, 0x1234, 0x5678, 0x12, 0x34, 0x567812345678))

    def __init__(self, ace):
        # Just copy all of the values out so we don't need to manage memory
        self.object = _guid2uuid(ace.obj_guid)
        self.inherited_object = _guid2uuid(ace.inh_guid)

        c_str = regfi.winsec_sid2str(ace.trustee)
        self.trustee = ctypes.cast(c_str, c_char_p).value.decode('utf-8', 'replace')
        libc.free(c_str)

        self.type = int(ace.type)
        self.flags = int(ace.flags)
        self.access_mask = int(ace.access_mask)


## A Microsoft security descriptor
# For more information, see:
#   http://msdn.microsoft.com/en-us/library/aa379563%28v=vs.85%29.aspx
#
class SecurityDescriptor(object):
    ## The security descriptor's owner SID, as a string
    owner = "S-1-2-..."

    ## The security descriptor's group SID, as a string
    group = "S-1-2-..."

    ## The system access control list represented as a list of @ref ACE objects.
    # 
    # Is set to None if a sacl isn't defined
    sacl = []

    ## The discretionary access control list represented as a list of @ref ACE objects
    #
    # Is set to None if a dacl isn't defined
    dacl = []

    def __init__(self, sec_desc):
        c_str = regfi.winsec_sid2str(sec_desc.owner_sid)
        self.owner = ctypes.cast(c_str, c_char_p).value.decode('utf-8', 'replace')
        libc.free(c_str)
        
        c_str = regfi.winsec_sid2str(sec_desc.grp_sid)
        self.group = ctypes.cast(c_str, c_char_p).value.decode('utf-8', 'replace')
        libc.free(c_str)

        self.sacl = None
        if sec_desc.sacl:
            self.sacl = []
            for i in range(0,sec_desc.sacl.contents.num_aces):
                self.sacl.append(ACE(sec_desc.sacl.contents.aces[i].contents))

        self.dacl = None
        if sec_desc.dacl:
            self.dacl = []
            for i in range(0,sec_desc.dacl.contents.num_aces):
                self.dacl.append(ACE(sec_desc.dacl.contents.aces[i].contents))


# Free class objects used for documentation
del ACE.type,ACE.flags,ACE.access_mask,ACE.object,ACE.inherited_object
del SecurityDescriptor.owner,SecurityDescriptor.group,SecurityDescriptor.sacl,SecurityDescriptor.dacl
