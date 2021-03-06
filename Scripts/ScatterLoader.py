"""
Description: IDA Python Loader script to load an executable in the custom ScatterBee format generated by ScatterRebuildPayload.py
Author: @malworms
License:
Copyright 2021 PwC UK
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at
    http://www.apache.org/licenses/LICENSE-2.0
Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
"""

#This script is meant to be placed inside the /loaders folder of your IDA installation

import struct, idaapi, idc

def add_seg(startea, endea, base, use32, name, clas):
    s = idaapi.segment_t()
    s.start_ea = startea
    s.end_ea   = endea
    s.sel      = idaapi.setup_selector(base)
    s.bitness  = use32
    s.align    = idaapi.saRelPara
    s.comb     = idaapi.scPub
    idaapi.add_segm_ex(s, name, clas, idaapi.ADDSEG_NOSREG|idaapi.ADDSEG_OR_DIE)

#first function called by IDA to check if the input file is valid
#we have set our custom file format to start with: SCATTER! - unlikely to collide with legitimate file formats
def accept_file(li, n):
    li.seek(0)
    if li.read(8) == b"SCATTER!":
        return {'format': "SCATTERBEE image", 'processor':'metapc'}
    return 0

#second function called by IDA to load the input file into an IDB database
#is required to map code/data to their respective segments
#TODO: extend this to support loading type libraries
def load_file(li, netflags, format):
    filesize = li.size()
    li.seek(8)
    #we want to use x86/64
    idaapi.set_processor_type("metapc", idaapi.SETPROC_LOADER)
    bitwidth = li.read(1)
    codetag = li.read(4)
    if codetag != b"CODE":
        print (codetag)
        idc.warning("did not find CODE tag")
        return 0
    code_base = 0
    code_length = 0
    bitness = 0
    if bitwidth == b" ":#32
        code_base = struct.unpack('<I', li.read(4))[0]
        code_length = struct.unpack('<I', li.read(4))[0]
        bitness = 1
    elif bitwidth == b"@":#64
        code_base = struct.unpack('<Q', li.read(8))[0]
        code_length = struct.unpack('<Q', li.read(8))[0]
        bitness = 2
    else:
        idc.warning("Error, unsupported bitwidth field found... %02x" % bitwidth)
        return 0
    #idc.warning("got to end")
    cur_offs = li.tell()
    if cur_offs+code_length > filesize:
        idc.warning("Error, CODE section is bigger than data to read")
        return 0
    add_seg(code_base, code_base+code_length, 0, bitness, ".text", "CODE")
    li.file2base(cur_offs, code_base, code_base+code_length, 1)
    print(li.tell())
    datatag = li.read(4)
    if datatag != b"DATA":
        idc.warning("Parsing DATA tag failed, possibly corrupt input file")
        return 0
    data_base = 0
    data_length = 0
    if bitwidth == b" ":#32
        data_base = struct.unpack('<I', li.read(4))[0]
        data_length = struct.unpack('<I', li.read(4))[0]
    elif bitwidth == b"@":#64
        currentflags = idc.get_inf_attr(idc.INF_LFLAGS)
        #make sure flag is set for 64 bit CPU here otherwise the decompiler won't work
        idc.set_inf_attr(idc.INF_LFLAGS, currentflags | idc.LFLG_64BIT)
        data_base = struct.unpack('<Q', li.read(8))[0]
        data_length = struct.unpack('<Q', li.read(8))[0]
    cur_offs = li.tell()
    if cur_offs+data_length > filesize:
        idc.warning("Error, DATA section is bigger than data to read")
        return 0
    print (data_base)
    print (data_length)
    add_seg(data_base, data_base+data_length, 0, bitness, ".data", "DATA")
    li.file2base(cur_offs, data_base, data_base+data_length, 1)
    return 1