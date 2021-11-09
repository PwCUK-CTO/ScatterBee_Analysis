"""
Description: IDA Python script to decode API calls in obfuscated strings and rename associated functions in IDA for ScatterBee samples
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

import idaapi, idc, idautils

jumper_func = idc.here()

def add_bytes(value):
    return ((value & 0xff) + ((value >> 8) & 0xff) + ((value >> 16) & 0xff) + ((value >> 24) & 0xff)) & 0xff

def hash_algo(string_start_addr, sub_value):
    out_str = b""
    byte3 = idaapi.get_byte(string_start_addr+3)
    byte2 = idaapi.get_byte(string_start_addr+2)
    byte1 = idaapi.get_byte(string_start_addr+1)
    byte0 = idaapi.get_byte(string_start_addr)
    v3 = ((17 * ((byte3 << 24) + (byte2 << 16) + (byte1 << 8) + byte0)) - sub_value) & 0xffffffff
    string_start_addr += 4
    v4 = idaapi.get_byte(string_start_addr)
    out_str += bytes([v4 ^ add_bytes(v3)])
    if v4 == add_bytes(v3):
        return out_str
    while True:
        v3 = ((17 * v3) - sub_value) & 0xffffffff
        string_start_addr += 1
        out_str += bytes([idaapi.get_byte(string_start_addr) ^ add_bytes(v3)])
        if out_str[-1:] == b"\x00":
            break
    return out_str

encode_constant = idaapi.ask_long(0, "Please enter a subtraction value in hex, e.g.: 0xabcd5678")

for i in idautils.CodeRefsTo(jumper_func, False):
    insn = idaapi.insn_t()
    if idaapi.decode_insn(insn, idc.prev_head(i)):
        if idaapi.get_inf_structure().is_64bit():
            str_loc = insn.Op2.addr
            proc_string_ea = idaapi.get_qword(str_loc+8)
        else:
            str_loc = insn.Op1.value
            proc_string_ea = idaapi.get_dword(str_loc+4)
        #lib_string_ea = idaapi.get_dword(str_loc)
        name = hash_algo(proc_string_ea, encode_constant)[:-1]
        print (name, hex(i), hex(str_loc))
        func = idaapi.get_func(i)
        if func is None:
            print ("no function defined at %08x...Attempting to create one" % i)
            #very hacky patch here as we have always seen these as push then jump thunks
            idc.add_func(i-5)
            func = idaapi.get_func(i)
            if func is not None:
                idaapi.set_name(func.start_ea, name.decode(), idaapi.SN_FORCE | idaapi.SN_NOCHECK)
            else:
                print("Still failed to create function, manual intervention required at %08x" % i)
        else:
            idaapi.set_name(func.start_ea, name.decode(), idaapi.SN_FORCE | idaapi.SN_NOCHECK)