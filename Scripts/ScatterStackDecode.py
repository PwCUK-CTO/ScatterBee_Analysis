"""
Description: IDA Python script to decode strings in ScatterBee payloads that are decoded at runtime and add them as comments
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
import hashlib
from Crypto.Cipher import AES

def get_encode_constant():
    lea_addr = idaapi.find_binary(idaapi.cvar.inf.minEA, idaapi.cvar.inf.maxEA, "8d 84 c8", 16, idaapi.SEARCH_DOWN)
    if lea_addr == idaapi.BADADDR:
        return lea_addr
    add_value = idaapi.get_dword(lea_addr+3)
    return (add_value ^ 0xffffffff) + 1

def get_push_args(addr):
    insn = idaapi.insn_t()
    idaapi.decode_insn(insn, addr)
    count = 0
    ret_arg_vals = []
    while count < 100:
        if insn.itype == 0x10:
            #call instruction
            break
        if insn.itype == 0x8f and insn.Op1.type == idaapi.o_imm:
            ret_arg_vals.append(insn.Op1.value)
        for ref in idautils.CodeRefsTo(addr, True):
            if ref != idc.prev_head(addr):
                #hacky quit method
                count = 100
        addr = idc.prev_head(addr)
        idaapi.decode_insn(insn, addr)
        count += 1
    return ret_arg_vals

def get_fast_call_args(addr):
    insn = idaapi.insn_t()
    idaapi.decode_insn(insn, addr)
    count = 0
    ret_arg_vals = []
    edx = None
    r8d = None
    r9d = None
    while count < 20:
        if insn.itype == 0x10:
            #call instruction
            break
        if insn.itype == idaapi.NN_mov:
            if insn.Op1.type == idaapi.o_reg and insn.Op2.type == idaapi.o_imm:
                if insn.Op1.reg == 8:
                    r8d = insn.Op2.value & 0xffffffff
                elif insn.Op1.reg == 9:
                    r9d = insn.Op2.value & 0xffffffff
                elif insn.Op1.reg == 2:
                    edx = insn.Op2.value & 0xffffffff
                    break
        for ref in idautils.CodeRefsTo(addr, True):
            if ref != idc.prev_head(addr):
                #hacky quit method
                count = 5
        addr = idc.prev_head(addr)
        idaapi.decode_insn(insn, addr)
        count += 1
    if edx is not None:
        ret_arg_vals.append(edx)
    if r8d is not None:
        ret_arg_vals.append(r8d)
    if r9d is not None:
        ret_arg_vals.append(r9d)
    return ret_arg_vals

def get_mov_stack_args(addr):
    insn = idaapi.insn_t()
    idaapi.decode_insn(insn, addr)
    count = 0
    ret_arg_vals = []
    while count < 100:
        if insn.itype == 0x10:
            #call instruction
            break
        elif insn.itype == 0x7a and insn.Op1.type == 4 and insn.Op2.type == idaapi.o_imm and (insn.Op1.reg == 4 or insn.Op1.reg == 0):
            stack_val = insn.Op1.addr & 0xffffffff
            if stack_val & 0x80000000:
                stack_val -= 0x100000000
            ret_arg_vals.append([stack_val, insn.Op2.value & 0xffffffff])
        for ref in idautils.CodeRefsTo(addr, True):
            if ref != idc.prev_head(addr):
                #hacky quit method
                count = 100
        addr = idc.prev_head(addr)
        idaapi.decode_insn(insn, addr)
        count += 1
    final_ret_vals = []
    low_val = 0xffffffff
    for i in ret_arg_vals:
        if i[0] < low_val:
            low_val = i[0]
    if low_val == 0xffffffff:
        return []
    while len(ret_arg_vals) > 0:
        index = 0
        low_val_found = False
        while index < len(ret_arg_vals):
            if ret_arg_vals[index][0] == low_val:
                low_val += 8
                low_val_found = True
                break
            index += 1
        if low_val_found == False:
            return final_ret_vals
        else:
            pair = ret_arg_vals.pop(index)
            final_ret_vals.append(pair[1])
    return final_ret_vals

def add_bytes(value):
    return ((value & 0xff) + ((value >> 8) & 0xff) + ((value >> 16) & 0xff) + ((value >> 24) & 0xff)) & 0xff

#adapted from - https://www.fireeye.com/content/dam/fireeye-www/global/en/blog/threat-research/flareon2016/challenge2-solution.pdf
def derive_key(key_md5):
    # SHA-1 hash algorithm used
    b0 = b""
    for x in key_md5:
        b0 += bytes([x ^ 0x36])
    b1 = b""
    for x in key_md5:
        b1 += bytes([x ^ 0x5c])
    # pad remaining bytes with the appropriate value
    b0 += b"\x36"*(64 - len(b0))
    b1 += b"\x5c"*(64 - len(b1))
    b0_md5 = hashlib.md5(b0).digest()
    b1_md5 = hashlib.md5(b1).digest()
    return b0_md5 + b1_md5

def decoder_AES(args, key_seed):
    length = (args[0] & 0xffff) ^ ((args[0] >> 16)+0x6811)
    seed1 = args[0] >> 24
    seed2 = (args[0] >> 16) & 0xff
    key = derive_key(hashlib.md5(key_seed+bytes([seed2])+bytes([seed1])).digest())[:16]
    obf_data = args[1:]
    obf_arr = b""
    for i in obf_data:
        obf_arr += bytes([i & 0xff])
        obf_arr += bytes([(i>>8) & 0xff])
        obf_arr += bytes([(i>>16) & 0xff])
        obf_arr += bytes([(i>>24) & 0xff])
    decryptor = AES.new(key, AES.MODE_CBC, iv=b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00")
    return decryptor.decrypt(obf_arr)

def decoder(args, sub_value):
    xor_val = args[0]
    obf_data = args[1:]
    obf_arr = []
    for i in obf_data:
        obf_arr.append(i & 0xff)
        obf_arr.append((i>>8) & 0xff)
        obf_arr.append((i>>16) & 0xff)
        obf_arr.append((i>>24) & 0xff)
    length = (xor_val & 0xffff) ^ (xor_val >> 16)
    if length > len(obf_arr):
        return b"%08x problem" % args[0]
    start_val = xor_val & 0xffff
    index = 0
    out_str = b""
    while index < length:
        start_val = ((17 * start_val) - sub_value) & 0xffffffff
        out_str += bytes([obf_arr[index] ^ (add_bytes(start_val))])
        index += 1
    return out_str

AES_keys = [b"\x82\xe4\xe2\xfe\xf1\x55\xd0\x9e\x01\xb7\x98\xff\x31\x8c\x0a\xf8", b"\x39\x88\xa1\x8d\xba\xe0\xd9\xf1\xb1\x5f\xaf\xc7\x62\x1e\x0d\x80"]
sub_keys = [0x53335D9F, 0xEF819993, 0xe8589ff, 0xdc7f607, 0x443246ba, 0x56AB233F]

use_AES = idaapi.ask_yn(0, "Answer Yes to decode AES strings, answer No to decode stream cipher strings")
use_FastCall = idaapi.ask_yn(0, "Answer Yes if the decode function uses __fastcall, answer No if the decode function uses any other calling convention")
if not use_AES:
    subkey = idaapi.ask_long(0, "Enter the hex value of the subtraction key. e.g.: 0xabcd1234")

for ref in idautils.CodeRefsTo(idc.here(), False):
    if use_FastCall:
        args = get_fast_call_args(idc.prev_head(ref))
        if len(args) == 3:
            stack_args = get_mov_stack_args(idc.prev_head(ref))
            for i in stack_args:
                args.append(i)
    else:
        args = get_push_args(idc.prev_head(ref))
    if len(args) > 1:
        if use_AES:
            for key in AES_keys:
                try:
                    decoded_str = decoder_AES(args, key)
                    if b"problem" in decoded_str:
                        print("error at %08x" % ref)
                        print(decoded_str)
                    else:
                        if decoded_str[-1] == decoded_str[-2]:
                            decoded_str = decoded_str[:-decoded_str[-1]]
                        print (decoded_str.strip())
                        idaapi.set_cmt(ref, decoded_str.strip().decode(), True)
                        break
                except:
                    pass
        else:
            decoded_str = decoder(args, subkey)
            idaapi.set_cmt(ref, decoded_str.decode(), True)
            print (decoded_str)
print ("If no errors occurred and no strings are decoded, then it is likely the AES key is unknown")