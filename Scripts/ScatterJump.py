"""
Description: IDA Python processor module extension to hook ScatterBee calls and fixup jump destinations
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

import idaapi
import idautils
import idc
import binascii

def AddOffset(addr, offset, is64bit):
        if is64bit:
            if offset & 0x80000000:
                offset |= 0xffffffff00000000
            addr += offset
            addr &= 0xffffffffffffffff
            return addr
        else:
            addr += offset
            addr &= 0xffffffff
            return addr

class ScatterHook(idaapi.IDP_Hooks):
    def __init__(self, tramp_offset):
        idaapi.IDP_Hooks.__init__(self)
        self.is64bit = idaapi.get_inf_structure().is_64bit
        self.tramp_offset = tramp_offset

    def ev_ana_insn(self, insn):
        b = idaapi.get_byte(insn.ea)
        if b == 0xE8: # call
            offset = idaapi.get_dword(insn.ea+1)
            if AddOffset(insn.ea+5, offset, self.is64bit) == self.tramp_offset:# the call is going to end up going to the dispatcher function
                insn.itype = idaapi.NN_jmp
                insn.Op1.type = idaapi.o_near
                insn.Op1.flags = 8
                insn.Op1.dtype = idaapi.dt_dword
                insn.Op1.specval = 0x1e0000#relative jump and not an absolute jump
                if self.is64bit:
                    insn.Op1.addr = (insn.ea+5+idaapi.get_qword(insn.ea+5)) & 0xffffffffffffffff
                else:
                    insn.Op1.addr = (idaapi.get_dword(insn.ea+5) + insn.ea + 5) & 0xffffffff
                insn.size = 9
                return True
        return False

def GetAllCallLocations():
    start_ea = idaapi.cvar.inf.minEA
    end_ea = idaapi.cvar.inf.maxEA
    call_loc = idaapi.find_binary(start_ea, end_ea, "e8", 16, idaapi.SEARCH_DOWN)
    call_locs = []
    while call_loc != idaapi.BADADDR:
        call_locs.append(call_loc)
        call_loc = idaapi.find_binary(call_loc+1, end_ea, "e8", 16, idaapi.SEARCH_DOWN)
    return call_locs

def GetDestination(call_addr):
    return AddOffset(call_addr+5, idaapi.get_dword(call_addr+1), idaapi.get_inf_structure().is_64bit())

#for each call location, find the most common call destination and check it starts with an xchg instruction
#return the location if there are > 1000 calls, most code will not call the same function 1500 times
def NeedScatterJumper():
    max_val = 0
    max_key = idaapi.BADADDR
    calls = GetAllCallLocations()
    dests = {}
    for call in calls:
        dest = GetDestination(call)
        if dest in dests:
            cur_val = dests.get(dest)
            dests[dest] = cur_val+1
            if cur_val+1 > max_val:
                max_val = cur_val+1
                max_key = dest
        else:
            dests[dest] = 1
    print ("Trampoline function entry: %08x" % max_key)
    #now print out if the start bytes are unusual, if they are the user can see the bytes and decide to decline to load the plugin
    if idaapi.get_inf_structure().is_64bit():
        if idaapi.get_bytes(max_key, 2) != b"\x4c\x87" or idaapi.get_bytes(max_key, 2) != b"\x48\x87":
            print ("found unknown start bytes: ", idaapi.get_bytes(max_key, 5))
    else:
        if idaapi.get_bytes(max_key, 1) != b"\x87":
            print ("found unknown start bytes: ", idaapi.get_bytes(max_key, 5))
    #check there were lots of calls to this function
    #this check is quite naive, but will only fp in weird circumstances and the user can still overrule it later.
    #go binaries may be particularly susceptible to FPs
    if max_val > 1500:
        return max_key
    return idaapi.BADADDR

#core IDA processor module extension code
class ScatterHook_t(idaapi.plugin_t):
    flags = idaapi.PLUGIN_PROC | idaapi.PLUGIN_HIDE
    comment = "ScatterJumper"
    wanted_hotkey = ""
    help = "Runs transparently"
    wanted_name = "ScatterJumper"
    hook = None

    def init(self):
        self.hook = None
        jump_loc = NeedScatterJumper()
        if jump_loc != idaapi.BADADDR:
            if idaapi.ask_yn(0, "Use the ScatterJump plugin?"):
                print ("######## Loading ScatterJumper ########")
                self.hook = ScatterHook(jump_loc)
                self.hook.hook()
                return idaapi.PLUGIN_KEEP
        return idaapi.PLUGIN_SKIP

    def run(self, arg):
        pass

    def term(self):
        if self.hook:
            self.hook.unhook()

def PLUGIN_ENTRY():
    return ScatterHook_t()