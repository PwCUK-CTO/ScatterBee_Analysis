"""
Description: IDA Python script to recursively descend through ScatterBee shellcode and rebuild an analysable binary. Output can be loaded into IDA with ScatterLoader.py
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

import idaapi, idc, idautils, struct

#script to extract original binaries from ScatterBee encoded binaries used by ShadowPad
#assumes the cursor is on the entry point to the shellcode
#requires the binary to have a code section and a data section
#code section should be the start of the shellcode up until the start of the relocations
#data section should be from the relocations up until the end of the binary

#set of addresses flagged for analysis
todo_addrs = set()
#add the first instruction
todo_addrs.add(idc.here())
#set of addresses that have already been analysed
used_addrs = set()
#list of chains of code execution
chains = []
#special high value used to differentiate normal jumps from fake ones
#not used in most binaries but there just in case a binary has multiple flows of instructions
#into the same instruction
fix_addrs = 0xffffffffffff0000
#base address is the lowest code address of this section
#base the new code at the same address as the old code so that offsets into the data section match
base_addr = idaapi.getseg(idc.here()).start_ea

#offset instructions: list of instructions that are known to be used by ScatterBee to load memory addresses for later use
offset_insns = [idaapi.NN_lea, idaapi.NN_push, idaapi.NN_mov, idaapi.NN_movzx, idaapi.NN_fstp, idaapi.NN_fdiv, idaapi.NN_fcomp,
    idaapi.NN_fcom, idaapi.NN_fst, idaapi.NN_fsubr, idaapi.NN_fild, idaapi.NN_fld, idaapi.NN_adc, idaapi.NN_movsx,
    idaapi.NN_movsxd, idaapi.NN_cmovnz, idaapi.NN_cmp, idaapi.NN_and, idaapi.NN_inc, idaapi.NN_fadd, idaapi.NN_fmul]

#none offset instructions: list of insns to explicitly ignore when checking code flow
none_offset_insns = [idaapi.NN_add, idaapi.NN_xor, idaapi.NN_pop, idaapi.NN_sub, idaapi.NN_test,
    idaapi.NN_dec, idaapi.NN_setz, idaapi.NN_imul, idaapi.NN_nop, idaapi.NN_or, idaapi.NN_bt]

#terrible python, but it does the job of getting the next instruction to analyse
def get_next_addr():
    global todo_addrs
    global used_addrs
    cur_addr = idaapi.BADADDR
    while len(todo_addrs) > 0:
        cur_addr = todo_addrs.pop()
        while cur_addr in used_addrs:
            if len(todo_addrs) == 0:
                cur_addr = idaapi.BADADDR
                break
            else:
                cur_addr = todo_addrs.pop()
        if cur_addr != idaapi.BADADDR:
            break
    return cur_addr

def InfoMsg(string):
    print ("[INFO]: " + string)

def in_code_section(ea):
    if idaapi.getseg(ea) is not None and idaapi.getseg(ea).type == 2:
        return True
    return False

def get_pointer(ea):
    if idaapi.get_inf_structure().is_64bit():
        return idaapi.get_qword(ea)
    else:
        return idaapi.get_dword(ea)

def use_addresses(ea, size):
    global used_addrs
    for i in range(ea, ea+size):
        used_addrs.add(i)

#checks if current address is an obfuscated jump based on metadata added by ScatterJump.py
def is_fudge_call(ea):
    insn = idaapi.insn_t()
    idaapi.decode_insn(insn, ea)
    if insn.itype == idaapi.NN_jmp and insn.size == 9:
        return True
    return False

#jumps through obfuscated calls until it gets to a normal instruction
def get_fudge_dest(ea):
    while is_fudge_call(ea):
        insn = idaapi.insn_t()
        idaapi.decode_insn(insn, ea)
        ea = insn.Op1.addr
    return ea

#naive check for known bytes at start of functions
def is_func_start(ea):
    if idaapi.get_inf_structure().is_64bit():
        if idaapi.get_byte(ea) == 0x55:
            return True
        if idaapi.get_byte(ea) == 0x51:
            return True
        if idaapi.get_byte(ea) == 0x53:
            return True
        if idaapi.get_byte(ea) == 0x52:
            return True
        if idaapi.get_byte(ea) == 0xe9:
            return True
        if idaapi.get_word(ea) == 0x8948:
            return True
        if idaapi.get_word(ea) == 0x8148:
            return True
        if idaapi.get_word(ea) == 0x8348:
            return True
        if idaapi.get_word(ea) == 0x8B48:
            return True
        if idaapi.get_word(ea) == 0x8B4c:
            return True
        if idaapi.get_word(ea) == 0xb70f:
            return True
    else:
        if idaapi.get_byte(ea) == 0x55 or idaapi.get_byte(ea) == 0x68:
            return True
    return False

#class to hold information about an original instruction from an obfuscated binary
class ChainLink:
    def __init__(self, addr, flow, jump, stack_cmp, assembly, needs_reloc, data_ref):
        self.addr = addr
        self.new_addr = None
        self.flow = flow
        self.jump = jump
        self.nextLink = None
        self.prevLink = None
        self.skip = False
        self.new_data_ref = None
        self.stack_cmp = stack_cmp
        self.assembly = assembly
        self.needs_reloc = needs_reloc
        self.data_ref = data_ref
        self.new_data_ref = None
    
    def addNext(self, node):
        self.nextLink = node
        node.prevLink = self

#class to hold multiple sequential original instructions
class Chain:
    def __init__(self, link=None):
        self.startLink = link
        self.endLink = link
    def addLink(self, link):
        if self.startLink == None:
            self.startLink = link
            self.endLink = link
            return True
        self.endLink.addNext(link)
        self.endLink = link
        return True
    def appendChain(self, chain):
        curLink = chain.startLink
        if self.endLink.flow != curLink.addr:
            InfoMsg("Chains don't match on append")
            print(hex(self.endLink.addr), hex(curLink.addr))
            print (self.endLink.flow)
            return
        self.endLink.nextLink = chain.startLink
        chain.startLink.prevLink = self.endLink
        self.endLink = chain.endLink
    def print(self):
        link = self.startLink
        while link is not None:
            print (hex(link.addr), idc.GetDisasm(link.addr))
            link = link.nextLink

#main logic for following a flow of code and storing the relevant information about it
def parse_flow(cur_ea):
    #start the current flow chain
    chain = Chain()
    #grab the current global sets, lists and values
    global used_addrs
    global todo_addrs
    global chains
    global fix_addrs
    #these are parsed from jumps in control flow, typically branches
    #are jumps to code in the same function so try to group them together by
    #analysing them in this flow
    close_jumps = []
    #these are code references that are outside typical control flow
    #add them to the list of addresses still to analyse after the current flow has been finished
    jumps = []
    while True:
        insn = idaapi.insn_t()
        could_decode = idaapi.decode_insn(insn, cur_ea)
        if could_decode == 0:
            #failed to decode instruction, pass location of error to user and carry on
            InfoMsg("Failed to decode %08x, aborting this chain and continuing, ensure to check for errors in the final file" % cur_ea)
            return
        use_addresses(cur_ea, insn.size)
        #decoded the current instruction, now pull out all the information about control flow from items
        ###
        #capture the target of the next instruction executed in flow
        #absolute jumps, and int 3s do not have flow currently
        flow = None
        #if the instruction can branch control flow to a new place capture it in this variable
        #currently don't support jump tables, but equally haven't found any itw yet
        jump = None
        #if the instruction has a reference to memory or code that may be used indirectly then capture it here
        data_ref = None
        #if the instruction is a "cmp rsp, 0D744h" then the next instruction is a bl jump to an illegal position
        #flag this in the chain to prevent bad control flow being taken
        stack_cmp = False
        #list to hold temporary instruction bytes
        assembly = idaapi.get_bytes(insn.ea, insn.size)
        #flag for if this instruction will need a fixup applying
        needs_reloc = False
        #calls are straightforward, calculate the destination of the jump, and the destination of the flow
        if insn.itype == idaapi.NN_call:
            #assume all calls return - may not be a good assumption...
            flow = get_fudge_dest(insn.ea+insn.size)
            if insn.Op1.type == idaapi.o_near:
                jump = get_fudge_dest(insn.Op1.addr)
                jumps.append(get_fudge_dest(insn.Op1.addr))
                needs_reloc = True
            elif insn.Op1.type != idaapi.o_reg:
                InfoMsg("Unsupported call at %08x" % insn.ea)
                return
            else:
                #this is a "call eax" or similar
                pass
        #indirect calls come in two forms, both can be parsed in the same way
        elif (insn.itype == idaapi.NN_callni or insn.itype == idaapi.NN_callfi):
            flow = get_fudge_dest(insn.ea+insn.size)
            if insn.Op1.type == idaapi.o_mem:
                needs_reloc = True
                #the reference is to uninitialised data, ignore it
                if get_pointer(insn.Op1.addr) == 0:
                    needs_reloc = False
                elif is_func_start(get_fudge_dest(get_pointer(insn.Op1.addr))):
                    jump = get_fudge_dest(get_pointer(insn.Op1.addr))
                    jumps.append(get_fudge_dest(get_pointer(insn.Op1.addr)))
                    assembly = b"\xe8\x90\x90\x90\x90"
                else:
                    #this happens a lot when rebuilding unpatched ScatterBee samples
                    InfoMsg("Unsupported call at %08x" % insn.ea)
                    InfoMsg("%08x" % get_pointer(insn.Op1.addr))
                    needs_reloc = False
                    #return
            else:
                pass
        #jumps have no flow, try to keep the target near to this chain as jump targets are usually inside the same function
        elif insn.itype == idaapi.NN_jmp:
            jump = get_fudge_dest(insn.Op1.addr)
            close_jumps.append(get_fudge_dest(insn.Op1.addr))
            needs_reloc = True
            #if they have used a small jump instruction, replace with a large one to guarantee we can reach the relative target in the final output
            if insn.size == 2:
                assembly = b"\xe9\x90\x90\x90\x90"
        #same for indirect jumps, but handle the loading form memory to calculate the destination
        elif insn.itype == idaapi.NN_jmpfi or insn.itype == idaapi.NN_jmpni:
            if insn.Op1.type == idaapi.o_mem:
                if is_func_start(get_fudge_dest(get_pointer(insn.Op1.addr))):
                    jump = get_fudge_dest(get_pointer(insn.Op1.addr))
                    close_jumps.append(get_fudge_dest(get_pointer(insn.Op1.addr)))
                    assembly = b"\xe9\x90\x90\x90\x90"
                    needs_reloc = True
            else:
                pass
        #never come across this jump type so don't know how to handle it
        elif insn.itype == idaapi.NN_jmpshort:
            InfoMsg("Encountered jmpshort at %08x, needs implementing. ABORTING, output will be invalid" % insn.ea)
            return
        #now handle all remaining conditional jump operands: i.e. jb, jz, ja etc
        elif insn.itype >= idaapi.NN_ja and insn.itype <= idaapi.NN_jz:
            #will always have flow with a conditional jump
            flow = get_fudge_dest(insn.ea+insn.size)
            if insn.itype == idaapi.NN_jb and chain.endLink.stack_cmp:
                pass
            else:
                needs_reloc = True
                #add the target of the jump to close jumps for analysis
                close_jumps.append(get_fudge_dest(insn.Op1.addr))
                #store the target of the jump in this link
                jump = get_fudge_dest(insn.Op1.addr)
                #similar to jumps, make sure that all jumps are 4 byte offset versions so the final target is within bounds of the rebuilt binary
                if insn.size < 5:
                    if insn.itype == idaapi.NN_jge:
                        assembly = b"\x0f\x8d\x90\x90\x90\x90"
                    elif insn.itype == idaapi.NN_jz:
                        assembly = b"\x0f\x84\x90\x90\x90\x90"
                    elif insn.itype == idaapi.NN_jnz:
                        assembly = b"\x0f\x85\x90\x90\x90\x90"
                    elif insn.itype == idaapi.NN_jle:
                        assembly = b"\x0f\x8e\x90\x90\x90\x90"
                    elif insn.itype == idaapi.NN_jl:
                        assembly = b"\x0f\x8c\x90\x90\x90\x90"
                    else:
                        InfoMsg("small conditional jump at %08x needs fixing" % insn.ea)
        #handle skipping the obfuscated stack comparison
        elif insn.itype == idaapi.NN_cmp and insn.Op1.type == idaapi.o_reg and insn.Op1.reg == 4:
            stack_cmp = True
            flow = get_fudge_dest(insn.ea+insn.size)
        #don't have flow, jump or data_refs for returns or int3s
        elif insn.itype == idaapi.NN_retn or insn.itype == idaapi.NN_int3:
            pass
        else:
            #no other instructions can alter control flow directly
            #memory references may be used by indirect calls so check those
            #to see if they need adding to the far reference analysis list
            
            #all will have flow
            flow = get_fudge_dest(insn.ea+insn.size)
            if insn.size < 5 or insn.itype in none_offset_insns:
                pass
            elif insn.itype in offset_insns:
                #iterate through operands looking for references to code
                for op in insn.ops:
                    #void operands are unused, no more operands to process
                    if op.type == idaapi.o_void:
                        break
                    #this handles pushes, have check in just in case other instructions get clobbered so we can assess them
                    if op.type == idaapi.o_imm and in_code_section(op.value):
                        #check immediate values to code section here
                        #InfoMsg("In immediate ref to code at %08x" % insn.ea)
                        if is_fudge_call(op.value) and is_func_start(get_fudge_dest(op.value)):
                            jumps.append(get_fudge_dest(op.value))
                            needs_reloc = True
                    elif op.type == idaapi.o_imm and in_code_section(op.value) == False and idaapi.is_loaded(op.value):
                        #check immediate values to pointers in data section here
                        #InfoMsg("In imm ref to data at %08x" % insn.ea)
                        if is_fudge_call(get_pointer(op.value)) and is_func_start(get_fudge_dest(get_pointer(op.value))):
                            jumps.append(get_fudge_dest(get_pointer(op.value)))
                            needs_reloc = True
                    elif op.type == idaapi.o_mem and in_code_section(op.addr) == False and idaapi.is_loaded(op.addr):
                        #got ref to data section
                        #check if it is a pointer to code or not, if it is then we need to add a data_ref
                        if is_fudge_call(get_pointer(op.addr)) and is_func_start(get_fudge_dest(get_pointer(op.addr))):
                            jumps.append(get_fudge_dest(get_pointer(op.addr)))
                            data_ref = get_fudge_dest(get_pointer(op.addr))
                            InfoMsg("added data ref at %08x to %08x" % (insn.ea, data_ref))
                            needs_reloc = True
                        elif op.specval == 0x1e0000:#relative offset
                            needs_reloc = True
                    elif op.type == idaapi.o_mem and in_code_section(op.addr):
                        #got offset ref to code section, possibly a subroutine start location called indirectly
                        if is_fudge_call(op.addr) and is_func_start(get_fudge_dest(op.addr)):
                            jumps.append(get_fudge_dest(op.addr))
                            needs_reloc = True
                    else:
                        if op.type != idaapi.o_reg and op.type != idaapi.o_displ:
                            #this was used in testing for unsupported instructions, shouldn't reach this location anymore
                            #can add a debug message here if your output is not as expected.
                            pass
            else:
                InfoMsg("None handled data insn at %08x" % insn.ea)
        link = ChainLink(cur_ea, flow, jump, stack_cmp, assembly, needs_reloc, data_ref)
        chain.addLink(link)
        #check if we can carry on flowing...
        if flow is not None and flow not in used_addrs:
            cur_ea = flow
        #the flow has already been analysed, try to join it up and then terminate this chain
        elif flow is not None:
            count = 0
            found = False
            for tmp_chain in chains:
                if tmp_chain.startLink.addr == flow:
                    found = True
                    break
                count += 1
            if found:
                found_chain = chains.pop(count)
                chain.appendChain(found_chain)
            else:
                #this code was added during development of the script, it 'shouldn't' get hit
                #if you do end up seeing these output messages, there is a good chance the script needs to support more
                #instructions than it currently does, add a comment/issue to GitHub or message @malworms on twitter
                InfoMsg("flowed into analysed instruction at %08x, flow is %08x" % (insn.ea, flow))
                InfoMsg("could not find existing chain starting here")
                InfoMsg("adding fixer jump link in")
                assembly = b"\xe9\x90\x90\x90\x90"
                fix_link = ChainLink(fix_addrs, None, flow, stack_cmp, assembly, needs_reloc, data_ref)
                chain.endLink.flow = fix_addrs
                fix_addrs += 1
                chain.addLink(fix_link)
            flow = None
        #we have finished a chain, need to append it and check if we need to start a new one for close code
        #if we don't hit this then we have flow and just carry on analysing
        if flow is None:
            #run out of flow for this chain so save it off and start a new one
            chains.append(chain)
            cur_ea = None
            #process all the near jumps first to keep code close to the previous chains in the final output.
            #gives a better structure in the final output than just picking the next flow on the list
            while len(close_jumps) > 0:
                cur_ea = close_jumps.pop()
                if cur_ea in used_addrs:
                    #ensure we can check if we found a new flow start or not
                    cur_ea = None
                else:
                    #create a new chain for this flow
                    chain = Chain()
                    break
        if cur_ea is None:
            #there is no flow, and no near jumps left to process
            #break and add all the far jumps to the processing queue
            break
    #finished direct flows and near jumps for this starter location
    #add unanalysed jumps to the queue
    for jump in jumps:
        orig_jump = jump
        if is_fudge_call(jump):
            jump = get_fudge_dest(jump)
        if jump not in used_addrs:
            if jump == 0:
                InfoMsg("Got jump to 0, investigate?")
            elif in_code_section(jump) == False:
                InfoMsg("Jumped to illegal location %08x" % orig_jump)
            else:
                todo_addrs.add(jump)

InfoMsg("starting")

next_addr = get_next_addr()
while next_addr != idaapi.BADADDR:
    parse_flow(next_addr)
    next_addr = get_next_addr()

InfoMsg("Parsed instruction flow")
InfoMsg("Total chains = %d" % len(chains))

#have found all the code flow we are interested in so build it into one sequential chain

final_chain = []
final_bytes = []
cur_offset = 0
for chain in chains:
    link = chain.startLink
    while link is not None:
        final_chain.append(link)
        link = link.nextLink

InfoMsg("built chain")

#now populate the final binary with the placeholder bytes
for link in final_chain:
    if link.stack_cmp:
        link.nextLink.skip = True
    if link.skip:
        continue
    link.new_addr = cur_offset
    for i in link.assembly:
        final_bytes.append(i)
    cur_offset += len(link.assembly)

InfoMsg("added instructions")

#lea's are used to get location of pointer to data, these will need placeholder pointers adding for these refs
#identified by links with "data_ref"
for link in final_chain:
    found = False
    if link.data_ref is not None:
        for linkdest in final_chain:
            if linkdest.addr == link.data_ref:
                link.new_data_ref = cur_offset
                final_bytes.append((base_addr+linkdest.new_addr)&0xff)
                final_bytes.append(((base_addr+linkdest.new_addr)>>8)&0xff)
                final_bytes.append(((base_addr+linkdest.new_addr)>>16)&0xff)
                final_bytes.append(((base_addr+linkdest.new_addr)>>24)&0xff)
                if idaapi.get_inf_structure().is_64bit():
                    final_bytes.append(((base_addr+linkdest.new_addr)>>32)&0xff)
                    final_bytes.append(((base_addr+linkdest.new_addr)>>40)&0xff)
                    final_bytes.append(((base_addr+linkdest.new_addr)>>48)&0xff)
                    final_bytes.append(((base_addr+linkdest.new_addr)>>56)&0xff)
                    cur_offset += 4
                cur_offset += 4
                found = True
                break
        if found == False:
            InfoMsg("could not find data link for %08x" % link.data_ref)

InfoMsg("Added drefs")
#now need to apply relocations, in particular:
#jumps need offsets fixing
#indirect calls and jumps need converting to calls and jumps
#all other movs/pushes etc are going to be data pointers already existing or code locations that we need to calculate
counter = 0
InfoMsg("total links = %d" % len(final_chain))
for link in final_chain:
    #debugger outputs for progress, uncomment to check progress is being made
    #if (counter % 250) == 0:
    #    InfoMsg("processing chain %d" % counter)
    #counter += 1
    if link.skip:
        continue
    if link.needs_reloc:
        insn = idaapi.insn_t()
        insn_length = idaapi.decode_insn(insn, link.addr)
        if insn_length == 0:
            InfoMsg("failed to decode insn at %08x" % link.addr)
            break
        fixup = 0
        ins_offset = 0
        insn_size = 0
        if insn.itype == idaapi.NN_call:
            for dst_link in final_chain:
                if link.jump == dst_link.addr:
                    if dst_link.new_addr is None:
                        #we are jumping to obf error code, this will never be taken
                        InfoMsg("Got to bad call, target is not in final binary %08x, %08x" % (insn.ea, dst_link.addr))
                    else:
                        fixup = dst_link.new_addr - link.new_addr
                        ins_offset = 1
                        ins_size = 5
                    break
        elif insn.itype == idaapi.NN_jmp:
            fixup = 0
            for dst_link in final_chain:
                if link.jump == dst_link.addr:
                    fixup = dst_link.new_addr - link.new_addr
                    ins_offset = 1
                    ins_size = 5
                    break
            if fixup == 0:
                pass
        elif ((insn.itype == idaapi.NN_callfi or insn.itype == idaapi.NN_callni) and (insn.Op1.type == idaapi.o_mem)):
            #fix indirect calls here. 2 byte prologue
            if get_pointer(insn.Op1.addr) == 0:
                #need to do the relocation to the data section
                fixup = insn.Op1.addr - (link.new_addr+base_addr)
                ins_offset = insn.Op1.offb
                ins_size = insn.size
            else:
                fixup = 0
                for dst_link in final_chain:
                    if link.jump == dst_link.addr:
                        fixup = dst_link.new_addr - link.new_addr
                        ins_offset = 1
                        ins_size = 5
                        break
                if fixup == 0:
                    pass
        elif insn.itype == idaapi.NN_jmpfi or insn.itype == idaapi.NN_jmpni and insn.Op1.type == idaapi.o_mem:
            if idaapi.get_dword(insn.Op1.addr) == 0:
                pass
            else:
                fixup = 0
                for dst_link in final_chain:
                    if link.jump == dst_link.addr:
                        fixup = dst_link.new_addr - link.new_addr
                        ins_offset = 1
                        ins_size = 5
                        break
                if fixup == 0:
                    pass
        elif (insn.itype >= idaapi.NN_ja and insn.itype <= idaapi.NN_jz):
            #fix conditional jumps here. 2 byte prologue
            fixup = 0
            for dst_link in final_chain:
                if link.jump == dst_link.addr:
                    fixup = dst_link.new_addr - link.new_addr
                    ins_offset = 2
                    ins_size = 6
                    break
            if fixup == 0:
                pass
        #calculated all the jumps, now do data ones
        elif insn.itype in offset_insns:
            for op in insn.ops:
                #void operands are unused, no more operands to process
                if op.type == idaapi.o_void:
                    break
                #this handles pushes, have check in just in case other instructions get clobbered so we can assess them
                if op.type == idaapi.o_imm and in_code_section(op.value):
                    #check immediate values to code section here
                    if is_fudge_call(op.value) and is_func_start(get_fudge_dest(op.value)):
                        for dst_link in final_chain:
                            if dst_link.addr == get_fudge_dest(op.value):
                                fixup = dst_link.new_addr+base_addr
                                ins_size = 0
                                ins_offset = op.offb
                elif op.type == idaapi.o_imm and in_code_section(op.value) == False and idaapi.is_loaded(op.value):
                    #no need to fix, absolute values into the data section will be the same in the reconstructed binary
                    pass
                elif op.type == idaapi.o_mem and in_code_section(op.addr) == False and idaapi.is_loaded(op.addr):
                    #assumption is that these will all be 4 byte relative offsets
                    if is_fudge_call(get_pointer(op.addr)) and is_func_start(get_fudge_dest(get_pointer(op.addr))):
                        #need to put the pointer to be our new small data section
                        if link.data_ref is None:
                            InfoMsg("Error in data_ref at %08x" % link.addr)
                        else:
                            if op.specval == 0x200000:
                                #this is an absolute offset type
                                fixup = link.new_data_ref+base_addr
                                ins_offset = op.offb
                                ins_size = 0
                            elif op.specval == 0x1e0000:
                                #this is a relative offset type
                                InfoMsg("Got experimental offset at %08x, double check it is correct" % link.addr)
                                fixup = link.new_data_ref+base_addr - link.new_addr
                                ins_offset = op.offb
                                ins_size = 0
                    else:
                        #just a standard relocation into the data section
                        if op.specval == 0x200000:
                            #this is an absolute offset type
                            fixup = op.addr
                            ins_offset = op.offb
                            ins_size = insn.size
                        elif op.specval == 0x1e0000:
                            #this is a relative offset type
                            fixup = op.addr - (link.new_addr+base_addr)
                            ins_offset = op.offb
                            ins_size = insn.size
                elif op.type == idaapi.o_mem and in_code_section(op.addr):
                    if is_fudge_call(op.addr) and is_func_start(get_fudge_dest(op.addr)):
                        for dst_link in final_chain:
                            if dst_link.addr == get_fudge_dest(op.addr):
                                fixup = dst_link.new_addr - link.new_addr
                                ins_offset = op.offb
                                ins_size = insn.size
                else:
                    if op.type != idaapi.o_reg and op.type != idaapi.o_displ:
                        pass
        if fixup > 0xffffffff:
            InfoMsg("got unhandled fixup %08x" % fixup)
        if fixup != 0:
            fixup -= ins_size
            final_bytes[link.new_addr+ins_offset] = fixup & 0xff
            final_bytes[link.new_addr+ins_offset+1] = (fixup >> 8) & 0xff
            final_bytes[link.new_addr+ins_offset+2] = (fixup >> 16) & 0xff
            final_bytes[link.new_addr+ins_offset+3] = (fixup >> 24) & 0xff

InfoMsg("Finished relocs")

#write the final binary out to file in the ScatterLoader.py format
with open (idaapi.get_input_file_path()+".descattered", "wb") as f:
    f.write(b"SCATTER!")
    if idaapi.get_inf_structure().is_64bit():
        f.write(b"\x40")
        f.write(b"CODE")
        f.write(struct.pack("<Q", base_addr))
        f.write(struct.pack("<Q", len(final_bytes)))
    else:
        f.write(b" ")
        f.write(b"CODE")
        f.write(struct.pack("<I", base_addr))
        f.write(struct.pack("<I", len(final_bytes)))
    for i in final_bytes:
        f.write(bytes([i]))
    f.write(b"DATA")
    data_seg = idaapi.get_segm_by_name(".data")
    if idaapi.get_inf_structure().is_64bit():
        f.write(struct.pack("<Q", data_seg.start_ea))
        f.write(struct.pack("<Q", data_seg.size()))
    else:
        f.write(struct.pack("<I", data_seg.start_ea))
        f.write(struct.pack("<I", data_seg.size()))
    data_bytes = idaapi.get_bytes(data_seg.start_ea, data_seg.size())
    f.write(data_bytes)

InfoMsg("Fin")