"""
Description: Python 3 script to patch decoded ScatterBee payload files
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

import sys, struct

def FindSubStrs(a_str, sub):
    start = 0
    while True:
        start = a_str.find(sub, start)
        if start == -1: return
        yield start
        start += len(sub) # use start += 1 to find overlapping matches

def Is64BitConfig(config_data, cur_loc):
    offset = cur_loc
    valid_tags = [0x80, 0x83, 0x84, 0xa0, 0x2, 0xa0, 0x90, 0x91, 0x92]
    start = struct.unpack("<I", config_data[offset:offset+4])[0]
    tag = start >> 24
    first_length = start & 0xffffff
    if tag != 0x80 or first_length > (len(config_data)-cur_loc-4) or first_length == 0:
        return False
    offset += 4
    offset += first_length
    second_start = struct.unpack("<I", config_data[offset:offset+4])[0]
    second_tag = second_start >> 24
    if second_tag not in valid_tags:
        return False
    second_length = second_start & 0xffffff
    if second_length > (len(config_data)-first_length-8) or second_length == 0:
        return False
    #we have now verified two consecutive tags, could do a third to really check as we have always seen at least 3 or check that it goes to the end of the file?
    return True

def Get64BitConfig(payload_data):
    #looking for a 64 bit payload config chunks. They occur 0x30 after the start of the 6 XOR DWORDs
    #high byte of first config should be 80, subsequent should be 02, a0, 90, 91 or 92
    possible_configs = list(FindSubStrs(payload_data, b"\x80"))
    for eighty_loc in possible_configs:
        if Is64BitConfig(payload_data, eighty_loc-3):
            return eighty_loc
    return -1

if len(sys.argv) < 2 or len(sys.argv) > 2:
    print ("Error - usage: python ScatterPatch.py filename")

with open (sys.argv[1], "rb") as f:
    contents = f.read()

if b"\x08"*16 in contents:
    #we have a 32 bit sample
    config_start = contents.find(b"\x08"*16, 0) - 0x7a
    print (hex(config_start))
    config_data = contents[config_start:]
    code_size = struct.unpack("<I", config_data[0x18:0x1c])[0]
    data_size = struct.unpack("<I", config_data[0x1c:0x20])[0]
    patch_size = struct.unpack("<I", config_data[0x20:0x24])[0]
    if code_size+data_size+patch_size != config_start:
        print("Error with config sizes")
        print (hex(code_size))
        print (hex(data_size))
        print (hex(patch_size))
        sys.exit(1)
    for i in range(code_size+data_size, code_size+data_size+patch_size, 8):
        location = struct.unpack("<I", contents[i:i+4])[0]
        patch = struct.unpack("<I", contents[i+4:i+8])[0]
        contents = contents[:location] + struct.pack("<I", patch) + contents[location+4:]
    with open (sys.argv[1]+".patched", "wb") as g:
        g.write(contents)
else:
    config_start = Get64BitConfig(contents) - 0x33
    if config_start == -1:
        print ("could not find 64 bit config location...")
        sys.exit(1)
    print ("using offset %08x as config" % config_start)
    config_data = contents[config_start:]
    code_size = struct.unpack("<I", config_data[0x18:0x1c])[0]
    data_size = struct.unpack("<I", config_data[0x1c:0x20])[0]
    patch_size = struct.unpack("<I", config_data[0x20:0x24])[0]
    if code_size+data_size+patch_size != config_start:
        print("Error with config sizes")
        print (hex(code_size))
        print (hex(data_size))
        print (hex(patch_size))
        sys.exit(1)
    for i in range(code_size+data_size, code_size+data_size+patch_size, 8):
        location = struct.unpack("<I", contents[i:i+4])[0]
        patch = struct.unpack("<I", contents[i+4:i+8])[0]
        contents = contents[:location] + struct.pack("<Q", patch) + contents[location+8:]
    with open (sys.argv[1]+".patched", "wb") as g:
        g.write(contents)