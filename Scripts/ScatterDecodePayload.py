"""
Description: Python script to decode ScatterBee payload files. It will also attempt to parse the configuration and optionally dump the embedded payloads to disk
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

import sys, struct, hashlib
from Crypto.Cipher import AES

current_key = None
known_sub_keys = [0x53335D9F, 0xEF819993, 0xe8589ff, 0xdc7f607, 0x443246ba, 0x56AB233F]
known_keystrings = [b"\x82\xe4\xe2\xfe\xf1\x55\xd0\x9e\x01\xb7\x98\xff\x31\x8c\x0a\xf8",
        b"\x39\x88\xa1\x8d\xba\xe0\xd9\xf1\xb1\x5f\xaf\xc7\x62\x1e\x0d\x80",
        b"\xf0\xc2\xc5\xc7\xd0\xd9\x5f\xd7\x58\xae\xab\xcb\x6b\x40\xc2\xcb",
        b"\x65\x66\x0d\xaf\x65\x15\xd3\xb7\x55\x7c\x73\x64\x65\x59\x95\xf4"]

def AddBytes(value):
    return ((value & 0xff) + ((value >> 8) & 0xff) + ((value >> 16) & 0xff) + ((value >> 24) & 0xff)) & 0xff

#adapted from: https://www.fireeye.com/content/dam/fireeye-www/global/en/blog/threat-research/flareon2016/challenge2-solution.pdf
def DeriveKey(key_md5):
    # MD5 hash algorithm used
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

def DecodeScatterStream(bytearr, seed, subkey):
    decoded_payload = b""
    for i in bytearr:
        seed = (((17 * seed) & 0xffffffff) - subkey) & 0xffffffff
        decoded_payload += bytes([i ^ (AddBytes(seed))])
    return decoded_payload

def DecryptAES(byte_arr, keystring):
    seed = byte_arr[-4:]
    key = DeriveKey(hashlib.md5(keystring+seed).digest())[:16]
    decryptor = AES.new(key, AES.MODE_CBC, iv=b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00")
    return decryptor.decrypt(byte_arr[:-4])

def FindSubStrs(a_str, sub):
    start = 0
    while True:
        start = a_str.find(sub, start)
        if start == -1: return
        yield start
        start += len(sub) # use start += 1 to find overlapping matches

def DecodeScatterStreamConfigEntry(config, offset, key):
    seed = struct.unpack("<H", config[0xbe+offset:0xbe+offset+2])[0]
    length = struct.unpack("<H", config[0xbe+offset+2:0xbe+offset+4])[0]
    obf_bytes = config[0xbe+offset+4:0xbe+offset+4+length]
    return DecodeScatterStream(obf_bytes, seed, key)

def Is32BitConfig(config_data, offset):
    code_size = struct.unpack("<I", config_data[offset+0x18:offset+0x1c])[0]
    data_size = struct.unpack("<I", config_data[offset+0x1c:offset+0x20])[0]
    patch_size = struct.unpack("<I", config_data[offset+0x20:offset+0x24])[0]
    
    if code_size+data_size+patch_size != offset:
        return False
    return True

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

def Extract32BitConfig(config_data, filename, dumpflag):
    if dumpflag:
        config_filename = filename + ".rawconfig.bin"
        print ("Dumping raw config data to %s" % config_filename)
        with open (config_filename, "wb") as g:
            g.write(config_data)
    code_size = struct.unpack("<I", config_data[0x18:0x1c])[0]
    data_size = struct.unpack("<I", config_data[0x1c:0x20])[0]
    patch_size = struct.unpack("<I", config_data[0x20:0x24])[0]
    operating_mode = struct.unpack("<I", config_data[0x28:0x2c])[0]
    offsets = []
    for i in range(19):
        offsets.append(struct.unpack("<H", config_data[0x34+(i*2):0x36+(i*2)])[0])
    for i in range(4):
        offsets.append(struct.unpack("<H", config_data[0x72+(i*2):0x74+(i*2)])[0])
    
    output_strs = []
    output_strs.append(b"code size: %08x\r\n" % code_size)
    output_strs.append(b"data size: %08x\r\n" % data_size)
    output_strs.append(b"patch size: %08x\r\n" % patch_size)
    output_strs.append(b"operating mode: %d\r\n" % operating_mode)
    global current_key
    for i in offsets:
        output_strs.append(DecodeScatterStreamConfigEntry(config_data, i, current_key))
    for i in output_strs:
        print (i)

def DecryptAESConfigString(obf_bytes, keystring):
    length = struct.unpack("<H", obf_bytes[:2])[0] ^ ((struct.unpack("<H", obf_bytes[2:4])[0]-0x92f)&0xffff)
    data = obf_bytes[4:4+length]
    seed1 = obf_bytes[2]
    seed2 = obf_bytes[3]
    key = DeriveKey(hashlib.md5(keystring+bytes([seed1])+bytes([seed2])).digest())[:16]
    decryptor = AES.new(key, AES.MODE_CBC, iv=b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00")
    decoded_str = decryptor.decrypt(data)
    if decoded_str[-1] == decoded_str[-2] and decoded_str[-1] < 17:
        decoded_str = decoded_str[:-decoded_str[-1]]
    elif decoded_str[-1] == 1:
        decoded_str = decoded_str[:-1]
    print (decoded_str)

def Extract64BitConfig(config_data, filename, dumpflag):
    global current_key, known_keystrings, known_sub_keys
    mode = 0
    #get meta of blob
    start_data = struct.unpack("<I", config_data[:4])[0]
    length = start_data & 0xffffff
    tag = start_data >> 24
    #move the config data past the chunk header
    config_data = config_data[4:]
    #first try AES decode only if the payload is 16 byte aligned
    for keystring in known_keystrings:
        try:
            decoded = DecryptAES(config_data[:length], keystring)
            if (b"\x08"*6)+(b"\x04"*7)+(b"\x02\x02\x02") in decoded:
                print ("Found AES encoded configuration...")
                current_key = keystring
                mode = 1
                #do the printing of config strings here
                for i in range(23):
                    offset = struct.unpack("<H", decoded[4+(2*i):6+(2*i)])[0]
                    try:
                        DecryptAESConfigString(decoded[0x331+offset:], current_key)
                    except:
                        print("could not decode index %d" % i)
                for i in range(4):
                    offset = struct.unpack("<H", decoded[0x50+(2*i):0x52+(2*i)])[0]
                    try:
                        DecryptAESConfigString(decoded[0x331+offset:], current_key)
                    except:
                        print("could not decode index %d" % (i+23))
                break
        except:
            decoded = b"BadDecode"
    #check if the AES key worked...
    if mode == 0:
        #try again with the existing subkey stream cipher logic
        decoded = DecodeScatterStream(config_data[4:length], struct.unpack("<I", config_data[:4])[0], current_key)
        if (b"\x08"*6)+(b"\x04"*7)+(b"\x02\x02\x02") in decoded:
            print ("Found stream cipher encoded configuration...")
            mode = 2
            #do the printing of config strings here
            for i in range(19):
                offset = struct.unpack("<H", decoded[(2*i):2+(2*i)])[0]
                length_string = struct.unpack("<H", decoded[0x366+offset+2:0x366+offset+4])[0]
                print (DecodeScatterStream(decoded[0x366+offset+4:0x366+offset+4+length_string], struct.unpack("<H", decoded[0x366+offset:0x366+offset+2])[0], current_key))
            for i in range(4):
                offset = struct.unpack("<H", decoded[0x4c+(2*i):0x4c+2+(2*i)])[0]
                length_string = struct.unpack("<H", decoded[0x366+offset+2:0x366+offset+4])[0]
                print (DecodeScatterStream(decoded[0x366+offset+4:0x366+offset+4+length_string], struct.unpack("<H", decoded[0x366+offset:0x366+offset+2])[0], current_key))
            for i in range(4):
                offset = struct.unpack("<H", decoded[0x3e+(2*i):0x3e+2+(2*i)])[0]
                length_string = struct.unpack("<H", decoded[0x366+offset+2:0x366+offset+4])[0]
                print (DecodeScatterStream(decoded[0x366+offset+4:0x366+offset+4+length_string], struct.unpack("<H", decoded[0x366+offset:0x366+offset+2])[0], current_key))
    if mode == 0:
        print("could not determine encoding scheme for config, exiting")
        return
    #get past the config chunk
    config_data = config_data[length:]
    if dumpflag:
        #dump the raw config
        with open (filename+"_80_raw_config.bin", "wb") as f:
            f.write(decoded)
        count = 0
        while True:
            #decode and dump all the raw payloads to new files here
            if len(config_data) < 8:
                break
            start_data = struct.unpack("<I", config_data[:4])[0]
            #move past the chunk header
            config_data = config_data[4:]
            length = start_data & 0xffffff
            if length == 0:
                break
            tag = start_data >> 24
            if mode == 1:
                try:
                    decoded = DecryptAES(config_data[:length], current_key)
                except:
                    decoded = b"BadDecode"
                    pass
            else:
                decoded = DecodeScatterStream(config_data[4:length], struct.unpack("<I", config_data[:4])[0], current_key)
            with open (filename+"_chunk_%d_%02x.bin" % (count, tag), "wb") as f:
                f.write(decoded)
            count += 1
            config_data = config_data[length:]

def Process32BitConfig(payload_data, filename, dumpflag):
    #this is a 32-bit payload so the start of the config will be at offset -0x7a from there.
    #Can also verify the structure if there are multiple 08 strings
    if b"\x08"*16 not in payload_data:
        return False
    possible_configs = list(FindSubStrs(payload_data, b"\x08"*16))
    for eight_loc in possible_configs:
        if Is32BitConfig(payload_data, eight_loc-0x7a):
            Extract32BitConfig(payload_data[eight_loc-0x7a:], filename, dumpflag)
            return True
    return False

def Process64BitConfig(payload_data, filename, dumpflag):
    #looking for a 64 bit payload config chunks. They occur 0x30 after the start of the 6 XOR DWORDs
    #high byte of first config should be 80, subsequent should be 02, a0, 90, 91 or 92
    possible_configs = list(FindSubStrs(payload_data, b"\x80"))
    for eighty_loc in possible_configs:
        if Is64BitConfig(payload_data, eighty_loc-3):
            Extract64BitConfig(payload_data[eighty_loc-3:], filename, dumpflag)
            return True
    return False

def GetStreamCipherDecodeKey(seed, firstbytes):
    global current_key, known_sub_keys
    for key in known_sub_keys:
        decoded_str = DecodeScatterStream(firstbytes, seed, key)
        if decoded_str[0] == 0xe9 and decoded_str[4] == 0:
            current_key = key
            return key
    return None

def GetAESDecodeKey(firstbytes):
    global known_keystrings, current_key
    for key in known_keystrings:
        try:
            decoded = DecryptAES(firstbytes, key)
            if decoded[0] == 0xe9 and decoded[4] == 0:
                current_key = key
                return key
        except:
            pass
    return None

def DecodeScatterBee(filename, dumpflag):
    #read the input data
    with open (filename, "rb") as f:
        data = f.read()
    #grab the first 4 bytes as the seed to use
    seed = struct.unpack("<I", data[:4])[0]
    #check whether we can decode the first few bytes to a valid jump instruction with existing keys
    subkey = GetStreamCipherDecodeKey(seed, data[4:9])
    if not subkey:
        subkey = GetAESDecodeKey(data[:16]+data[-4:])
        if not subkey:
            print ("Failed to find a valid key and decoding algorithm for this sample")
            return
        print ("Found valid AES key, attempting to decode payload with: ", subkey)
        try:
            decoded_payload = DecryptAES(data, subkey)
        except:
            print ("Error in AES decode payload")
            return
    else:
        #decode the whole payload
        print ("Found valid key %08x, attempting to decode payload" % subkey)
        decoded_payload = DecodeScatterStream(data[4:], seed, subkey)
    #dump the decoded file out if the user wants it stored
    if dumpflag:
        finalfile = filename+".decoded.bin"
        print ("Dumping payload to file: %s" % (finalfile))
        with open (finalfile, "wb") as g:
            g.write(decoded_payload)
    #try to get 32 bit config by default
    #if the file isn't a 32 bit sample this should return very quickly with False
    if Process32BitConfig(decoded_payload, filename, dumpflag) == False:
        if Process64BitConfig(decoded_payload, filename, dumpflag) == False:
            print ("Could not decode the config from the payload, may need more research to support this variant")

if len(sys.argv) < 2 or len(sys.argv) > 3:
    print ("usage: python ScatterBeeDecode.py filename [Optional flag] -d\n\n-d will dump the extracted payload to disk rather than just printing the configuration data to output")
    sys.exit()

filename = sys.argv[1]
print (filename)

dump = False
if len(sys.argv) == 3:
    if sys.argv[2] == "-d":
        dump = True
    else:
        print ("read invalid flag: %s, expecting -d" % sys.argv[2])
        sys.exit()

DecodeScatterBee(filename, dump)