# ScatterBee_Analysis
Scripts to aid analysis of files obfuscated with ScatterBee.

### This repository of scripts is meant to be consumed in conjunction with the public PwC report on ScatterBee at: 
When analysing a ScatterBee encoded file you will likely come across two types of file that are tricky to analyse - a loader, and a malicious payload.  
Loaders are typically DLLs that somewhere contain a single jump into ScatterBee obfuscated code that will eventually load, decode and run a malicious payload.  
The malicious payloads at rest on disk are stored in an obfuscated/encrypted format. The loader decodes them and jumps to the first byte of the decoded data, this first byte acts as the payloads entry point.  
The decoded payload is also obfuscated with ScatterBee.
When loading ScatterBee obfuscated files into IDA Pro you can eliminate the calls to obfuscated jump functions by using ScatterJump.py.  

#### scripts/ScatterJump.py
This script is designed to be placed in your IDA Pro installations `/plugin` directory. It has been tested as working with IDA 7.6.  
This script is an IDA Python processor module extension for x86 and x64 processors in IDA pro.  
It contains checks so that it will not load unless it detects a possible ScatterBee obfuscated jump function. This is so that a user does not have to interact with the plugin *every time* a file is loaded into IDA.  
It is known that Go binaries may cause this plugin to pass its checks, just decline the plugin to be loaded in the popup dialogue in cases when you do not suspect ScatterBee encoding is present.  

#### scripts/ScatterLoader.py
This script is designed to be placed in your IDA Pro installations `/loaders` directory. It has been tested as working with IDA 7.6.  
This script is an IDA Python loader module for a simple custom binary format. The custom binary format and the loader have been created to reduce complexity in the workflow of analysing ScatterBee samples. The loader can be chosen in IDA's load file screen when loading files that have been created by ScatterRebuildPayload.py.  

## Reversing a malicious ScatterBee DLL
With the loader and processor module installed it is possible to begin analysing ScatterBee DLLs.  
Loading a ScatterBee DLL into IDA with the processor module installed should result in the following dialogue being displayed:  

![alt text](/Images/load_plugin.PNG?raw=true)

Select yes and IDA will then start loading the DLL. Once the auto-analysis has completed you should be able to explore the binary and locate a `jmp` into code that contains a 9-byte long jump instruction. This jump will have been created by the `ScatterJump` plugin.  

![alt text](/Images/entrypoint_code.PNG?raw=true)

The overwriting of the parent executables entrypoint above in this example leads to the following jump location.  

![alt text](/Images/first_jump.PNG?raw=true)

The output in IDA at this stage will still not be very helpful in IDA due to the stack comparisons and jumps.  
At this stage use the ScatterRebuildPayload.py script to obtain a deobfuscated copy of the ScatterBee loaders code.  
Place the cursor in IDA on the first jump into the obfuscated code and run the ScatterRebuildPayload script via the `Alt+F7` shortcut or IDA's run script command.  

The output of this script will be a new binary in the same location as the old one with the suffix `.descattered`. This file is in the custom binary format recognised by `ScatterLoader` and so can be opened in IDA. Make sure to select the `SCATTERBEE` processor when prompted.

![alt text](/Images/loader.PNG?raw=true)

At this point you may be tempted to dive into analysing the code in IDA, but there are a couple of steps that will save you a lot of effort...  
First, go to the type libraries window in IDA (`Shift+F11`), and add in the relevant windows libraries. Usually these would be the `nt_api...` - Windows Native API - and `mssdk` - MS SDK - libraries for the platform that the binary is expected to run on.  
Next, you will want to locate the function that is used to lookup API calls at run time. Use the `Alt+B` (Search Binary) shortcut to search for the following pattern: `E8 ?? ?? ?? ?? FF E0` - `call loc_xyz; jmp eax/rax`.  
This function is sometimes incorrectly defined, if there is code flowing into it, like below.  

![alt text](/Images/api_call_bad.PNG?raw=true)

Undefine the code flowing into it with `u`, make a function in IDA at the `call` using `p` and then redefine and make a function at the code that flowed into it with `p`. After these steps you should have something that looks like below.

![alt text](/Images/api_call_good.PNG?raw=true)

Next you will want to find out what obfuscation constant has been applied to the API strings, navigate into the `call` function and there should be a function inside here that carries out an `XOR` operation along with `shl` instructions in a loop.

![alt text](/Images/xor_value.PNG?raw=true)

The value in the lea instruction highlighted above is the subtraction value that is the key to the API call obfuscation. Copy/remember this value and then go back to the `call loc_xyz; jmp eax/rax` function, place the cursor on the first instruction and then run the IDA Python script ScatterDecodeAPICalls.py.  
This script will ask the user for the subtraction value, once inputted the script will rename all the functions that call this lookup function to be the relevant API calls, this should automatically apply the correct type information to a lot of the binary.

![alt text](/Images/decodeAPIs.PNG?raw=true)

You should now be able to go statically analyse the rest of the ScatterBee loader in IDA Pro.  
The only last thing to look out for is if you get errors in the decompiler like the following:

![alt text](/Images/bad_sp.PNG?raw=true)

These are caused by IDA failing to recognise how the stack is handled during the calls to the API lookup functions, you can see how IDA changes the value of the stack incorrectly at one of these calls in this screenshot by the green stack size markers:

![alt text](/Images/API_stack_mod.PNG?raw=true)

To fix this, go to the line with the API call, press `Alt+K`, and set the value to be `0xc`. This will tell IDA that the stack has 3 arguments cleaned up as `GetModuleNameW` takes 3 arguments and is a `__stdcall` function and will allow IDA to recalculate the local stacks usage for the current function. Alternatively, explicitly setting the function prototype to the correct definition should also cleanup these cases.  

## Reversing a malicious ScatterBee payload
ScatterBee payloads can either be encoded using a stream cipher, or AES with a key generated from MD5 hashing. Once you have identified a malicious file you can try to decode it using `ScatterDecodePayload.py`.  

```
python ScatterDecodePayload.py filename -d
```
This script will look to extract the ShadowPad configuration data from the payload and print it to the console, if the optional `-d` flag is specified, it will also extract and decode the embedded files to disk ready for analysis.  

![alt text](/Images/payload_config.PNG?raw=true)

If you wish to analyse the payload file statically beyond just extracting the configuration data then carry on reading...  
Load the resulting `payload_name.decoded.bin` file generated by the `ScatterDecodePayload` script with the `-d` option into IDA. This file is the raw ScatterBee encoded data that will be decoded, loaded into memory and then executed from the start of the payload by a loader DLL.  
Make sure that you enable the `ScatterJump` plugin to allow IDA to follow the obfuscated jumps in the sample. There is no need to rebase the file or load any type libraries when first opening it in IDA, just ensure that it is in x86 mode for payloads loaded by a 32-bit DLL and x64 mode for payloads loaded by a 64-bit DLL.  
Once the file has loaded and the initial auto-analysis has completed, locate the end of the code section by scanning the preview bar at the top of IDA and jumping to the end of the blue section.

![alt text](/Images/segment_boundary.PNG?raw=true)

Copy the value of this memory location, in this case `0xE0000`, and open the IDA segments window. `Shift+F7`  
Add a new segment with the start address as the copied location, the name as `.data` and the end address as the default value.  
Next edit the first segment to ensure it is a CODE type and has RWX permissions. It should look something like the following:  

![alt text](/Images/payload_segments.PNG?raw=true)

With the segments setup correctly you can then run the `ScatterRebuildPayload.py` script from the first instruction in the binary. This may take a few minutes depending on the size of the payload.  
The output of the script may have lots of lines saying - `[INFO]: Unsupported call at 00059a5d` - this is due to the payload not having been patched yet by its first few functions.  
Opening the result in IDA will allow you to follow the code for a handfull of calls before reaching instructions like the following:  

![alt text](/Images/bad_call.PNG?raw=true)

This is due to the first couple of functions being responsible for patching the binary at runtime, as described in the associated ScatterBee blog.  
To get past this issue, you need to patch the decoded payload, this can be done with `ScatterPatch.py`. Pass the decoded payload (not the rebuilt payload) to the script with the following python command:  

```
python ScatterPatch.py filename.decoded.bin
```

The resulting file - `filename.decoded.bin.patched` - will then have all the patches applied to it and can be opened in IDA with the `ScatterJump` plugin enabled.  
Go through the same process of setting up the segments with the correct names and permissions.  

Now the challenge is finding the correct entry point to use with the `ScatterRebuildPayload` script. In some samples you can re-run the script from the same location as before (the first byte), in others the patching mechanism will overwrite the entry point so there is no longer any valid code.  
Typically you can use the next large 9-byte jump you find at the start of the binary as it usually points to the code just after the patching has finished.  

To guarantee that you are at the code just after the code that carried out the patching though you can make use of the `cmp esp, #value` obfuscated instructions that we left in the rebuilt payload.  
Each of the `#values` in the stack comparisons occurs exactly once in the payload file. So you can locate the first stack comparison instruction in the unpatched and rebuilt binary that occurs after the patching function has returned, and then search for that same stack comparison value in the patched file and you know you will be following code from just after the patching and before the malicious payloads functionality.  

![alt text](/Images/stack_cmp.PNG?raw=true)

Stack comparison after the patching function in the rebuilt binary is shown above.  

![alt text](/Images/stack_cmp_patched.PNG?raw=true)

And then the same stack comparison in the patched binary.  

Make sure to follow the code xrefs in IDA in the patched binary back to the entry point of the function - `push ebp` - before running the rebuild script so that the final rebuilt payload's first function is accurate.  

The final rebuilt payload will now be dropped out at `filename.decoded.bin.patched.descattered`, and can be loaded into IDA in the same way as previously described for the loader DLL section. Make sure to add the relevant type libraries, and then fixup the API calls before trying to carry out analysis.  
You may also need to ensure that the `wsprintfA` call has a type declaration with var args as otherwise it breaks a lot of IDA's stack analysis. (Just hit `y` on the function name and set the type to be `int wsprintfA(_DWORD, _DWORD, ...)`, or if you can be bothered, look up the actual function prototype in MSDN)  
With all that - there is just one final gotcha to look at in these samples... Stack strings!  
These final payloads obfuscate the strings in the binary and decode them at runtime. All of the strings are stored either encoded on the stack, or in the data section. For the stack strings they will look a little like this when the decoding function uses `__stdcall`:  

![alt text](/Images/stack_string.PNG?raw=true)

There is also a decoder that uses `__fastcall` which will have a couple of the values put into registers ecx/rcx, edx/rdx etc...  
To decode these strings and add a comment with the decoded string at the location of where the string is decoded: navigate into the decoding subroutine and work out if the algorithm uses a subtraction constant, like below, or an AES algorithm.  

![alt text](/Images/stack_str_decode.PNG?raw=true)

Then go to the first instruction of the decode algorithm and run the IDA Python script `ScatterStackDecode.py`. This script will prompt the user for input as to whether the decoder uses `__fastcall` or not, and whether the algorithm is an AES variant or not. If the decode algorithm uses a substraction constant then the user will be asked for the value:  

![alt text](/Images/stack_string_sub_value.PNG?raw=true)

Otherwise the script will try to use known AES keys to decode the strings. If you come across a sample using AES keys that are not in the known set you may have to extend the script to support them.  
From here on you can analyse the binary statically just like most other malware samples.
