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

Insert popup here...

Select yes and IDA will then start loading the DLL. Once the auto-analysis has completed you should be able to explore the binary and locate a `jump` into code that contains a 9-byte long jump instruction. This jump will have been created by the `ScatterJump` plugin.  
The output in IDA at this stage will still not be very helpful in IDA due to the stack comparisons and jumps.  
At this stage use the ScatterRebuildPayload.py script to obtain a deobfuscated copy of the ScatterBee loaders code.  
Place the cursor in IDA on the first jump into the obfuscated code and run the ScatterRebuildPayload script via the `Alt+F7` shortcut or IDA's run script command.  

The output of this script will be a new binary in the same location as the old one with the suffix `.descattered`. This file is in the custom binary format recognised by `ScatterLoader` and so can be opened in IDA. Make sure to select the `SCATTERBEE` processor when prompted.

Insert image here...

At this point you may be tempted to dive into analysing the code in IDA, but there are a couple of steps that will save you a lot of effort...  
First, go to the type libraries window in IDA (`Shift+F11`), and add in the relevant windows libraries. Usually these would be the `nt_api...` - Windows Native API - libraries for the platform that the binary is expected to run on.  
Next, you will want to locate the function that is used to lookup API calls at run time. Use the `Alt+B` (Search Binary) shortcut to search for the following pattern: `E8 ?? ?? ?? ?? FF E0` - `call loc_xyz; jmp eax/rax`.  
This function is sometimes incorrectly defined, if there is code flowing into it, like below.  

insert image here...

Undefine the code flowing into it with `u`, make a function in IDA at the `call` using `p` and then redefine and make a function at the code that flowed into it with `p`. After these steps you should have something that looks like below.

insert image...

Next you will want to find out what obfuscation constant has been applied to the API strings, navigate into the `call` function and there should be a function inside here that carries out an `XOR` operation along with `shl` instructions in a loop.

insert image

The value in the lea instruction highlighted above is the subtraction value that is the key to the API call obfuscation. Copy/remmember this value and then go back to the `call loc_xyz; jmp eax/rax` function, place the cursor on the first instruction and then run the IDA Python script ScatterDecodeAPICalls.py.  
This script will ask the 

#### scripts/ScatterRebuildPayload.py
##### **IMPORTANT**: This script requires that the segments in IDA are created and set to the correct sizes.
##### For DLL loaders - no action is required, the default memory setup in IDA should work correctly.
##### For payload files - locate the end of the code section and the start of the data section in IDA and create a new segment from there up until the end of the file. This boundary should be easy to spot when ScatterJump is installed.
Insert image of boundary here
#####   Make sure the code up until this boundary is in a segment with the `CODE` attribute set in IDA. Make sure that the code after the boundary is in a segment with the name `.data`.
Insert image of segments here
