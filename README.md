# ScatterBee_Analysis
Scripts to aid analysis of files obfuscated with ScatterBee.

### This repository of scripts is meant to be consumed in conjunction with the public PwC report on ScatterBee at: 

When analysing a ScatterBee encoded file you will likely come across two types of file - a loader, and a malicious payload.

Loaders are typically DLLs that somewhere contain a single jump into ScatterBee obfuscated code that will eventually load, decode and run a malicious payload.

The malicious payloads at rest on disk are stored in an obfuscated/encrypted format. The loader decodes them and jumps to the first byte of the decoded data, this first byte acts as the payloads entry point.
The decoded payload is also obfuscated with ScatterBee.

When loading ScatterBee obfuscated files into IDA Pro you can eliminate the calls to obfuscated jump functions by using ScatterJump.py.

#### scripts/ScatterJump.py
This script is designed to be placed in your IDA Pro installations `/plugin` directory. It has been tested as working with IDA 7.6.
This script is an IDA Python processor module extension for x86 and x64 processors in IDA pro.
It contains checks so that it will not load unless it detects a possible ScatterBee obfuscated jump function. This is so that a user does not have to interact with the plugin **every time** a file is loaded into IDA.
It is known that Go binaries may cause this plugin to pass its checks, just decline the plugin to be loaded in the popup dialogue in cases when you do not suspect ScatterBee encoding is present.

Insert images of before and after scatterjump here...

Once the obfuscated jumps have been removed from a binary in IDA via the ScatterJump script it is possible to extract the original unobfuscated instructions from the ScatterBee code with ScatterRebuildPayload.py

#### scripts/ScatterRebuildPayload.py
##### **IMPORTANT**: This script requires that the segments in IDA are created and set to the correct sizes.
##### For DLL loaders - no action is required, the default memory setup in IDA should work correctly.
##### For payload files - locate the end of the code section and the start of the data section in IDA and create a new segment from there up until the end of the file. This boundary should be easy to spot when ScatterJump is installed.
Insert image of boundary here
#####   Make sure the code up until this boundary is in a segment with the `CODE` attribute set in IDA. Make sure that the code after the boundary is in a segment with the name `.data`.
Insert image of segments here
