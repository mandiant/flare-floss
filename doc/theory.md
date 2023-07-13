# FLARE Obfuscated String Solver

## Theory
Malware authors pack their software to resist reverse engineering and
 enable their operations to survive longer.
However, many features of packing are easy to automatically identify
 during static or dynamic analysis.
Therefore, some authors obfuscate only the most sensitive resources used by
 malware in an attempt to blend in.
We call this "string obfuscation".
String obfuscation maintains some difficulty around extracting host or network based
 signatures (such as filenames, registry keys, or domain names), while
 structuring the executable file like legitimate programs.
This is a technique that balances moderate anti-reverse
 engineering tricks with a moderate level of stealth.

As a reverse engineer, it takes significant effort to extract obfuscated
 strings from a malware sample.
This is because there are a huge number of possible encoding functions,
 configurations, and control flows.
For example, some malware uses a single-byte XOR operation with a static
 key for all obfuscated strings, while other malware uses RC4 encryption
 with a unique key per string.
Its often difficult to figure out how encoded data is protected without
 opening IDA Pro or reviewing a debugger trace.

Manual extraction of obfuscated strings commonly involves thoroughly
 studying a decryption routine and reimplementing it in a scripting language.
This is a tedious and error-prone process that is fun at first, and
 mind-numbing after a few iterations.
Alternatively, an analyst may instrument a debugger to hop around
 hundreds of locations in hopes of forcing the malware to decode itself.
This is also complex, tedious, and error-prone.

FLOSS combines and automates the best manual reverse engineering
 techniques for string decoding.
First, it uses heuristics to identify decoding routines in a sample.
Then FLOSS extracts cross references and arguments to decoders
 using control flow analysis.
Next FLOSS emulates decoder functions using extracted arguments.
Finally, FLOSS diffs the emulator memory states from before and
  after decoder emulation and extracts human readable strings.


### Algorithm

  1. Analyze control flow of malware to identify functions, basic blocks, etc.
  2. Use heuristics to find potential decoding routines
  3. Brute force emulate all code paths among basic blocks and functions
  4. Snapshot emulator state (registers, memory) at appropriate points
  5. Extract arguments to decoder functions from emulator snapshots
  6. Emulate decoder functions using extracted arguments and emulator state
  7. Diff memory state from before and after decoder emulation
  8. Extract human-readable strings from memory state difference
