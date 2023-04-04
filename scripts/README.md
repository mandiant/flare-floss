# FLOSS Scripts
FLOSS supports converting its output into scripts for various tools. Please see the render scripts in this directory.
  
Additionally, there is another [plugin for IDA](idaplugin.py) to allow FLOSS to automatically
extract obfuscated strings and apply them to the currently loaded module in IDA. `idaplugin.py` is a IDAPython script you can directly run within IDA Pro (File - Script File... [ALT + F7]).

# Installation
These scripts can be downloaded from the FLOSS [GitHub](https://github.com/mandiant/flare-floss) repository
alongside the source, which is required for the scripts to run.
To install FLOSS as source, see the documentation [here](../doc/installation.md).


# Usage
## Convert FLOSS output for use by other tools

- Run FLOSS on the desired executable with the `-j` or `--json` argument to emit a JSON result
and redirect it to a JSON file.  
    `$ floss -j suspicious.exe > floss_results.json`

For Binary Ninja, IDA Pro, Ghidra or Radare2:
- Run the script for your tool of choice by passing the result json file as an argument and
redirect the output to a Python (.py) file.  

Ghidra Example:  
    `$ python render-ghidra-import-script.py floss_results.json > apply_floss.py`

- Run the Python script `apply_floss.py` using the desired tool.

For x64dbg:
- Instead of a Python file, redirect the output to a .json file.  
    `$ python render-x64dbg-database.py floss-results.json > database.json`

- Open the JSON file `database.json` in x64dbg.
