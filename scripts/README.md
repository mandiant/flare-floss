# FLARE Obfuscated String Solver

## Scripts
FLOSS currently supports converting its outputs into scripts for
the following tools:
1. [IDA pro](render-ida-import-script.py)
2. [Binary Ninja](render-binja-import-script.py)
3. [Ghidra](render-ghidra-import-script.py)
4. [Radare2](render-r2-import-script.py)
5. [X64dbg](render-x64dbg-database.py)
  
Additionally, there is another [plugin for IDA](idaplugin.py) to allow FLOSS to
automatically extract obfuscated strings and apply them to the
currently loaded module in IDA.

# Installation
These scripts can be downloaded from the FLOSS [GitHub](https://github.com/mandiant/flare-floss) repository
alongside the source, which is required for the scripts to run.
To install FLOSS, see the documentation [here](../doc/installation.md).


# Usage
#### To convert FLOSS output into scripts for tools:

- Run FLOSS on the desired executable with the JSON argument to emit a JSON result
and redirect it to a JSON file.


    $ floss -j suspicious.exe > floss_results.json

- Run the script for your tool of choice, pass the result json as an argument and
redirect the output to a Python(.py) file.


    $ python render-tool-import-script.py floss_results.json > apply_floss.py

- Run the new python file in the tool you made it for.

#### To run the IDA plugin,
