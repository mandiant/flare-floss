# FLOSS Scripts
FLOSS supports converting its output into scripts for various tools. Please see the render scripts in this directory.
  
Additionally, there is another [plugin for IDA](idaplugin.py) to allow FLOSS to automatically
extract obfuscated strings and apply them to the currently loaded module in IDA.

# Installation
These scripts can be downloaded from the FLOSS [GitHub](https://github.com/mandiant/flare-floss) repository
alongside the source, which is required for the scripts to run.
To install FLOSS as source, see the documentation [here](../doc/installation.md).


# Usage
#### To convert FLOSS output into scripts for tools:

- Run FLOSS on the desired executable with the -j or --json argument to emit a JSON result
and redirect it to a JSON file.


    $ floss -j suspicious.exe > floss_results.json

For Binary Ninja, IDA, Ghidra or Radare2,
- Run the script for your tool of choice by passing the result json as an argument and
redirect the output to a Python(.py) file.

IDA

      $ python render-ida-import-script.py floss_results.json > apply_floss.py

Binary Ninja

    $ python render-binja-import-script.py floss_results.json > apply_floss.py

Ghidra

    $ python render-ghidra-import-script.py floss_results.json > apply_floss.py

Radare2

    $ python render-r2-import-script.py floss_results.json > apply_floss.py

- Run the new python file apply_floss.py in the tool you made it for.

For x64dbg,
- Instead of a python file, redirect the output to a .json file.


    $ python render-x64dbg-database.py floss-results.json > database.json

- Open the JSON file database.json in x64dbg.

#### To run the IDA plugin,
