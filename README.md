![PyPI - Python Version](https://img.shields.io/pypi/pyversions/flare-floss)
[![CI status](https://github.com/mandiant/flare-floss/actions/workflows/tests.yml/badge.svg)](https://github.com/mandiant/flare-floss/actions/workflows/tests.yml)
[![build status](https://github.com/mandiant/flare-floss/actions/workflows/build.yml/badge.svg)](https://github.com/mandiant/flare-floss/actions/workflows/build.yml)
[![License](https://img.shields.io/badge/license-Apache--2.0-green.svg)](LICENSE.txt)

<img src="https://raw.githubusercontent.com/mandiant/flare-floss/master/resources/logo.png" width="350"/>

# FLARE Obfuscated String Solver

Rather than heavily protecting backdoors with hardcore packers, many
malware authors evade heuristic detections by obfuscating only key
portions of an executable. Often, these portions are strings and resources
used to configure domains, files, and other artifacts of an infection.
These key features will not show up as plaintext in output of the `strings.exe` utility
that we commonly use during basic static analysis.

The FLARE Obfuscated String Solver (FLOSS, formerly FireEye Labs Obfuscated String Solver) uses advanced
static analysis techniques to automatically deobfuscate strings from
malware binaries. You can use it just like `strings.exe` to enhance
basic static analysis of unknown binaries.

FLOSS extracts all the following string types:
1. static strings: "regular" ASCII and UTF-16LE strings
2. decoded strings: strings decoded in a function
3. stack strings: strings constructed on the stack at run-time
4. tight strings: special form of stack strings, decoded on the stack

Please review the theory behind FLOSS [here](doc/theory.md). Our [blog post](https://www.mandiant.com/resources/automatically-extracting-obfuscated-strings) talks more about the motivation behind FLOSS and details how the tool works.


## Quick Run
To try FLOSS right away, download a standalone executable file from the releases page:
https://github.com/mandiant/flare-floss/releases

For a detailed description of *installing* FLOSS, review the documentation
 [here](doc/installation.md).


## Usage
Extract obfuscated strings from a malware binary:

    $ floss /path/to/malware/binary

Display the help/usage screen to see all available switches.

    $ floss -h

For a detailed description of *using* FLOSS, review the documentation
 [here](doc/usage.md).

For a detailed description of *testing* FLOSS, review the documentation
 [here](doc/test.md).
