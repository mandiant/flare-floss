![PyPI - Python Version](https://img.shields.io/pypi/pyversions/flare-floss)
[![Last release](https://img.shields.io/github/v/release/mandiant/flare-floss)](https://github.com/mandiant/flare-floss/releases)
[![CI status](https://github.com/mandiant/flare-floss/actions/workflows/tests.yml/badge.svg)](https://github.com/mandiant/flare-floss/actions/workflows/tests.yml)
[![Downloads](https://img.shields.io/github/downloads/mandiant/flare-floss/total)](https://github.com/mandiant/flare-floss/releases)
[![License](https://img.shields.io/badge/license-Apache--2.0-green.svg)](LICENSE.txt)

![FLOSS logo](https://github.com/mandiant/flare-floss/blob/master/resources/floss-logo.png)

# FLARE Obfuscated String Solver

The FLARE Obfuscated String Solver (FLOSS, formerly FireEye Labs Obfuscated String Solver) uses advanced
static analysis techniques to automatically extract and deobfuscate all strings from
malware binaries. You can use it just like `strings.exe` to enhance the
basic static analysis of unknown binaries.

### Obfuscated Strings

Rather than heavily protecting backdoors with hardcore packers, many
malware authors evade heuristic detections by obfuscating only key
portions of an executable. Often, these portions are strings and resources
used to configure domains, files, and other artifacts of an infection.
These key features will not show up as plaintext in the output of the `strings.exe` utility
that we commonly use during basic static analysis.

FLOSS extracts all the following string types:
1. static strings: "regular" ASCII and UTF-16LE strings
2. stack strings: strings constructed on the stack at run-time
3. tight strings: a special form of stack strings, decoded on the stack
4. decoded strings: strings decoded in a function

Please review the theory behind FLOSS [here](doc/theory.md).

Our [blog post](https://www.mandiant.com/resources/automatically-extracting-obfuscated-strings) talks more about the motivation behind FLOSS and details how the tool works.

FLOSS version 2.0 updates are detailed in this [blog post](https://www.mandiant.com/resources/floss-version-2).

### Language-specific Strings
Not all compilers use string formats that the classic `strings.exe` algorithm supports. For example, if strings are UTF-8 encoded or stored without a NULL-terminator. FLOSS can identify and extract strings from programs compiled from the following languages:
 1. Go
 2. Rust

The strings FLOSS extracts specific to a compiler are much easier to inspect by humans. 

Please consult the documentation to learn more about the [language-specific string extraction](doc/language_specific_strings.md).

## Installation
To use FLOSS, download a standalone executable file from the releases page:
https://github.com/mandiant/flare-floss/releases

See the [installation documentation](doc/installation.md) for a detailed description of all methods to install FLOSS.

## Usage Examples
Extract obfuscated strings from a malware binary:

    $ floss malware.exe

Only extract stack and tight strings:

    $ floss --only stack tight -- suspicious.exe

Do not extract static strings:

    $ floss --no static -- backdoor.exe

Display the help/usage screens:

    $ floss -h  # show core arguments
    $ floss -H  # show all supported arguments

For a detailed description of using FLOSS, review the documentation
 [here](doc/usage.md).

## Scripts
FLOSS also contains additional Python scripts in the [scripts](scripts) directory 
which can be used to load its output into other tools such as Binary Ninja or IDA Pro.
For detailed description of these scripts review the documentation [here](scripts/README.md).

## Mailing List
Subscribe to the FLARE mailing list for community announcements by sending an email with the subject "subscribe" to [flare-external@google.com](mailto:flare-external@google.com?subject=subscribe&body=subscribe).
