# QUANTUMSTRAND

QUANTUMSTRAND is an experiment that augments traditional `strings.exe` output with context to aid in malware analysis and reverse engineering.
For example, we show the structure of a file alongside its strings and mute/highlight entries based on their global prevalence, library association, expert rules, and more.
If the experiment proves successful, we'll merge the best features directly into FLOSS and deprecate the QUANTUMSTRAND codename.

You can get prerelease builds of QUANTUMSTRAND from the [releases page](https://github.com/mandiant/flare-floss/releases).
Of course, this is an experiment, so there are no guarantees and many things yet to polish.

Note: the QUANTUMSTRAND database and signature files are tracked using Git LFS; contributors cloning the repo may need Git LFS installed to fetch those files.

## Features

  - extract ASCII and UTF-16LE strings
  - show strings next to right-aligned, colored context, including "tags" and file offset
  - render string within PE section range delimiters
  - annotate strings from known PE structures, like the import table
  - don't show junk strings that overlap with instructions
  - mute strings known to be globally prevalent, via an embedded database
  - mute strings from popular open source libraries, via embedded databases
  - highlight strings that match expert rules, via embedded databases


![screenshot 1](https://github.com/mandiant/flare-floss/assets/156560/f2d471a3-2624-498c-aaa9-928e2909c338)
![screenshot 2](https://github.com/mandiant/flare-floss/assets/156560/23bd20a1-7dff-46b5-be65-12582cb90d64)
