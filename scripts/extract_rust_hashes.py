#!/usr/bin/env python3
# Copyright (C) 2023 Mandiant, Inc. All Rights Reserved.

"""
File name: extract_rust_hashes.py

Description: Generates a database of Rust hashes from the Rust repository. Repo: https://github.com/rust-lang/rust/releases

Usage:

  $ python3 extract_rust_hashes.py

Copyright (C) 2023 Mandiant, Inc. All Rights Reserved.
Licensed under the Apache License, Version 2.0 (the "License");
 you may not use this file except in compliance with the License.
You may obtain a copy of the License at: [package root]/LICENSE.txt
Unless required by applicable law or agreed to in writing, software distributed under the License
 is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and limitations under the License.
"""

import subprocess
from pathlib import Path

import requests
from bs4 import BeautifulSoup

page_number = 1
rust_hashes = {}

print("Fetching Rust hashes from https://github.com/rust-lang/rust/releases...")

while True:
    r = requests.get("https://github.com/rust-lang/rust/releases?page={}".format(page_number))
    soup = BeautifulSoup(r.text, "html.parser")
    tables = soup.find_all(
        "div", class_="col-md-2 d-flex flex-md-column flex-row flex-wrap pr-md-6 mb-2 mb-md-0 flex-items-start pt-md-4"
    )

    # if there are no more tables, means we have reached the end of the page, break
    if len(tables) == 0:
        break

    # for each table, get the hash and version
    for table in tables:
        hash = str(table.find("a", attrs={"class": "Link Link--muted mb-2"})["href"]).split("/")[-1]
        version = table.find("span").text.strip()
        rust_hashes[hash] = version

    page_number += 1


print("\n{} hashes fetched.".format(len(rust_hashes)))
print("Writing it to rust_version_database.py...")

# write the hashes to a file
header = """
# Copyright (C) 2023 Mandiant, Inc. All Rights Reserved.

#############################################################################################
# File: rust_version_database.py
# Origin: Rust Repository https://github.com/rust-lang/rust
#
# Description:
# This file serves as a comprehensive reference, capturing the commit hashes associated with Rust versions over time.
# It facilitates tracking the commit history and enables the precise association of specific versions with their respective commits.
#
# Regeneration Instructions:
#
# To regenerate or update this file, you can follow these steps:
# 1. Navigate to the script directory.
# 2. Execute the script 'extract_rust_hashes.py'.
#    Example command: python extract_rust_hashes.py
#############################################################################################


"""

# write the hashes to a file
file_path = Path("rust_version_database.py")
with file_path.open(mode="w") as f:
    f.write(header)
    f.write("rust_commit_hash = ")
    f.write(str(rust_hashes))

# format the file
subprocess.call(["black", "-l", "120", "rust_version_database.py"])
