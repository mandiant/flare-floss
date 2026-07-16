# -*- mode: python -*-
# Copyright 2017 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.


import subprocess

from PyInstaller.utils.hooks import collect_submodules

# layout/tags/quantum modules are not imported by floss/main.py yet, but must be
# bundled for the standalone binary (formerly built via qs.spec).
quantum_hiddenimports = (
    collect_submodules("floss.layout")
    + collect_submodules("floss.tags")
    + [
        "floss.quantum",
        "floss.document",
        "floss.render.layout_text",
        "floss.ranges",
        "elftools",
        "lancelot",
        "machofile",
        "dnfile",
        "msgspec",
    ]
)

# when invoking pyinstaller from the project root,
# this gets run from the project root.
with open("./floss/version.py", "wb") as f:
    # git output will look like:
    #
    #     tags/v1.0.0-0-g3af38dc
    #         ------- tag
    #                 - commits since
    #                   g------- git hash fragment
    version = (
        subprocess.check_output(["git", "describe", "--always", "--tags", "--long"])
        .decode("utf-8")
        .strip()
        .replace("tags/", "")
    )
    f.write(("__version__ = '%s'" % version).encode("utf-8"))

datas = [
    # when invoking pyinstaller from the project root,
    # this gets invoked from the directory of the spec file,
    # i.e. ./.github/pyinstaller
    ('../../floss/sigs', 'sigs'),
    # tag databases (legacy path: floss/qs/db/data)
    ('../../floss/qs/db/data/crt/*.jsonl.gz', 'floss/qs/db/data/crt'),
    ('../../floss/qs/db/data/expert/*.jsonl', 'floss/qs/db/data/expert'),
    ('../../floss/qs/db/data/gp/*.jsonl.gz', 'floss/qs/db/data/gp'),
    ('../../floss/qs/db/data/gp/*.bin', 'floss/qs/db/data/gp'),
    ('../../floss/qs/db/data/oss/*.jsonl.gz', 'floss/qs/db/data/oss'),
    ('../../floss/qs/db/data/winapi/*.txt.gz', 'floss/qs/db/data/winapi'),
]

excludes = [
    # ignore packages that would otherwise be bundled with the .exe.
    # review: build/pyinstaller/xref-pyinstaller.html
    # we don't do any GUI stuff, so ignore these modules
    "tkinter",
    "_tkinter",
    "Tkinter",

    # tqdm provides renderers for ipython,
    # however, this drags in a lot of dependencies.
    # since we don't spawn a notebook, we can safely remove these.
    "IPython",
    "ipywidgets",

    # these are pulled in by networkx
    # but we don't need to compute the strongly connected components.
    "numpy",
    "scipy",
    "matplotlib",
    "pandas",
    "pytest",

    # deps from viv that we don't use.
    # this duplicates the entries in `hook-vivisect`,
    # but works better this way.
    "vqt",
    "vdb.qt",
    "envi.qt",
    "PyQt5",
    "qt5",
    "pyqtwebengine",
    "pyasn1",
]

a = Analysis(
    # when invoking pyinstaller from the project root,
    # this gets invoked from the directory of the spec file,
    # i.e. ./.github/pyinstaller
    ["../../floss/main.py"],
    pathex=["floss"],
    binaries=[],
    datas=datas,
    hiddenimports=quantum_hiddenimports,
    hookspath=[".github/pyinstaller/hooks"],
    runtime_hooks=[],
    excludes=excludes,
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name="floss",
    # when invoking pyinstaller from the project root,
    # this gets invoked from the directory of the spec file,
    # i.e. ./.github/pyinstaller
    icon="../../resources/floss.ico",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,
)

# enable the following to debug the contents of the .exe
# writes to ./dist/floss-dat
#coll = COLLECT(
#    exe, a.binaries, a.zipfiles, a.datas, strip=None, upx=True, name="floss-dat"
#)
