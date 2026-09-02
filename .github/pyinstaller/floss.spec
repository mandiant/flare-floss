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
from pathlib import Path

from PyInstaller.utils.hooks import collect_submodules

# layout/tags are imported lazily from floss.pipeline; collect them so the
# standalone binary still bundles the full layout-aware static path.
layout_tags_hiddenimports = (
    collect_submodules("floss.layout")
    + collect_submodules("floss.tags")
    + [
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

if not Path("viewer/dist/index.html").is_file():
    raise SystemExit("missing viewer/dist/index.html; run: cd viewer && npm install && npm run build")

datas = [
    # when invoking pyinstaller from the project root,
    # this gets invoked from the directory of the spec file,
    # i.e. ./.github/pyinstaller
    ('../../floss/sigs', 'sigs'),
    # pre-built HTML viewer used by ``floss --html`` (from ``npm run build``)
    ('../../viewer/dist/index.html', 'floss/render/templates'),
    # tag databases
    ('../../floss/tags/data/crt/*.jsonl.gz', 'floss/tags/data/crt'),
    ('../../floss/tags/data/expert/*.jsonl', 'floss/tags/data/expert'),
    ('../../floss/tags/data/gp/*.jsonl.gz', 'floss/tags/data/gp'),
    ('../../floss/tags/data/gp/*.bin', 'floss/tags/data/gp'),
    ('../../floss/tags/data/oss/*.jsonl.gz', 'floss/tags/data/oss'),
    ('../../floss/tags/data/winapi/*.txt.gz', 'floss/tags/data/winapi'),
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
    hiddenimports=layout_tags_hiddenimports,
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
