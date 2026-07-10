# -*- mode: python -*-
# Copyright (C) 2017 Mandiant, Inc. All Rights Reserved.
import subprocess

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

a = Analysis(
    # when invoking pyinstaller from the project root,
    # this gets invoked from the directory of the spec file,
    # i.e. ./.github/pyinstaller
    ["../../floss/qs/main.py"],
    pathex=["floss"],
    binaries=[],
    datas=[
        # when invoking pyinstaller from the project root,
        # this gets invoked from the directory of the spec file,
        # i.e. ./.github/pyinstaller
        ('../../floss/qs/db/data/crt/*.jsonl.gz', 'floss/qs/db/data/crt'),
        ('../../floss/qs/db/data/expert/*.jsonl', 'floss/qs/db/data/expert'),
        ('../../floss/qs/db/data/gp/*.jsonl.gz', 'floss/qs/db/data/gp'),
        ('../../floss/qs/db/data/gp/*.bin', 'floss/qs/db/data/gp'),
        ('../../floss/qs/db/data/oss/*.jsonl.gz', 'floss/qs/db/data/oss'),
        ('../../floss/qs/db/data/winapi/*.txt.gz', 'floss/qs/db/data/winapi'),
    ],
    hiddenimports=[],
    hookspath=[".github/pyinstaller/hooks"],
    runtime_hooks=[],
    excludes=[
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
    ],
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
    name="quantumstrand",
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
