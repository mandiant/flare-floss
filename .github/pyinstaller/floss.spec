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
    ["../../floss/main.py"],
    pathex=["floss"],
    binaries=[],
    datas=[],
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
    name="floss",
    # when invoking pyinstaller from the project root,
    # this gets invoked from the directory of the spec file,
    # i.e. ./.github/pyinstaller
    # TODO wait for PyInstaller 5.0.2... icon="../../resources/icon.ico",
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
coll = COLLECT(
    exe, a.binaries, a.zipfiles, a.datas, strip=None, upx=True, name="floss-dat"
)
