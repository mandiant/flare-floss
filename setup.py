#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Copyright (C) 2017 FireEye, Inc. All Rights Reserved.

import os

try:
    from setuptools import setup
except ImportError:
    from distutils.core import setup


requirements = [
    "q",
    "pyyaml",
    "tabulate",
    "vivisect",
    "plugnplay",
    "viv-utils",
    "enum34",
    "python-idb"
]

# this sets __version__
# via: http://stackoverflow.com/a/7071358/87207
# and: http://stackoverflow.com/a/2073599/87207
with open(os.path.join("floss", "version.py"), "rb") as f:
    exec(f.read())

setup(
    name='floss',
    version=__version__,
    description="",
    long_description="",
    author="Willi Ballenthin, Moritz Raabe",
    author_email='william.ballenthin@mandiant.com, moritz.raabe@mandiant.com',
    url='https://www.github.com/fireeye/flare-floss',
    packages=[
        'floss',
        'floss.plugins',
    ],
    package_dir={'floss': 'floss'},
    entry_points={
        "console_scripts": [
            "floss=floss.main:main",
        ]
    },
    include_package_data=True,
    install_requires=requirements,
    zip_safe=False,
    keywords='floss',
    classifiers=[
        'Development Status :: 4 - Beta',
        'Intended Audience :: Developers',
        'Natural Language :: English',
        "Programming Language :: Python :: 2",
    ],
)
