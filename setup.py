#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Copyright (C) 2017 Mandiant, Inc. All Rights Reserved.

from pathlib import Path

import setuptools

requirements = [
    "tabulate==0.9.0",
    "vivisect==1.1.1",
    "viv-utils[flirt]==0.7.9",
    "pydantic==1.10.9",
    "tqdm==4.65.0",
    "networkx==3.1",
    "halo==0.0.31",
    "rich==13.4.2",
    "pefile>=2022.5.30",
    "binary2strings==0.1.13",
]

# this sets __version__
# via: http://stackoverflow.com/a/7071358/87207
# and: http://stackoverflow.com/a/2073599/87207
file_path = Path("floss") / "version.py"
exec(file_path.read_text())


# via: https://packaging.python.org/guides/making-a-pypi-friendly-readme/
this_directory = Path(__file__).resolve().parent
readme_file = this_directory / "README.md"
long_description = readme_file.read_text()


pkgs = setuptools.find_packages()
if "floss.sigs" not in pkgs:
    pkgs.append("floss.sigs")


setuptools.setup(
    name="flare-floss",
    version=__version__,
    description="FLARE Obfuscated String Solver",
    long_description=long_description,
    long_description_content_type="text/markdown",
    author="Willi Ballenthin, Moritz Raabe",
    author_email="william.ballenthin@mandiant.com, moritz.raabe@mandiant.com",
    url="https://www.github.com/mandiant/flare-floss",
    packages=pkgs,
    package_dir={"floss": "floss"},
    entry_points={
        "console_scripts": [
            "floss=floss.main:main",
        ]
    },
    include_package_data=True,
    install_requires=requirements,
    extras_require={
        "dev": [
            "pre-commit==3.5.0",
            "pyyaml==6.0.1",
            "pytest==7.4.3",
            "pytest-sugar==0.9.4",
            "pytest-instafail==0.5.0",
            "pytest-cov==4.1.0",
            "pycodestyle==2.11.1",
            "black==23.10.1",
            "isort==5.11.4",
            "mypy==1.6.1",
            # type stubs for mypy
            "types-PyYAML==6.0.10",
            "types-tabulate==0.9.0.3",
        ],
        "build": [
            "pyinstaller==6.1.0",
        ],
    },
    zip_safe=False,
    keywords="floss malware analysis obfuscation strings FLARE",
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: Developers",
        "Intended Audience :: Information Technology",
        "License :: OSI Approved :: Apache Software License",
        "Natural Language :: English",
        "Programming Language :: Python :: 3",
        "Topic :: Security",
    ],
    python_requires=">=3.8",
)
