# FLARE Obfuscated String Solver

## Installation
You can install FLOSS in a few different ways.
First, if you simply want to use FLOSS to extract strings, just download
 the [standalone binaries](https://github.com/mandiant/flare-floss/releases/latest).
However, if you want to use FLOSS as a Python library,
 you can install the package directly from GitHub using `pip`.
Finally, if you'd like to contribute patches or features to FLOSS,
 you'll need to work with a local copy of the source code.

## Method 1: Using FLOSS standalone

If you simply want to use FLOSS to extract strings,
use the standalone binaries we host on GitHub:
 https://github.com/mandiant/flare-floss/releases.
These binary executable files contain all the source code,
 Python interpreter, and associated resources needed to make FLOSS run.
This means you can run it without any installation!
Just invoke the file using your terminal shell to see the help documentation.

We use PyInstaller to create these packages.

### MacOS Standalone installation

By default, on macOS Catalina or greater, Gatekeeper will block execution of the standalone binary. To resolve this, simply try to execute it once on the command-line and then go to `System Preferences` / `Security & Privacy` / `General` and approve the application.

## Method 2: Using FLOSS as a Python library

If you'd like to use FLOSS as part of an automated analysis system,
 you might want to invoke it as a Python library.
We designed FLOSS to be as easy to use from a client program as from
 the command line.
 
:warning: **FLOSS requires Python >= 3.8.**

### Step 1: Install FLOSS module

Use `pip` (Python >= 3.8) to install the `flare-floss` module to your local
 Python environment.
This fetches the library code to your computer, but does not keep
 editable source files around for you to hack on.
If you'd like to edit the source files, see Method 3.

- Install FLOSS:

    `$ pip install flare-floss`


### Step 2: Use FLOSS from a Python script

You can now import the `floss` module from a Python script:

    #!/usr/env/python
    import floss
    print(dir(floss))


## Method 3: Inspecting the FLOSS source code

If you'd like to review and modify the FLOSS source code,
 you'll need to check it out from GitHub and install it locally.
By following these instructions, you'll maintain a local directory
 of source code that you can modify and run easily.

### Step 1: Check out source code

- Clone the FLOSS git repository:

    `$ git clone https://github.com/mandiant/flare-floss /local/path/to/src`

### Step 2: Install the local source code

Next, use `pip` to install the source code in "editable" mode.
This means that Python will load the FLOSS module from this local
 directory rather than copying it to `site-packages` or `dist-packages`.
This is good, because it is easy for us to modify files and see the
 effects reflected immediately.
But be careful not to remove this directory unless uninstalling FLOSS!

- Install FLOSS:

    `$ pip install -e /local/path/to/src`

You'll find that the `floss.exe` (Windows) or `floss` (Linux, macOS) executables
 in your path now invoke the FLOSS binary from this directory.

### Step 3: Install development and testing dependencies

To install all testing and development dependencies, run:

`$ pip install -e /local/path/to/src[dev]`

We use a git submodule to separate [code](https://github.com/mandiant/flare-floss) and [test data](https://github.com/mandiant/flare-floss-testfiles).
To clone everything use the `--recurse-submodules` option:
- `$ git clone --recurse-submodules https://github.com/mandiant/flare-floss.git /local/path/to/src` (HTTPS)
- `$ git clone --recurse-submodules git@github.com:mandiant/flare-floss.git /local/path/to/src` (SSH)

Or use the manual option:
- clone repository
  - `$ git clone https://github.com/mandiant/flare-floss.git /local/path/to/src` (HTTPS)
  - `$ git clone git@github.com:mandiant/flare-floss.git /local/path/to/src` (SSH)
- `$ cd /local/path/to/src`
- `$ git submodule update --init tests/data`

We use the following tools to ensure consistent code style and formatting:

  - [black](https://github.com/psf/black) code formatter
  - [isort](https://pypi.org/project/isort/) code formatter
  - [mypy](https://mypy-lang.org/) type checking

We use [pre-commit](https://pre-commit.com/) so that its trivial to run the same linters & configuration locally as in CI.

Run all linters liks:
    ❯ pre-commit run --all-files
    isort....................................................................Passed
    black....................................................................Passed
    mypy.....................................................................Passed
    
Or run a single linter like:
    ❯ pre-commit run --all-files isort
    isort....................................................................Passed

Importantly, you can configure pre-commit to run automatically before every commit by running:

    ❯ pre-commit install --hook-type pre-commit
    pre-commit installed at .git/hooks/pre-commit

    ❯ pre-commit install --hook-type pre-push
    pre-commit installed at .git/hooks/pre-push

This way you can ensure that you don't commit code style or formatting offenses.
You can always temporarily skip the checks by using the `-n`/`--no-verify` git option.


### Step 4: Building standalone executables

Once you're happy with your contribution to FLOSS, you can package and
 distribute a standalone executable for your friends using PyInstaller.
This combines the source code, Python interpreter, and required resources
 into a single file that can be run without installation.

- Install pyinstaller:

    `$ pip install pyinstaller`

- Build standalone executable:

    `$ pyinstaller .github/pyinstaller/floss.spec`

- Distribute standalone executable:

    `$ cp ./dist/floss.exe /the/internet`
