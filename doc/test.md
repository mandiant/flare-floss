# FireEye Labs Obfuscated String Solver

## Testing

We use [py.test](http://pytest.org/latest/usage.html) to test
 FLOSS and ensure it adheres to our specifications.
You can run test cases using the following steps
 to confirm that FLOSS behaves as expected on your platform.

First, make sure that `py.test` is installed:

    pip install py.test


## Binary Test Cases

We test FLOSS using a collection of binary files that implement
various decoding routines. You can find the C source code for these
tests under the direction `tests/src/`.

### Building Binary Test Cases

You can easily build the binary test cases on both Linux (and OSX) and Windows systems,
 because the source code is C99 source code.
Under Linux, we provide Makefiles that invoke the build commands to compile all the tests in one go.
On Windows, you may need to script calls to `cl.exe` using a batch script.

If you install [wclang](https://github.com/tpoechtrager/wclang),
 you can cross compile 32- and 64-bit Windows executables from your Linux environment.
We use Docker containers to automate the generation of consistent build environments.
You can use the following steps to configure your environment for building the binary test cases:

    sudo apt-get install clang mingw-w64 cmake make
    git clone https://github.com/tpoechtrager/wclang.git /home/user/src/wclang
    cd /home/user/src/wclang
    cmake -DCMAKE_INSTALL_PREFIX=/usr/local
    make
    sudo make install

You can now run `make all` from the directory `tests/src` to build all the test cases in ELF,
 PE32, and PE64 formats.

### Adding a new Binary Test Case

  - decide on a name for your test.
    pick something like: decode-rot-13.
    follow the examples and stick to this name throughout the test case.
  - copy the directory `tests/src/template` to ``tests/src/decode-rot-13`.
  - update the test.yml document to describe the purpose of the test.
  - update the Makefile in `tests/src/decode-rot-13/Makefile`.
    you should only need to update the test name in the first line.
    change it to `test-decode-rot-13`.
  - move the file `template.c` to `decode-rot-13.c` and provide your implementation.
  - update the Makefile in `tests/src/Makefile`.
    add a new line in the first section with the name of your test.
  - ensure you have the build environment configured, as described in the section
    "Building Binary Test Cases".
  - cd to `tests/src/decode-rot-13` and run `make all`. confirm the binary runs as expected.
  - create a new branch named `feature/test-decode-rot-13`,
    add and commit the Readme, Makefiles, and .c source file, and submit a PR to this repository.

## Running the tests
You can run execute the tests with:

    py.test tests/src/ -v