# FLARE Obfuscated String Solver

## Testing

We use [pytest](http://pytest.org/latest/usage.html) to test FLOSS and ensure that it adheres to our specifications. You can run test cases using the following steps to confirm that FLOSS behaves as expected on your platform.

First, make sure that `pytest` is installed:

    pip install pytest


## Binary Test Cases

We test FLOSS using a collection of binary files that implement various decoding routines. You can find the C source code for these tests under the directory `tests/data/src/`.

We store all test-related files in the [flare-floss-testfiles](https://github.com/mandiant/flare-floss-testfiles) repository.

### Building Binary Test Cases

You can easily build the binary test cases on both Linux (and OSX) and Windows systems because the source code is C99 source code. Under Linux, we provide Makefiles that invoke the build commands to compile all the tests in one go. On Windows, you may need to script calls to `cl.exe` using a batch script.

If you install [wclang](https://github.com/tpoechtrager/wclang),
you can cross-compile 32-bit and 64-bit Windows executables from your Linux environment.
You can use the following steps to configure your environment for building the binary test cases:

    sudo apt-get install clang mingw-w64 cmake make
    git clone https://github.com/tpoechtrager/wclang.git /home/user/src/wclang
    cd /home/user/src/wclang
    cmake -DCMAKE_INSTALL_PREFIX=/usr/local
    make
    sudo make install

You can now run `make all` from the directory `tests/data/src` to build all the test cases in ELF, PE32, and PE64 formats.

### Adding a new Binary Test Case

  - Decide on a name for your test. Pick something like `decode-rot-13`. Follow the examples and stick to this name throughout the test case.
  - Copy the directory `tests/data/src/template` to `tests/data/src/decode-rot-13`.
  - Update the `test.yml` document to describe the purpose of the test.
  - Update the Makefile in `tests/data/src/decode-rot-13/Makefile`. You should only need to update the test name in the first line. Change it to `test-decode-rot-13`.
  - Move the file `template.c` to `decode-rot-13.c` and provide your implementation.
  - Update the Makefile in `tests/data/src/Makefile`. Add a new line in the first section with the name of your test.
  - Ensure you have the build environment configured, as described in the section "Building Binary Test Cases."
  - `cd` to `tests/data/src/decode-rot-13` and run `make all`. Confirm the binary runs as expected.
  - Create a new branch named `feature/test-decode-rot-13`, add and commit the Readme, Makefiles, .c source file, compiled binaries, and submit a PR to the [flare-floss-testfiles](https://github.com/mandiant/flare-floss-testfiles) repository.
