# Copyright (C) 2017 Mandiant, Inc. All Rights Reserved.

import os

import yaml
import pytest
import viv_utils

import floss.main as floss_main
import floss.stackstrings as stackstrings
import floss.tightstrings as tightstrings
import floss.string_decoder as string_decoder
from floss.const import MIN_STRING_LENGTH
from floss.identify import (
    get_function_fvas,
    get_top_functions,
    get_functions_with_tightloops,
    find_decoding_function_features,
    get_functions_without_tightloops,
)


def extract_strings(vw):
    """
    Deobfuscate strings from vivisect workspace
    """
    top_functions, decoding_function_features = identify_decoding_functions(vw)

    for s_decoded in string_decoder.decode_strings(
        vw, get_function_fvas(top_functions), MIN_STRING_LENGTH, disable_progress=True
    ):
        yield s_decoded.string

    no_tightloop_functions = get_functions_without_tightloops(decoding_function_features)
    for s_stack in stackstrings.extract_stackstrings(
        vw, no_tightloop_functions, MIN_STRING_LENGTH, disable_progress=True
    ):
        yield s_stack.string

    tightloop_functions = get_functions_with_tightloops(decoding_function_features)
    for s_tight in tightstrings.extract_tightstrings(vw, tightloop_functions, MIN_STRING_LENGTH, disable_progress=True):
        yield s_tight.string


def identify_decoding_functions(vw):
    selected_functions = floss_main.select_functions(vw, None)
    decoding_function_features, _ = find_decoding_function_features(vw, selected_functions, disable_progress=True)
    top_functions = get_top_functions(decoding_function_features, 20)
    return top_functions, decoding_function_features


def pytest_collect_file(parent, path):
    if path.basename == "test.yml":
        return YamlFile.from_parent(parent, fspath=path)


class YamlFile(pytest.File):
    def collect(self):
        spec = yaml.safe_load(self.path.open())
        test_dir = os.path.dirname(str(self.fspath))
        for platform, archs in spec["Output Files"].items():
            for arch, filename in archs.items():
                # TODO specify max runtime via command line option
                MAX_RUNTIME = 30.0
                try:
                    runtime_raw = spec["FLOSS running time"]
                    runtime = float(runtime_raw.split(" ")[0])
                    if runtime > MAX_RUNTIME:
                        # skip this test
                        continue
                except KeyError:
                    pass
                except ValueError:
                    pass
                filepath = os.path.join(test_dir, filename)
                if os.path.exists(filepath):
                    yield FLOSSTest.from_parent(
                        self, path=filepath, platform=platform, arch=arch, filename=filename, spec=spec
                    )


class FLOSSTestError(Exception):
    def __init__(self, expected, got):
        self.expected = expected
        self.got = got


class FLOSSStringsNotExtracted(FLOSSTestError):
    pass


class FLOSSDecodingFunctionNotFound(Exception):
    pass


class FLOSSTest(pytest.Item):
    def __init__(self, parent, path, platform, arch, filename, spec):
        name = "{name:s}::{platform:s}::{arch:s}".format(name=spec["Test Name"], platform=platform, arch=arch)
        super(FLOSSTest, self).__init__(name, parent)
        self.spec = spec
        self.platform = platform
        self.arch = arch
        self.filename = filename

    def _test_strings(self, test_path):
        expected_strings = set(self.spec["Decoded strings"])
        if not expected_strings:
            return

        arch = self.spec.get("Shellcode Architecture")
        if arch in ("i386", "amd64"):
            vw = viv_utils.getShellcodeWorkspaceFromFile(test_path, arch)
            found_strings = set(extract_strings(vw))
        else:
            # default assumes pe
            vw = viv_utils.getWorkspace(test_path)
            found_strings = set(extract_strings(vw))

        if not (expected_strings <= found_strings):
            raise FLOSSStringsNotExtracted(expected_strings, found_strings)

    def _test_detection(self, test_path):
        try:
            expected_functions = set(self.spec["Decoding routines"][self.platform][self.arch])
        except KeyError:
            expected_functions = set([])

        if not expected_functions:
            return

        vw = viv_utils.getWorkspace(test_path)
        top_functions, _ = identify_decoding_functions(vw)
        found_functions = set(top_functions)

        if not (expected_functions <= found_functions):
            raise FLOSSDecodingFunctionNotFound(expected_functions, found_functions)

    def runtest(self):
        xfail = self.spec.get("Xfail", {})
        if "all" in xfail:
            pytest.xfail("unsupported test case (known issue)")

        if "{0.platform:s}-{0.arch:s}".format(self) in xfail:
            pytest.xfail("unsupported platform&arch test case (known issue)")

        spec_path = self.location[0]
        test_dir = os.path.dirname(spec_path)
        test_path = os.path.join(test_dir, self.filename)

        self._test_detection(test_path)
        self._test_strings(test_path)

    def reportinfo(self):
        return self.fspath, 0, "usecase: %s" % self.name

    def repr_failure(self, excinfo):
        if isinstance(excinfo.value, FLOSSStringsNotExtracted):
            expected = excinfo.value.expected
            got = excinfo.value.got
            return "\n".join(
                [
                    "FLOSS extraction failed:",
                    "   expected: %s" % str(expected),
                    "   got: %s" % str(got),
                    "   missing (expected-got): %s" % str(set(expected) - set(got)),
                    "   unexpected (got-expected): %s" % str(set(got) - set(expected)),
                ]
            )
