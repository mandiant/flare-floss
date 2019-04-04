#!/usr/bin/env python
# encoding: utf-8
# Copyright (C) 2017 FireEye, Inc. All Rights Reserved.

from __future__ import print_function
import os
import sys
import mmap
import json
import string
import logging
from time import time
from optparse import OptionParser, OptionGroup

import idb
import tabulate
import viv_utils

import version
import strings
import stackstrings
import string_decoder
import plugins.arithmetic_plugin
import identification_manager as im
import plugins.library_function_plugin
import plugins.function_meta_data_plugin
import plugins.mov_plugin
from interfaces import DecodingRoutineIdentifier
from decoding_manager import LocationType
from base64 import b64encode

from utils import get_vivisect_meta_info


floss_logger = logging.getLogger("floss")


KILOBYTE = 1024
MEGABYTE = 1024 * KILOBYTE
MAX_FILE_SIZE = 16 * MEGABYTE

SUPPORTED_FILE_MAGIC = set(["MZ"])

MIN_STRING_LENGTH_DEFAULT = 4


class LoadNotSupportedError(Exception):
    pass


class WorkspaceLoadError(Exception):
    pass


def hex(i):
    return "0x%X" % (i)


def decode_strings(vw, decoding_functions_candidates, min_length, no_filter=False, max_instruction_count=20000, max_hits=1):
    """
    FLOSS string decoding algorithm
    :param vw: vivisect workspace
    :param decoding_functions_candidates: identification manager
    :param min_length: minimum string length
    :param no_filter: do not filter decoded strings
    :param max_instruction_count: The maximum number of instructions to emulate per function.
    :param max_hits: The maximum number of hits per address
    :return: list of decoded strings ([DecodedString])
    """
    decoded_strings = []
    function_index = viv_utils.InstructionFunctionIndex(vw)
    # TODO pass function list instead of identification manager
    for fva, _ in decoding_functions_candidates.get_top_candidate_functions(10):
        for ctx in string_decoder.extract_decoding_contexts(vw, fva, max_hits):
            for delta in string_decoder.emulate_decoding_routine(vw, function_index, fva, ctx, max_instruction_count):
                for delta_bytes in string_decoder.extract_delta_bytes(delta, ctx.decoded_at_va, fva):
                    for decoded_string in string_decoder.extract_strings(delta_bytes, min_length, no_filter):
                        decoded_strings.append(decoded_string)
    return decoded_strings


def sanitize_string_for_printing(s):
    """
    Return sanitized string for printing.
    :param s: input string
    :return: sanitized string
    """
    sanitized_string = s.encode('unicode_escape')
    sanitized_string = sanitized_string.replace('\\\\', '\\')  # print single backslashes
    sanitized_string = "".join(c for c in sanitized_string if c in string.printable)
    return sanitized_string


def sanitize_string_for_script(s):
    """
    Return sanitized string that is added to IDAPython script content.
    :param s: input string
    :return: sanitized string
    """
    sanitized_string = sanitize_string_for_printing(s)
    sanitized_string = sanitized_string.replace('\\', '\\\\')
    sanitized_string = sanitized_string.replace('\"', '\\\"')
    return sanitized_string


def print_plugin_list():
    print("Available identification plugins:")
    print("\n".join([" - %s" % plugin.get_name_version() for plugin in get_all_plugins()]))


# TODO add --plugin_dir switch at some point
def get_all_plugins():
    """
    Return all plugins to be run.
    """
    ps = DecodingRoutineIdentifier.implementors()
    if len(ps) == 0:
        ps.append(plugins.function_meta_data_plugin.FunctionCrossReferencesToPlugin())
        ps.append(plugins.function_meta_data_plugin.FunctionArgumentCountPlugin())
        ps.append(plugins.function_meta_data_plugin.FunctionIsThunkPlugin())
        ps.append(plugins.function_meta_data_plugin.FunctionBlockCountPlugin())
        ps.append(plugins.function_meta_data_plugin.FunctionInstructionCountPlugin())
        ps.append(plugins.function_meta_data_plugin.FunctionSizePlugin())
        ps.append(plugins.function_meta_data_plugin.FunctionRecursivePlugin())
        ps.append(plugins.library_function_plugin.FunctionIsLibraryPlugin())
        ps.append(plugins.arithmetic_plugin.XORPlugin())
        ps.append(plugins.arithmetic_plugin.ShiftPlugin())
        ps.append(plugins.mov_plugin.MovPlugin())
    return ps


def make_parser():
    usage_message = "%prog [options] FILEPATH"

    parser = OptionParser(usage=usage_message,
                          version="%prog {:s}\nhttps://github.com/fireeye/flare-floss/".format(version.__version__))

    parser.add_option("-n", "--minimum-length", dest="min_length",
                      help="minimum string length (default is %d)" % MIN_STRING_LENGTH_DEFAULT)
    parser.add_option("-f", "--functions", dest="functions",
                      help="only analyze the specified functions (comma-separated)",
                      type="string")
    parser.add_option("--save-workspace", dest="save_workspace",
                      help="save vivisect .viv workspace file in current directory", action="store_true")
    parser.add_option("-m", "--show-metainfo", dest="should_show_metainfo",
                      help="display vivisect workspace meta information", action="store_true")
    parser.add_option("--no-filter", dest="no_filter",
                      help="do not filter deobfuscated strings (may result in many false positive strings)",
                      action="store_true")
    parser.add_option("--max-instruction-count", dest="max_instruction_count", type=int, default=20000,
                      help="maximum number of instructions to emulate per function (default is 20000)")
    parser.add_option("--max-address-revisits", dest="max_address_revisits", type=int, default=0,
                      help="maximum number of address revisits per function (default is 0)")
    parser.add_option("-c", "--complementary-idb", dest="complementary_idb", type="string",
                      help="complementary pristine IDA Pro database file to aid library name resolution")

    shellcode_group = OptionGroup(parser, "Shellcode options", "Analyze raw binary file containing shellcode")
    shellcode_group.add_option("-s", "--shellcode", dest="is_shellcode", help="analyze shellcode",
                               action="store_true")
    shellcode_group.add_option("-e", "--shellcode_ep", dest="shellcode_entry_point",
                               help="shellcode entry point", type="string")
    shellcode_group.add_option("-b", "--shellcode_base", dest="shellcode_base",
                               help="shellcode base offset", type="string")
    parser.add_option_group(shellcode_group)

    extraction_group = OptionGroup(parser, "Extraction options", "Specify which string types FLOSS shows from a file, "
                                                                 "by default all types are shown")
    extraction_group.add_option("--no-static-strings", dest="no_static_strings", action="store_true",
                                help="do not show static ASCII and UTF-16 strings")
    extraction_group.add_option("--no-decoded-strings", dest="no_decoded_strings", action="store_true",
                                help="do not show decoded strings")
    extraction_group.add_option("--no-stack-strings", dest="no_stack_strings", action="store_true",
                                help="do not show stackstrings")
    parser.add_option_group(extraction_group)

    format_group = OptionGroup(parser, "Format Options")
    format_group.add_option("-g", "--group", dest="group_functions",
                            help="group output by virtual address of decoding functions",
                            action="store_true")
    format_group.add_option("-q", "--quiet", dest="quiet", action="store_true",
                            help="suppress headers and formatting to print only extracted strings")
    parser.add_option_group(format_group)

    logging_group = OptionGroup(parser, "Logging Options")
    logging_group.add_option("-v", "--verbose", dest="verbose",
                             help="show verbose messages and warnings", action="store_true")
    logging_group.add_option("-d", "--debug", dest="debug",
                             help="show all trace messages", action="store_true")
    parser.add_option_group(logging_group)

    output_group = OptionGroup(parser, "Script output options")
    output_group.add_option("-i", "--ida", dest="ida_python_file",
                            help="create an IDAPython script to annotate the decoded strings in an IDB file")
    output_group.add_option("--x64dbg", dest="x64dbg_database_file",
                            help="create a x64dbg database/json file to annotate the decoded strings in x64dbg")
    output_group.add_option("-r", "--radare", dest="radare2_script_file",
                            help="create a radare2 script to annotate the decoded strings in an .r2 file")
    output_group.add_option("-j", "--binja", dest="binja_script_file",
                            help="create a Binary Ninja script to annotate the decoded strings in a BNDB file")
    parser.add_option_group(output_group)

    identification_group = OptionGroup(parser, "Identification Options")
    identification_group.add_option("-p", "--plugins", dest="plugins",
                                    help="apply the specified identification plugins only (comma-separated)")
    identification_group.add_option("-l", "--list-plugins", dest="list_plugins",
                                    help="list all available identification plugins and exit",
                                    action="store_true")
    parser.add_option_group(identification_group)

    profile_group = OptionGroup(parser, "FLOSS Profiles")
    profile_group.add_option("-x", "--expert", dest="expert",
                             help="show duplicate offset/string combinations, save workspace, group function output",
                             action="store_true")
    parser.add_option_group(profile_group)

    return parser


def set_logging_levels(should_debug=False, should_verbose=False):
    """
    Sets the logging levels of each of Floss's loggers individually.
    Recommended to use if Floss is being used as a library, and your
    project has its own logging set up. If both parameters 'should_debug'
    and 'should_verbose' are false, the logging level will be set to ERROR.
    :param should_debug: set logging level to DEBUG
    :param should_verbose: set logging level to INFO
    """
    log_level = None
    emulator_driver_level = None

    if should_debug:
        log_level = logging.DEBUG
        emulator_driver_level = log_level

    elif should_verbose:
        log_level = logging.INFO
        emulator_driver_level = log_level
    else:
        log_level = logging.ERROR
        emulator_driver_level = logging.CRITICAL

    # ignore messages like:
    # DEBUG: mapping section: 0 .text
    logging.getLogger("vivisect.parsers.pe").setLevel(log_level)

    # ignore messages like:
    # WARNING:EmulatorDriver:error during emulation of function: BreakpointHit at 0x1001fbfb
    # ERROR:EmulatorDriver:error during emulation of function ... DivideByZero: DivideByZero at 0x10004940
    # TODO: probably should modify emulator driver to de-prioritize this
    logging.getLogger("EmulatorDriver").setLevel(emulator_driver_level)

    # ignore messages like:
    # WARNING:Monitor:logAnomaly: anomaly: BreakpointHit at 0x1001fbfb
    logging.getLogger("Monitor").setLevel(log_level)

    # ignore messages like:
    # WARNING:envi/codeflow.addCodeFlow:parseOpcode error at 0x1001044c: InvalidInstruction("'660f3a0fd90c660f7f1f660f6fe0660f' at 0x1001044c",)
    logging.getLogger("envi/codeflow.addCodeFlow").setLevel(log_level)

    # ignore messages like:
    # WARNING:vtrace.platforms.win32:LoadLibrary C:\Users\USERNA~1\AppData\Local\Temp\_MEI21~1\vtrace\platforms\windll\amd64\symsrv.dll: [Error 126] The specified module could not be found
    # WARNING:vtrace.platforms.win32:LoadLibrary C:\Users\USERNA~1\AppData\Local\Temp\_MEI21~1\vtrace\platforms\windll\amd64\dbghelp.dll: [Error 126] The specified module could not be found
    logging.getLogger("vtrace.platforms.win32").setLevel(log_level)

    # ignore messages like:
    # DEBUG: merge_candidates: Function at 0x00401500 is new, adding
    logging.getLogger("floss.identification_manager.IdentificationManager").setLevel(log_level)

    # ignore messages like:
    # WARNING: get_caller_vas: unknown caller function: 0x403441
    # DEBUG: get_all_function_contexts: Getting function context for function at 0x00401500...
    logging.getLogger("floss.function_argument_getter.FunctionArgumentGetter").setLevel(log_level)

    # ignore messages like:
    # DEBUG: Emulating function at 0x004017A9 called at 0x00401644, return address: 0x00401649
    logging.getLogger("floss").setLevel(log_level)

    # ignore messages like:
    # DEBUG: extracting stackstrings at checkpoint: 0x4048dd stacksize: 0x58
    logging.getLogger("floss.stackstrings").setLevel(log_level)

    # ignore messages like:
    # WARNING:plugins.arithmetic_plugin.XORPlugin:identify: Invalid instruction encountered in basic block, skipping: 0x4a0637
    logging.getLogger("floss.plugins.arithmetic_plugin.XORPlugin").setLevel(log_level)
    logging.getLogger("floss.plugins.arithmetic_plugin.ShiftPlugin").setLevel(log_level)

    # ignore messages like:
    # DEBUG: identify: Identified WSAStartup_00401476 at VA 0x00401476
    logging.getLogger("floss.plugins.library_function_plugin.FunctionIsLibraryPlugin").setLevel(log_level)

    # ignore messages like:
    # DEBUG: identify: Function at 0x00401500: Cross references to: 2
    logging.getLogger("floss.plugins.function_meta_data_plugin.FunctionCrossReferencesToPlugin").setLevel(log_level)

    # ignore messages like:
    # DEBUG: identify: Function at 0x00401FFF: Number of arguments: 3
    logging.getLogger("floss.plugins.function_meta_data_plugin.FunctionArgumentCountPlugin").setLevel(log_level)

    # ignore messages like:
    # DEBUG: get_meta_data: Function at 0x00401470 has meta data: Thunk: ws2_32.WSACleanup
    logging.getLogger("floss.plugins.function_meta_data_plugin.FunctionIsThunkPlugin").setLevel(log_level)

    # ignore messages like:
    # DEBUG: get_meta_data: Function at 0x00401000 has meta data: BlockCount: 7
    logging.getLogger("floss.plugins.function_meta_data_plugin.FunctionBlockCountPlugin").setLevel(log_level)

    # ignore messages like:
    # DEBUG: get_meta_data: Function at 0x00401000 has meta data: InstructionCount: 60
    logging.getLogger("floss.plugins.function_meta_data_plugin.FunctionInstructionCountPlugin").setLevel(log_level)

    # ignore messages like:
    # DEBUG: get_meta_data: Function at 0x00401000 has meta data: Size: 177
    logging.getLogger("floss.plugins.function_meta_data_plugin.FunctionSizePlugin").setLevel(log_level)

    # ignore messages like:
    # DEBUG: identify: suspicious MOV instruction at 0x00401017 in function 0x00401000: mov byte [edx],al
    logging.getLogger("floss.plugins.mov_plugin.MovPlugin").setLevel(log_level)

    logging.getLogger("idb.netnode").setLevel(logging.WARN)
    logging.getLogger("viv_utils.idaloader").setLevel(logging.WARN)


def set_log_config(should_debug=False, should_verbose=False):
    """
    Removes root logging handlers, and sets Floss's logging level.
    Recommended to use if Floss is being used in a standalone script, or
    your project doesn't have any loggers. If both parameters 'should_debug'
    and 'should_verbose' are false, the logging level will be set to ERROR.
    :param should_debug: set logging level to DEBUG
    :param should_verbose: set logging level to INFO
    """
    # reset .basicConfig root handler
    # via: http://stackoverflow.com/a/2588054
    root = logging.getLogger()
    if root.handlers:
        for handler in root.handlers:
            root.removeHandler(handler)

    if should_debug:
        logging.basicConfig(level=logging.DEBUG)
    elif should_verbose:
        logging.basicConfig(level=logging.INFO)
    else:
        logging.basicConfig(level=logging.WARNING)

    set_logging_levels(should_debug, should_verbose)


def parse_functions_option(functions_option):
    """
    Return parsed -f command line option or None.
    """
    fvas = None
    if functions_option:
        fvas = [int(fva, 0x10) for fva in functions_option.split(",")]
    return fvas


def validate_file_path(parser, file_path, try_help_msg=""):
    if not os.path.exists(file_path):
        parser.error("File '%s' does not exist\n%s" % (file_path, try_help_msg))
    if not os.path.isfile(file_path):
        parser.error("'%s' is not a file\n%s" % (file_path, try_help_msg))
    return file_path


def parse_sample_file_path(parser, args):
    """
    Return validated input file path or terminate program.
    """
    try_help_msg = "Try '%s -h' for more information" % parser.get_prog_name()
    if len(args) != 1:
        parser.error("Please provide a valid file path\n%s" % try_help_msg)
    sample_file_path = args[0]
    return validate_file_path(parser, sample_file_path, try_help_msg)


def select_functions(vw, functions_option):
    """
    Given a workspace and sequence of function addresses, return the list
    of valid functions, or all valid function addresses.
    :param vw: vivisect workspace
    :param functions_option: -f command line option
    :return: list of all valid function addresses
    """
    function_vas = parse_functions_option(functions_option)

    workspace_functions = set(vw.getFunctions())
    if function_vas is None:
        return workspace_functions

    function_vas = set(function_vas)
    functions_not_found = function_vas - workspace_functions
    if len(functions_not_found) > 0:
        raise Exception("Functions don't exist in vivisect workspace: %s" % get_str_from_func_list(
            list(functions_not_found)))

    return function_vas


def get_str_from_func_list(function_list):
    return ", ".join(map(hex, function_list))


def parse_plugins_option(plugins_option):
    """
    Return parsed -p command line option or "".
    """
    return (plugins_option or "").split(",")


def select_plugins(plugins_option):
    """
    Return the list of valid plugin names from the list of
    plugin names, or all valid plugin names.
    :param plugins_option: -p command line argument value
    :return: list of strings of all selected plugins
    """
    plugin_names = parse_plugins_option(plugins_option)

    plugin_names = set(plugin_names)
    all_plugin_names = set(map(str, get_all_plugins()))

    if "" in plugin_names:
        plugin_names.remove("")
    if not plugin_names:
        return list(all_plugin_names)

    if len(plugin_names - all_plugin_names) > 0:
        # TODO handle exception
        raise Exception("Plugin not found")

    return plugin_names


def filter_unique_decoded(decoded_strings):
    unique_values = set()
    originals = []
    for decoded in decoded_strings:
        hashable = (decoded.s, decoded.decoded_at_va, decoded.fva)
        if hashable not in unique_values:
            unique_values.add(hashable)
            originals.append(decoded)
    return originals


def parse_min_length_option(min_length_option):
    """
    Return parsed -n command line option or default length.
    """
    min_length = int(min_length_option or str(MIN_STRING_LENGTH_DEFAULT))
    return min_length


def is_workspace_file(sample_file_path):
    """
    Return if input file is a vivisect workspace, based on file extension
    :param sample_file_path:
    :return: True if file extension is .viv, False otherwise
    """
    if os.path.splitext(sample_file_path)[1] == ".viv":
        return True
    return False


def is_supported_file_type(sample_file_path):
    """
    Return if FLOSS supports the input file type, based on header bytes
    :param sample_file_path:
    :return: True if file type is supported, False otherwise
    """
    with open(sample_file_path, "rb") as f:
        magic = f.read(2)

    if magic in SUPPORTED_FILE_MAGIC:
        return True
    else:
        return False


def print_identification_results(sample_file_path, decoder_results):
    """
    Print results of string decoding routine identification phase.
    :param sample_file_path: input file
    :param decoder_results: identification_manager
    """
    # TODO pass functions instead of identification_manager
    candidates = decoder_results.get_top_candidate_functions(10)
    if len(candidates) == 0:
        print("No candidate functions found.")
    else:
        print("Most likely decoding functions in: " + sample_file_path)
        print(tabulate.tabulate(
            [(hex(fva), "%.5f" % (score,)) for fva, score in candidates],
            headers=["address", "score"]))


def print_decoding_results(decoded_strings, group_functions, quiet=False, expert=False):
    """
    Print results of string decoding phase.
    :param decoded_strings: list of decoded strings ([DecodedString])
    :param group_functions: group output by VA of decoding routines
    :param quiet: print strings only, suppresses headers
    :param expert: expert mode
    """

    if group_functions:
        if not quiet:
            print("\nFLOSS decoded %d strings" % len(decoded_strings))
        fvas = set(map(lambda i: i.fva, decoded_strings))
        for fva in fvas:
            grouped_strings = filter(lambda ds: ds.fva == fva, decoded_strings)
            len_ds = len(grouped_strings)
            if len_ds > 0:
                if not quiet:
                    print("\nDecoding function at 0x%X (decoded %d strings)" % (fva, len_ds))
                print_decoded_strings(grouped_strings, quiet=quiet, expert=expert)
    else:
        if not expert:
            seen = set()
            decoded_strings = [x for x in decoded_strings if not (x.s in seen or seen.add(x.s))]
        if not quiet:
            print("\nFLOSS decoded %d strings" % len(decoded_strings))

        print_decoded_strings(decoded_strings, quiet=quiet, expert=expert)


def print_decoded_strings(decoded_strings, quiet=False, expert=False):
    """
    Print decoded strings.
    :param decoded_strings: list of decoded strings ([DecodedString])
    :param quiet: print strings only, suppresses headers
    :param expert: expert mode
    """
    if quiet or not expert:
        for ds in decoded_strings:
            print(sanitize_string_for_printing(ds.s))
    else:
        ss = []
        for ds in decoded_strings:
            s = sanitize_string_for_printing(ds.s)
            if ds.characteristics["location_type"] == LocationType.STACK:
                offset_string = "[STACK]"
            elif ds.characteristics["location_type"] == LocationType.HEAP:
                offset_string = "[HEAP]"
            else:
                offset_string = hex(ds.va or 0)
            ss.append((offset_string, hex(ds.decoded_at_va), s))

        if len(ss) > 0:
            print(tabulate.tabulate(ss, headers=["Offset", "Called At", "String"]))


def create_x64dbg_database_content(sample_file_path, imagebase, decoded_strings):
    """
    Create x64dbg database/json file contents for file annotations.
    :param sample_file_path: input file path
    :param imagebase: input files image base to allow calculation of rva
    :param decoded_strings: list of decoded strings ([DecodedString])
    :return: json needed to annotate a binary in x64dbg
    """
    export = {
        "comments": []
    }
    module = os.path.basename(sample_file_path)
    processed = {}
    for ds in decoded_strings:
        if ds.s != "":
            sanitized_string = sanitize_string_for_script(ds.s)
            if ds.characteristics["location_type"] == LocationType.GLOBAL:
                rva = hex(ds.va - imagebase)
            else:
                rva = hex(ds.decoded_at_va - imagebase)

            if not processed[rva]:
                processed[rva] = "FLOSS: " + sanitized_string
            else:
                processed[rva] += "\t" + sanitized_string

    for i in processed.keys():
        comment = {
            "text": processed[i],
            "manual": False,
            "module": module,
            "address": i
        }
        export["comments"].append(comment)

    return json.dumps(export, indent=1)


def create_ida_script_content(sample_file_path, decoded_strings, stack_strings):
    """
    Create IDAPython script contents for IDB file annotations.
    :param sample_file_path: input file path
    :param decoded_strings: list of decoded strings ([DecodedString])
    :param stack_strings: list of stack strings ([StackString])
    :return: content of the IDAPython script
    """
    main_commands = []
    for ds in decoded_strings:
        if ds.s != "":
            sanitized_string = sanitize_string_for_script(ds.s)
            if ds.characteristics["location_type"] == LocationType.GLOBAL:
                main_commands.append("print \"FLOSS: string \\\"%s\\\" at global VA 0x%X\"" % (sanitized_string, ds.va))
                main_commands.append("AppendComment(%d, \"FLOSS: %s\", True)" % (ds.va, sanitized_string))
            else:
                main_commands.append("print \"FLOSS: string \\\"%s\\\" decoded at VA 0x%X\"" % (sanitized_string, ds.decoded_at_va))
                main_commands.append("AppendComment(%d, \"FLOSS: %s\")" % (ds.decoded_at_va, sanitized_string))
    main_commands.append("print \"Imported decoded strings from FLOSS\"")

    ss_len = 0
    for ss in stack_strings:
        if ss.s != "":
            sanitized_string = sanitize_string_for_script(ss.s)
            main_commands.append("AppendLvarComment(%d, %d, \"FLOSS stackstring: %s\", True)" % (ss.fva, ss.frame_offset, sanitized_string))
            ss_len += 1
    main_commands.append("print \"Imported stackstrings from FLOSS\"")

    script_content = """from idc import RptCmt, Comment, MakeRptCmt, MakeComm, GetFrame, GetFrameLvarSize, GetMemberComment, SetMemberComment, Refresh


def AppendComment(ea, s, repeatable=False):
    # see williutils and http://blogs.norman.com/2011/security-research/improving-ida-analysis-of-x64-exception-handling
    if repeatable:
        string = RptCmt(ea)
    else:
        string = Comment(ea)

    if not string:
        string = s  # no existing comment
    else:
        if s in string:  # ignore duplicates
            return
        string = string + "\\n" + s
    if repeatable:
        MakeRptCmt(ea, string)
    else:
        MakeComm(ea, string)


def AppendLvarComment(fva, frame_offset, s, repeatable=False):
    stack = GetFrame(fva)
    if stack:
        lvar_offset = GetFrameLvarSize(fva) - frame_offset
        if lvar_offset and lvar_offset > 0:
            string = GetMemberComment(stack, lvar_offset, repeatable)
            if not string:
                string = s
            else:
                if s in string:  # ignore duplicates
                    return
                string = string + "\\n" + s
            if SetMemberComment(stack, lvar_offset, string, repeatable):
                print "FLOSS appended stackstring comment \\\"%%s\\\" at stack frame offset 0x%%X in function 0x%%X" %% (s, frame_offset, fva)
                return
    print "Failed to append stackstring comment \\\"%%s\\\" at stack frame offset 0x%%X in function 0x%%X" %% (s, frame_offset, fva)


def main():
    print "Annotating %d strings from FLOSS for %s"
    %s
    Refresh()

if __name__ == "__main__":
    main()
""" % (len(decoded_strings) + ss_len, sample_file_path, "\n    ".join(main_commands))
    return script_content


def create_binja_script_content(sample_file_path, decoded_strings, stack_strings):
    """
    Create Binary Ninja script contents for BNDB file annotations.
    :param sample_file_path: input file path
    :param decoded_strings: list of decoded strings ([DecodedString])
    :param stack_strings: list of stack strings ([StackString])
    :return: content of the Binary Ninja script
    """
    main_commands = []
    for ds in decoded_strings:
        if ds.s != "":
            sanitized_string = sanitize_string_for_script(ds.s)
            if ds.characteristics["location_type"] == LocationType.GLOBAL:
                main_commands.append("print \"FLOSS: string \\\"%s\\\" at global VA 0x%X\"" % (sanitized_string, ds.va))
                main_commands.append("AppendComment(%d, \"FLOSS: %s\")" % (ds.va, sanitized_string))
            else:
                main_commands.append("print \"FLOSS: string \\\"%s\\\" decoded at VA 0x%X\"" % (sanitized_string, ds.decoded_at_va))
                main_commands.append("AppendComment(%d, \"FLOSS: %s\")" % (ds.decoded_at_va, sanitized_string))
    main_commands.append("print \"Imported decoded strings from FLOSS\"")

    ss_len = 0
    for ss in stack_strings:
        if ss.s != "":
            sanitized_string = sanitize_string_for_script(ss.s)
            main_commands.append("AppendLvarComment(%d, %d, \"FLOSS stackstring: %s\")" % (ss.fva, ss.pc, sanitized_string))
            ss_len += 1
    main_commands.append("print \"Imported stackstrings from FLOSS\"")

    script_content = """import binaryninja as bn


def AppendComment(ea, s):

    s = s.encode('ascii')
    refAddrs = []
    for ref in bv.get_code_refs(ea):
        refAddrs.append(ref)

    for addr in refAddrs:
        fnc = bv.get_functions_containing(addr.address)
        fn = fnc[0]

        string = fn.get_comment_at(addr.address)

        if not string:
            string = s  # no existing comment
        else:
            if s in string:  # ignore duplicates
                return
            string = string + "\\n" + s

        fn.set_comment_at(addr.address, string)

def AppendLvarComment(fva, pc, s):

    # stack var comments are not a thing in Binary Ninja so just add at top of function
    # and at location where it's used as an arg
    s = s.encode('ascii')
    fn = bv.get_function_at(fva)

    for addr in [fva, pc]:
        string = fn.get_comment_at(addr)

        if not string:
            string = s
        else:
            if s in string:  # ignore duplicates
                return
            string = string + "\\n" + s

        fn.set_comment(addr, string)

print "Annotating %d strings from FLOSS for %s"
%s

""" % (len(decoded_strings) + ss_len, sample_file_path, "\n".join(main_commands))
    return script_content


def create_r2_script_content(sample_file_path, decoded_strings, stack_strings):
    """
    Create r2script contents for r2 session annotations.
    :param sample_file_path: input file path
    :param decoded_strings: list of decoded strings ([DecodedString])
    :param stack_strings: list of stack strings ([StackString])
    :return: content of the r2script
    """
    main_commands = []
    fvas = []
    for ds in decoded_strings:
        if ds.s != "":
            sanitized_string = b64encode("\"FLOSS: %s (floss_%x)\"" % (ds.s, ds.fva))
            if ds.characteristics["location_type"] == LocationType.GLOBAL:
                main_commands.append("CCu base64:%s @ %d" % (sanitized_string, ds.va))
                if ds.fva not in fvas:
                    main_commands.append("af @ %d" % (ds.fva))
                    main_commands.append("afn floss_%x @ %d" % (ds.fva, ds.fva))
                    fvas.append(ds.fva)
            else:
                main_commands.append("CCu base64:%s @ %d" % (sanitized_string, ds.decoded_at_va))
                if ds.fva not in fvas:
                    main_commands.append("af @ %d" % (ds.fva))
                    main_commands.append("afn floss_%x @ %d" % (ds.fva, ds.fva))
                    fvas.append(ds.fva)
    ss_len = 0
    for ss in stack_strings:
        if ss.s != "":
            sanitized_string = b64encode("\"FLOSS: %s\"" % ss.s)
            main_commands.append("Ca -0x%x base64:%s @ %d" % (ss.frame_offset, sanitized_string, ss.fva))
            ss_len += 1

    return "\n".join(main_commands)


def create_x64dbg_database(sample_file_path, x64dbg_database_file, imagebase, decoded_strings):
    """
    Create an x64dbg database to annotate an executable with decoded strings.
    :param sample_file_path: input file path
    :param x64dbg_database_file: output file path
    :param imagebase: imagebase for target file
    :param decoded_strings: list of decoded strings ([DecodedString])
    """
    script_content = create_x64dbg_database_content(sample_file_path, imagebase, decoded_strings)
    with open(x64dbg_database_file, 'wb') as f:
        try:
            f.write(script_content)
            floss_logger.info("Wrote x64dbg database to %s\n" % x64dbg_database_file)
        except Exception as e:
            raise e


def create_ida_script(sample_file_path, ida_python_file, decoded_strings, stack_strings):
    """
    Create an IDAPython script to annotate an IDB file with decoded strings.
    :param sample_file_path: input file path
    :param ida_python_file: output file path
    :param decoded_strings: list of decoded strings ([DecodedString])
    :param stack_strings: list of stack strings ([StackString])
    """
    script_content = create_ida_script_content(sample_file_path, decoded_strings, stack_strings)
    ida_python_file = os.path.abspath(ida_python_file)
    with open(ida_python_file, 'wb') as f:
        try:
            f.write(script_content)
            floss_logger.info("Wrote IDAPython script file to %s\n" % ida_python_file)
        except Exception as e:
            raise e
    # TODO return, catch exception in main()


def create_binja_script(sample_file_path, binja_script_file, decoded_strings, stack_strings):
    """
    Create a Binary Ninja script to annotate a BNDB file with decoded strings.
    :param sample_file_path: input file path
    :param binja_script_file: output file path
    :param decoded_strings: list of decoded strings ([DecodedString])
    :param stack_strings: list of stack strings ([StackString])
    """
    script_content = create_binja_script_content(sample_file_path, decoded_strings, stack_strings)
    binja_script__file = os.path.abspath(binja_script_file)
    with open(binja_script_file, 'wb') as f:
        try:
            f.write(script_content)
            floss_logger.info("Wrote Binary Ninja script file to %s\n" % binja_script_file)
        except Exception as e:
            raise e
    # TODO return, catch exception in main()


def create_r2_script(sample_file_path, r2_script_file, decoded_strings, stack_strings):
    """
    Create an r2script to annotate r2 session with decoded strings.
    :param sample_file_path: input file path
    :param r2script_file: output file path
    :param decoded_strings: list of decoded strings ([DecodedString])
    :param stack_strings: list of stack strings ([StackString])
    """
    script_content = create_r2_script_content(sample_file_path, decoded_strings, stack_strings)
    r2_script_file = os.path.abspath(r2_script_file)
    with open(r2_script_file, 'wb') as f:
        try:
            f.write(script_content)
            floss_logger.info("Wrote radare2script file to %s\n" % r2_script_file)
        except Exception as e:
            raise e
    # TODO return, catch exception in main()


def print_static_strings(path, min_length, quiet=False):
    """
    Print static ASCII and UTF-16 strings from provided file.
    :param path: input file
    :param min_length: minimum string length
    :param quiet: print strings only, suppresses headers
    """
    with open(path, "rb") as f:
        b = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)

        if os.path.getsize(path) > MAX_FILE_SIZE:
            # for large files, there might be a huge number of strings,
            # so don't worry about forming everything into a perfect table
            if not quiet:
                print("FLOSS static ASCII strings")
            for s in strings.extract_ascii_strings(b, n=min_length):
                print("%s" % s.s)
            if not quiet:
                print("")

            if not quiet:
                print("FLOSS static Unicode strings")
            for s in strings.extract_unicode_strings(b, n=min_length):
                print("%s" % s.s)
            if not quiet:
                print("")

            if os.path.getsize(path) > sys.maxint:
                floss_logger.warning("File too large, strings listings may be truncated.")
                floss_logger.warning("FLOSS cannot handle files larger than 4GB on 32bit systems.")

        else:
            # for reasonably sized files, we can read all the strings at once
            if not quiet:
                print("FLOSS static ASCII strings")
            for s in strings.extract_ascii_strings(b, n=min_length):
                print("%s" % (s.s))
            if not quiet:
                print("")

            if not quiet:
                print("FLOSS static UTF-16 strings")
            for s in strings.extract_unicode_strings(b, n=min_length):
                print("%s" % (s.s))
            if not quiet:
                print("")


def print_stack_strings(extracted_strings, quiet=False, expert=False):
    """
    Print extracted stackstrings.
    :param extracted_strings: list of stack strings ([StackString])
    :param quiet: print strings only, suppresses headers
    :param expert: expert mode
    """
    count = len(extracted_strings)

    if not quiet:
        print("\nFLOSS extracted %d stackstrings" % (count))

    if not expert:
        for ss in extracted_strings:
            print("%s" % (ss.s))
    elif count > 0:
        print(tabulate.tabulate(
            [(hex(s.fva), hex(s.frame_offset), s.s) for s in extracted_strings],
            headers=["Function", "Frame Offset", "String"]))


def print_file_meta_info(vw, selected_functions):
    print("\nVivisect workspace analysis information")
    try:
        for k, v in get_vivisect_meta_info(vw, selected_functions).iteritems():
            print("%s: %s" % (k, v or "N/A"))  # display N/A if value is None
    except Exception, e:
        floss_logger.error("Failed to print vivisect analysis information: {0}".format(e.message))


def fetch_function_names_from_idb(idb_file_path):
    with idb.from_file(idb_file_path) as db:
        api = idb.IDAPython(db)

        result = {}
        for fva in api.idautils.Functions():
            function_name = api.idc.GetFunctionName(fva)
            result[fva] = function_name

        return result


def apply_function_names(vw, function_names):
    for fva, function_name in function_names.items():
        if vw.isFunction(fva):
            vw.makeName(fva, function_name)
            viv_utils.set_function_name(vw, fva, function_name)
            floss_logger.debug('IDA Pro name imported : 0x%x:%s' % (fva, function_name))
        else:
            floss_logger.debug('IDA Pro name ignored  : 0x%x:%s' % (fva, function_name))


def load_workspace(sample_file_path, save_workspace, idb_file_path=None):
    # inform user that getWorkspace implicitly loads saved workspace if .viv file exists
    if is_workspace_file(sample_file_path) or os.path.exists("%s.viv" % sample_file_path):
        floss_logger.info("Loading existing vivisect workspace...")
    else:
        if not is_supported_file_type(sample_file_path):
            raise LoadNotSupportedError("FLOSS currently supports the following formats for string decoding and "
                                        "stackstrings: PE\nYou can analyze shellcode using the -s switch. See the "
                                        "help (-h) for more information.")
        floss_logger.info("Generating vivisect workspace...")

    vw = viv_utils.getWorkspace(sample_file_path, should_save=False)

    if idb_file_path:
        function_names = fetch_function_names_from_idb(idb_file_path)
        apply_function_names(vw, function_names)

    if save_workspace:
        vw.saveWorkspace()

    return vw


def load_shellcode_workspace(sample_file_path, save_workspace, shellcode_ep_in, shellcode_base_in):
    if is_supported_file_type(sample_file_path):
        floss_logger.warning("Analyzing supported file type as shellcode. This will likely yield weaker analysis.")

    shellcode_entry_point = 0
    if shellcode_ep_in:
        shellcode_entry_point = int(shellcode_ep_in, 0x10)

    shellcode_base = 0
    if shellcode_base_in:
        shellcode_base = int(shellcode_base_in, 0x10)

    floss_logger.info("Generating vivisect workspace for shellcode, base: 0x%x, entry point: 0x%x...",
                      shellcode_base, shellcode_entry_point)
    with open(sample_file_path, "rb") as f:
        shellcode_data = f.read()
    return viv_utils.getShellcodeWorkspace(shellcode_data, "i386", shellcode_base, shellcode_entry_point,
                                           save_workspace, sample_file_path)


def load_vw(sample_file_path, save_workspace, verbose, is_shellcode, shellcode_entry_point, shellcode_base, idb_file_path=None):
    try:
        if not is_shellcode:
            if shellcode_entry_point or shellcode_base:
                floss_logger.warning("Entry point and base offset only apply in conjunction with the -s switch when "
                                     "analyzing raw binary files.")
            return load_workspace(sample_file_path, save_workspace, idb_file_path=idb_file_path)
        else:
            return load_shellcode_workspace(sample_file_path, save_workspace, shellcode_entry_point, shellcode_base)
    except LoadNotSupportedError, e:
        floss_logger.error(str(e))
        raise WorkspaceLoadError
    except Exception, e:
        floss_logger.error("Vivisect failed to load the input file: {0}".format(e.message), exc_info=verbose)
        raise WorkspaceLoadError


def main(argv=None):
    """
    :param argv: optional command line arguments, like sys.argv[1:]
    :return: 0 on success, non-zero on failure
    """
    logging.basicConfig(level=logging.WARNING)

    parser = make_parser()
    if argv is not None:
        options, args = parser.parse_args(argv[1:])
    else:
        options, args = parser.parse_args()

    set_log_config(options.debug, options.verbose)

    if options.list_plugins:
        print_plugin_list()
        return 0

    sample_file_path = parse_sample_file_path(parser, args)
    min_length = parse_min_length_option(options.min_length)

    complementary_idb_file_path = options.complementary_idb
    if complementary_idb_file_path:
        validate_file_path(parser, complementary_idb_file_path)

    # expert profile settings
    if options.expert:
        options.save_workspace = True
        options.group_functions = True
        options.quiet = False

    if not is_workspace_file(sample_file_path):
        if not options.no_static_strings and not options.functions:
            floss_logger.info("Extracting static strings...")
            print_static_strings(sample_file_path, min_length=min_length, quiet=options.quiet)

        if options.no_decoded_strings and options.no_stack_strings and not options.should_show_metainfo:
            # we are done
            return 0

    if os.path.getsize(sample_file_path) > MAX_FILE_SIZE:
        floss_logger.error("FLOSS cannot extract obfuscated strings or stackstrings from files larger than"
                           " %d bytes" % MAX_FILE_SIZE)
        return 1

    try:
        vw = load_vw(sample_file_path, options.save_workspace, options.verbose,
                     options.is_shellcode, options.shellcode_entry_point, options.shellcode_base,
                     idb_file_path=complementary_idb_file_path)
    except WorkspaceLoadError:
        return 1

    try:
        selected_functions = select_functions(vw, options.functions)
    except Exception as e:
        floss_logger.error(str(e))
        return 1

    floss_logger.debug("Selected the following functions: %s", get_str_from_func_list(selected_functions))

    selected_plugin_names = select_plugins(options.plugins)
    floss_logger.debug("Selected the following plugins: %s", ", ".join(map(str, selected_plugin_names)))
    selected_plugins = filter(lambda p: str(p) in selected_plugin_names, get_all_plugins())

    if options.should_show_metainfo:
        meta_functions = None
        if options.functions:
            meta_functions = selected_functions
        print_file_meta_info(vw, meta_functions)

    time0 = time()

    if not options.no_decoded_strings:
        floss_logger.info("Identifying decoding functions...")
        decoding_functions_candidates = im.identify_decoding_functions(vw, selected_plugins, selected_functions)
        if options.expert:
            print_identification_results(sample_file_path, decoding_functions_candidates)

        floss_logger.info("Decoding strings...")
        decoded_strings = decode_strings(vw, decoding_functions_candidates, min_length, options.no_filter,
                                         options.max_instruction_count, options.max_address_revisits + 1)
        # TODO: The de-duplication process isn't perfect as it is done here and in print_decoding_results and
        # TODO: all of them on non-sanitized strings.
        if not options.expert:
            decoded_strings = filter_unique_decoded(decoded_strings)
        print_decoding_results(decoded_strings, options.group_functions, quiet=options.quiet, expert=options.expert)
    else:
        decoded_strings = []

    if not options.no_stack_strings:
        floss_logger.info("Extracting stackstrings...")
        stack_strings = stackstrings.extract_stackstrings(vw, selected_functions, min_length, options.no_filter)
        stack_strings = list(stack_strings)
        if not options.expert:
            # remove duplicate entries
            stack_strings = set(stack_strings)
        print_stack_strings(stack_strings, quiet=options.quiet, expert=options.expert)
    else:
        stack_strings = []

    if options.x64dbg_database_file:
        imagebase = vw.filemeta.values()[0]['imagebase']
        floss_logger.info("Creating x64dbg database...")
        create_x64dbg_database(sample_file_path, options.x64dbg_database_file, imagebase, decoded_strings)

    if options.ida_python_file:
        floss_logger.info("Creating IDA script...")
        create_ida_script(sample_file_path, options.ida_python_file, decoded_strings, stack_strings)

    if options.radare2_script_file:
        floss_logger.info("Creating r2script...")
        create_r2_script(sample_file_path, options.radare2_script_file, decoded_strings, stack_strings)

    if options.binja_script_file:
        floss_logger.info("Creating Binary Ninja script...")
        create_binja_script(sample_file_path, options.binja_script_file, decoded_strings, stack_strings)

    time1 = time()
    if not options.quiet:
        print("\nFinished execution after %f seconds" % (time1 - time0))

    return 0


if __name__ == "__main__":
    sys.exit(main())
