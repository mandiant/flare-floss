# Copyright (C) 2020 Mandiant, Inc. All Rights Reserved.

KILOBYTE = 1024
MEGABYTE = 1024 * KILOBYTE
MAX_FILE_SIZE = 16 * MEGABYTE
SUPPORTED_FILE_MAGIC = {b"MZ"}
MIN_STRING_LENGTH = 4
MAX_STRING_LENGTH = 2048

# Decoded String (DS)
# maximum number of instructions to emulate per function
DS_MAX_INSN_COUNT = 20000
# maximum number of address revisits per function when extracting contexts
DS_MAX_ADDRESS_REVISITS_CTX_EXTRACTION = 1
# maximum number of address revisits per function when emulating decoding functions
DS_MAX_ADDRESS_REVISITS_EMULATION = 300
# shortcut decoding of a function if only few strings are found
DS_FUNCTION_MIN_DECODED_STRINGS = 5
# decoding candidate only called a few times
DS_FUNCTION_CALLS_RARE = 7
# decoding candidate called more often
DS_FUNCTION_CALLS_OFTEN = 15
# for decoders called very often, limit threshold shortcut
DS_FUNCTION_SHORTCUT_THRESHOLD_VERY_OFTEN = 15

# Tight String (TS)
# max instruction count to emulate in a tight loop
TS_MAX_INSN_COUNT = 10000
# max basic blocks per tight function (that basically just wraps a tight loop)
TS_TIGHT_FUNCTION_MAX_BLOCKS = 10
