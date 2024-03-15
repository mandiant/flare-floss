# Copyright (C) 2017 Mandiant, Inc. All Rights Reserved.

import copy
import operator
import collections
from typing import Dict, List, Tuple, DefaultDict

import tqdm
import viv_utils
import viv_utils.flirt
from tqdm.contrib.logging import logging_redirect_tqdm

import floss.logging_
from floss.utils import is_thunk_function, redirecting_print_to_tqdm
from floss.features.extract import (
    abstract_features,
    extract_insn_features,
    extract_function_features,
    extract_basic_block_features,
)
from floss.features.features import Arguments, BlockCount, TightFunction, InstructionCount

logger = floss.logging_.getLogger(__name__)


def get_function_api(f):
    """
    Retrieves API metadata for a function using Vivisect.

    Queries the Vivisect workspace for information about a function's return type, name, calling convention, and arguments. 

    Args:
        f:  The function object (likely within a Vivisect workspace context).

    Returns:
        dict: A dictionary containing the extracted API metadata:
            *   ret_type: The function's return type.
            *   ret_name: The name of the return value (if any).
            *   call_conv:  The function's calling convention.
            *   func_name: The function's name.
            *   arguments: A list of argument descriptions. 
    """
    ret_type, ret_name, call_conv, func_name, args = f.vw.getFunctionApi(int(f))

    return {
        "ret_type": ret_type,
        "ret_name": ret_name,
        "call_conv": call_conv,
        "func_name": func_name,
        "arguments": args,
    }


def get_function_meta(f):
    """
    Retrieves metadata for a function using Vivisect.

    Queries the Vivisect workspace for information about a function's size, block count, and instruction count.

    Args:
        f: The function object (likely within a Vivisect workspace context).

    Returns:
        dict: A dictionary containing the extracted metadata:
            *   size: The function's size in bytes.
            *   block_count: The number of basic blocks in the function.
            *   instruction_count: The number of instructions in the function.

    """
    meta = f.vw.getFunctionMetaDict(int(f))

    return {
        "api": get_function_api(f),
        "size": meta.get("Size", 0),
        "block_count": meta.get("BlockCount", 0),
        "instruction_count": meta.get("InstructionCount", 0),
    }


def get_max_calls_to(vw, skip_thunks=True, skip_libs=True):
    """
    Retrieves the maximum number of calls to a function in a Vivisect workspace.

    Args:
        vw: The Vivisect workspace.
        skip_thunks: Whether to skip thunk functions.
        skip_libs: Whether to skip library functions.

    Returns:
        int: The maximum number of calls to a function in the workspace.

    """
    calls_to = set()

    for fva in vw.getFunctions():
        if skip_thunks and is_thunk_function(vw, fva):
            continue

        # TODO skip_libs and is_library_function
        #     continue

        calls_to.add(len(vw.getXrefsTo(fva)))

    return max(calls_to)


def get_function_score_weighted(features):
    """
    Calculates a weighted score for a function based on its features.

    Args:
        features: The features of the function.

    Returns:
        float: The weighted score of the function.

    """
    return round(sum(feature.weighted_score() for feature in features) / sum(feature.weight for feature in features), 3)


def get_top_functions(candidate_functions, count=20) -> List[Dict[int, Dict]]:
    """
    Retrieves the top scoring functions from a set of candidate functions.

    Args:
        candidate_functions: A dictionary of candidate functions and their scores.
        count: The number of top functions to retrieve.

    Returns:
        List[Dict[int, Dict]]: A list of the top scoring functions.

    """
    return sorted(candidate_functions.items(), key=lambda x: operator.getitem(x[1], "score"), reverse=True)[:count]


def get_tight_function_fvas(decoding_function_features) -> List[int]:
    """
    Retrieves the function virtual addresses of functions with tight loops. 

    Args:
        decoding_function_features: A dictionary of decoding function features.

    Returns:
        List[int]: A list of function virtual addresses.
    """
    tight_function_fvas = list()
    for fva, function_data in decoding_function_features.items():
        if any(filter(lambda f: isinstance(f, TightFunction), function_data["features"])):
            tight_function_fvas.append(fva)
    return tight_function_fvas


def append_unique(fvas, fvas_to_append):
    """
    Appends unique function virtual addresses to a list.

    Args:
        fvas: The list of function virtual addresses.
        fvas_to_append: The list of function virtual addresses to append.

    Returns:
        List[int]: The updated list of function virtual addresses.

    """
    for fva in fvas_to_append:
        if fva not in fvas:
            fvas.append(fva)
    return fvas


def get_function_fvas(functions) -> List[int]:
    """
    Retrieves the function virtual addresses from a dictionary of functions.

    Args:
        functions: A dictionary of functions.

    Returns:
        List[int]: A list of function virtual addresses.

    """
    return list(map(lambda p: p[0], functions))


def get_functions_with_tightloops(functions):
    """
    Retrieves functions with tight loops from a dictionary of functions.

    Args:
        functions: A dictionary of functions.

    Returns:
        Dict[int, List]: A dictionary of functions with tight loops.  

    """
    return get_functions_with_features(
        functions, (floss.features.features.TightLoop, floss.features.features.KindaTightLoop)
    )


def get_functions_without_tightloops(functions):
    """
    Retrieves functions without tight loops from a dictionary of functions.

    Args:
        functions: A dictionary of functions.

    Returns:
        Dict[int, List]: A dictionary of functions without tight loops.
    """
    tloop_functions = get_functions_with_tightloops(functions)
    no_tloop_funcs = copy.copy(functions)
    for fva, _ in tloop_functions.items():
        del no_tloop_funcs[fva]
    return no_tloop_funcs


def get_functions_with_features(functions, features) -> Dict[int, List]:
    """
    Retrieves functions with specified features from a dictionary of functions.

    Args:
        functions: A dictionary of functions.
        features: The features to search for.

    Returns:
        Dict[int, List]: A dictionary of functions with specified features.

    """
    functions_by_features = dict()
    for fva, function_data in functions.items():
        func_features = list(filter(lambda f: isinstance(f, features), function_data["features"]))
        if func_features:
            functions_by_features[fva] = func_features
    return functions_by_features


def find_decoding_function_features(vw, functions, disable_progress=False) -> Tuple[Dict[int, Dict], Dict[int, str]]:
    """
    Identifies decoding function features from a set of functions.

    Args:
        vw: The Vivisect workspace.
        functions: The set of functions to analyze.
        disable_progress: Whether to disable progress output.

    Returns:
        Tuple[Dict[int, Dict], Dict[int, str]]: A tuple containing the decoding function features and library functions.

    """
    decoding_candidate_functions: DefaultDict[int, Dict] = collections.defaultdict(dict)

    library_functions: Dict[int, str] = dict()

    pbar = tqdm.tqdm
    if disable_progress:
        logger.info("identifying decoding function features...")
        # do not use tqdm to avoid unnecessary side effects when caller intends
        # to disable progress completely
        pbar = lambda s, *args, **kwargs: s

    functions = sorted(functions)
    n_funcs = len(functions)

    pb = pbar(
        functions, desc="finding decoding function features", unit=" functions", postfix="skipped 0 library functions"
    )
    with logging_redirect_tqdm(), redirecting_print_to_tqdm():
        for f in pb:
            function_address = int(f)

            if is_thunk_function(vw, function_address):
                continue

            if viv_utils.flirt.is_library_function(vw, function_address):
                # TODO handle j_j_j__free_base (lib function wrappers), e.g. 0x140035AF0 in d2ca76...
                # TODO ignore function called to by library functions
                function_name = viv_utils.get_function_name(vw, function_address)
                logger.debug("skipping library function 0x%x (%s)", function_address, function_name)
                library_functions[function_address] = function_name
                n_libs = len(library_functions)
                percentage = 100 * (n_libs / n_funcs)
                if isinstance(pb, tqdm.tqdm):
                    pb.set_postfix_str("skipped %d library functions (%d%%)" % (n_libs, percentage))
                continue

            f = viv_utils.Function(vw, function_address)

            function_data = {
                "meta": get_function_meta(f),
                "features": [],
                "xrefs_to": len(list(vw.getXrefsTo(function_address))),
            }

            # meta data features
            function_data["features"].append(BlockCount(function_data["meta"].get("block_count")))
            function_data["features"].append(InstructionCount(function_data["meta"].get("instruction_count")))
            function_data["features"].append(Arguments(function_data["meta"].get("api", []).get("arguments")))

            for feature in extract_function_features(f):
                function_data["features"].append(feature)

            for bb in f.basic_blocks:
                for feature in extract_basic_block_features(f, bb):
                    function_data["features"].append(feature)

                for insn in bb.instructions:
                    for feature in extract_insn_features(f, bb, insn):
                        function_data["features"].append(feature)

            for feature in abstract_features(function_data["features"]):
                function_data["features"].append(feature)

            function_data["score"] = get_function_score_weighted(function_data["features"])

            logger.debug("analyzed function 0x%x - total score: %.3f", function_address, function_data["score"])
            for feat in function_data["features"]:
                logger.trace("  %s", feat)

            decoding_candidate_functions[function_address] = function_data

        return decoding_candidate_functions, library_functions
