# Copyright 2017 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.


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
    ret_type, ret_name, call_conv, func_name, args = f.vw.getFunctionApi(int(f))

    return {
        "ret_type": ret_type,
        "ret_name": ret_name,
        "call_conv": call_conv,
        "func_name": func_name,
        "arguments": args,
    }


def get_function_meta(f):
    meta = f.vw.getFunctionMetaDict(int(f))

    return {
        "api": get_function_api(f),
        "size": meta.get("Size", 0),
        "block_count": meta.get("BlockCount", 0),
        "instruction_count": meta.get("InstructionCount", 0),
    }


def get_max_calls_to(vw, skip_thunks=True, skip_libs=True):
    calls_to = set()

    for fva in vw.getFunctions():
        if skip_thunks and is_thunk_function(vw, fva):
            continue

        # TODO skip_libs and is_library_function
        #     continue

        calls_to.add(len(vw.getXrefsTo(fva)))

    return max(calls_to)


def get_function_score_weighted(features):
    return round(sum(feature.weighted_score() for feature in features) / sum(feature.weight for feature in features), 3)


def get_top_functions(candidate_functions, count=20) -> List[Dict[int, Dict]]:
    return sorted(candidate_functions.items(), key=lambda x: operator.getitem(x[1], "score"), reverse=True)[:count]


def get_tight_function_fvas(decoding_function_features) -> List[int]:
    """return offsets of identified tight functions"""
    tight_function_fvas = list()
    for fva, function_data in decoding_function_features.items():
        if any(filter(lambda f: isinstance(f, TightFunction), function_data["features"])):
            tight_function_fvas.append(fva)
    return tight_function_fvas


def append_unique(fvas, fvas_to_append):
    for fva in fvas_to_append:
        if fva not in fvas:
            fvas.append(fva)
    return fvas


def get_function_fvas(functions) -> List[int]:
    return list(map(lambda p: p[0], functions))


def get_functions_with_tightloops(functions):
    return get_functions_with_features(
        functions, (floss.features.features.TightLoop, floss.features.features.KindaTightLoop)
    )


def get_functions_without_tightloops(functions):
    tloop_functions = get_functions_with_tightloops(functions)
    no_tloop_funcs = copy.copy(functions)
    for fva, _ in tloop_functions.items():
        del no_tloop_funcs[fva]
    return no_tloop_funcs


def get_functions_with_features(functions, features) -> Dict[int, List]:
    functions_by_features = dict()
    for fva, function_data in functions.items():
        func_features = list(filter(lambda f: isinstance(f, features), function_data["features"]))
        if func_features:
            functions_by_features[fva] = func_features
    return functions_by_features


def find_decoding_function_features(vw, functions, disable_progress=False) -> Tuple[Dict[int, Dict], Dict[int, str]]:
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
