# Copyright 2026 Google LLC
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


import struct
import logging
from bisect import bisect_left
from typing import Dict, List, Tuple, Iterable

import floss.utils
from floss.results import StaticString
from floss.language.elf import ELF
from floss.language.utils import StructString

logger = logging.getLogger(__name__)

MAX_STRING_LEN = 1024 * 1024
MAX_RUNS_TO_TRY = 8
MAX_ANCHOR_ATTEMPTS_PER_RUN = 64


def find_longest_monotonically_increasing_run(values: List[int]) -> Tuple[int, int]:
    """
    for the given sorted list of values,
    find the (start, end) indices of the longest run of values
    such that each value is greater than or equal to the previous value.
    """
    max_run_length = 0
    max_run_end_index = 0

    current_run_length = 0
    prior_value = 0

    for i, value in enumerate(values):
        if value >= prior_value:
            current_run_length += 1
        else:
            current_run_length = 1

        if current_run_length > max_run_length:
            max_run_length = current_run_length
            max_run_end_index = i

        prior_value = value

    max_run_start_index = max_run_end_index - max_run_length + 1

    return max_run_start_index, max_run_end_index


def _is_va_in_readable_segments(view: ELF, va: int) -> bool:
    for segment in view.iter_readable_segments():
        if segment.vaddr_start <= va < segment.vaddr_end:
            return True
    return False


def _is_va_in_readonly_segments(view: ELF, va: int) -> bool:
    for segment in view.iter_readonly_segments():
        if segment.vaddr_start <= va < segment.vaddr_end:
            return True
    return False


def get_struct_string_candidates_elf(view: ELF, min_length: int = 1) -> Iterable[Tuple[StructString, int]]:
    """
    Find candidate struct String instances in the given elf file
    """
    for segment in view.iter_readonly_segments():
        data = view.data[segment.file_off : segment.file_end]
        # check segment data len (8 bytes for pointer,8 for len)
        if len(data) < 16:
            continue

        for offset in range(0, len(data) - 16 + 1, 8):
            struct_va = segment.vaddr_start + offset
            ptr = struct.unpack_from("<Q", data, offset)[0]
            length = struct.unpack_from("<Q", data, offset + 8)[0]

            if ptr == 0 or length == 0:
                continue
            if length < min_length:
                continue
            if length > MAX_STRING_LEN:
                continue
            if not _is_va_in_readable_segments(view, ptr):
                continue
            if not _is_va_in_readable_segments(view, ptr + length - 1):
                continue

            yield StructString(struct_va, length), ptr


def read_struct_string_elf(view: ELF, ptr: int, instance: StructString) -> str:
    """
    Read the string for the given struct String instance,
    validating that it looks like UTF-8
    """
    buf = view.read_va(ptr, instance.length + 1)
    instance_data = buf[: instance.length]
    next_byte = buf[instance.length]

    try:
        s = instance_data.decode("utf-8")
    except UnicodeDecodeError:
        raise ValueError("struct string instance does not contain valid UTF-8")

    if s.encode("utf-8") != instance_data:
        raise ValueError("struct string length incorrect")

    if next_byte == 0x00:
        raise ValueError("struct string is NULL terminated")

    return s


def _find_segment_for_va(view: ELF, va: int):
    for segment in view.iter_load_segments():
        if segment.vaddr_start <= va < segment.vaddr_end:
            return segment
    return None


def _get_monotonic_runs(values: List[int]) -> List[Tuple[int, int]]:
    if not values:
        return []

    runs: List[Tuple[int, int]] = []
    run_start = 0
    prior_value = values[0]

    for i, value in enumerate(values[1:], start=1):
        if value < prior_value:
            runs.append((run_start, i - 1))
            run_start = i
        prior_value = value

    runs.append((run_start, len(values) - 1))
    # longest runs are prioritized
    runs.sort(key=lambda run: run[1] - run[0] + 1, reverse=True)
    return runs


def _iter_anchor_indices(run_start: int, run_end: int) -> Iterable[int]:
    """
    Sometimes the midpoint candidate is invalid (not UTF-8 or not a real Go string)
    by trying nearby candidates, FLOSS can recover and find a valid blob anchor
    """
    run_mid = (run_start + run_end) // 2
    yield run_mid

    for delta in range(1, run_end - run_start + 1):
        left = run_mid - delta
        right = run_mid + delta

        if left >= run_start:
            yield left
        if right <= run_end:
            yield right


def _find_blob_range_from_anchor(view: ELF, ptr: int) -> Tuple[int, int]:
    segment = _find_segment_for_va(view, ptr)
    if segment is None:
        raise ValueError("string data pointer is not in a load segment")

    segment_data = view.data[segment.file_off : segment.file_end]
    instance_offset = ptr - segment.vaddr_start

    next_null = segment_data.find(b"\x00\x00\x00\x00", instance_offset)
    assert next_null != -1

    prev_null = segment_data.rfind(b"\x00\x00\x00\x00", 0, instance_offset)
    assert prev_null != -1

    blob_start = segment.vaddr_start + prev_null
    blob_end = segment.vaddr_start + next_null
    logger.debug("string blob: [0x%x-0x%x]", blob_start, blob_end)
    return blob_start, blob_end


def find_string_blob_range_elf(
    view: ELF, struct_strings: List[StructString], ptrs_by_struct_va: Dict[int, int]
) -> Tuple[int, int]:
    """
    Find the range of the string blob, as loaded in memory.
    This is an improvement from the PE version as ELF Go binaries are
    less uniform across versions so one run/one midpoint is less reliable
    This one:
    - builds all monotic runs,sorts by length and tries several
    - tries many anchor points around midpoint
    - scores blobs
    """
    if not struct_strings:
        raise ValueError("no struct string candidates")

    struct_strings.sort(key=lambda s: s.address)

    # no need to compute the single longest monotonic run
    # here we compute all monotonic runs
    lengths = list(map(lambda s: s.length, struct_strings))
    runs = _get_monotonic_runs(lengths)

    if not runs:
        raise ValueError("failed to find monotonic runs")

    sorted_ptrs = sorted(ptrs_by_struct_va.values())

    def score_blob_range(blob_start: int, blob_end: int) -> Tuple[int, int]:
        # a good candidate range contains many pointers and has reasonable size
        if blob_end <= blob_start:
            return (0, 0)

        # num of pointers in the blob range
        count = bisect_left(sorted_ptrs, blob_end) - bisect_left(sorted_ptrs, blob_start)
        return count, blob_end - blob_start

    # if no valid range is found , this is raised
    first_error: ValueError | None = None
    best_blob_range: Tuple[int, int] | None = None
    best_score = (0, 0)

    # iterate over monotonic runs
    for run_start, run_end in runs[:MAX_RUNS_TO_TRY]:
        readonly_anchor_indices: List[int] = []
        readable_anchor_indices: List[int] = []

        for i in _iter_anchor_indices(run_start, run_end):
            instance = struct_strings[i]
            ptr = ptrs_by_struct_va.get(instance.address)
            if ptr is None:
                continue

            if _is_va_in_readonly_segments(view, ptr):
                readonly_anchor_indices.append(i)
            else:
                readable_anchor_indices.append(i)

        attempts = 0
        # iterate over anchor points
        for i in readonly_anchor_indices + readable_anchor_indices:
            if attempts >= MAX_ANCHOR_ATTEMPTS_PER_RUN:
                break
            attempts += 1

            instance = struct_strings[i]
            ptr = ptrs_by_struct_va.get(instance.address)
            if ptr is None:
                continue

            try:
                # validate and score anchors
                s = read_struct_string_elf(view, ptr, instance)
                logger.debug("string blob: struct string instance: 0x%x: %s...", instance.address, s[:16])
                blob_start, blob_end = _find_blob_range_from_anchor(view, ptr)
                score = score_blob_range(blob_start, blob_end)
                # track the best blob range
                if score > best_score:
                    best_score = score
                    best_blob_range = (blob_start, blob_end)
            except ValueError as exc:
                if first_error is None:
                    first_error = exc

    if best_blob_range is not None:
        logger.debug(
            "string blob: selected best ELF blob range [0x%x-0x%x], score=(%d pointers, %d bytes)",
            best_blob_range[0],
            best_blob_range[1],
            best_score[0],
            best_score[1],
        )
        return best_blob_range

    if first_error is not None:
        raise first_error

    raise ValueError("failed to find valid string blob anchor")


def get_string_blob_strings_elf(view: ELF, min_length: int) -> Iterable[StaticString]:
    """
    For the given ELF file compiled by Go,
    find the string blob and then extract strings from it.
    """

    with floss.utils.timing("find struct string candidates"):
        deduped_candidates: Dict[int, Tuple[StructString, int]] = {}
        for struct_string, ptr in get_struct_string_candidates_elf(view):
            deduped_candidates.setdefault(struct_string.address, (struct_string, ptr))

        struct_string_candidates = list(sorted(deduped_candidates.values(), key=lambda candidate: candidate[0].address))
        struct_strings = [struct_string for struct_string, _ in struct_string_candidates]
        ptrs_by_struct_va = {struct_string.address: ptr for struct_string, ptr in struct_string_candidates}

        if not struct_strings:
            logger.warning(
                "Failed to find struct string candidates: Is this a Go binary? If so, the Go version may be unsupported."
            )
            return

    with floss.utils.timing("find string blob"):
        try:
            string_blob_start, string_blob_end = find_string_blob_range_elf(view, struct_strings, ptrs_by_struct_va)
        except ValueError:
            logger.warning(
                "Failed to find string blob range: Is this a Go binary? If so, the Go version may be unsupported."
            )
            return

    with floss.utils.timing("collect string blob strings"):
        string_blob_size = string_blob_end - string_blob_start
        string_blob_buf = view.read_va(string_blob_start, string_blob_size)

        string_blob_pointers: List[int] = []

        for instance in struct_strings:
            ptr = ptrs_by_struct_va.get(instance.address)
            if ptr is None:
                continue

            if not (string_blob_start <= ptr < string_blob_end):
                continue

            string_blob_pointers.append(ptr)

        if not string_blob_pointers:
            return

        last_size = 0
        string_blob_pointers = list(sorted(set(string_blob_pointers)))
        for start, end in zip(string_blob_pointers, string_blob_pointers[1:]):
            assert string_blob_start <= start < string_blob_end
            assert string_blob_start <= end < string_blob_end

            size = end - start
            string_blob_offset = start - string_blob_start
            sbuf = string_blob_buf[string_blob_offset : string_blob_offset + size]

            try:
                s = sbuf.decode("utf-8")
            except UnicodeDecodeError:
                continue

            if not s:
                continue

            if last_size > len(s):
                logger.warning("probably missed a string blob string ending at: 0x%x", start - 1)

            try:
                string = StaticString.from_utf8(sbuf, view.va_to_file_offset(start), min_length)
                yield string
            except ValueError:
                pass

            last_size = len(s)

        last_pointer = string_blob_pointers[-1]
        last_pointer_offset = last_pointer - string_blob_start
        last_buf = string_blob_buf[last_pointer_offset:]
        for size in range(len(last_buf), 0, -1):
            try:
                _ = last_buf[:size].decode("utf-8")
            except UnicodeDecodeError:
                continue
            else:
                try:
                    string = StaticString.from_utf8(last_buf[:size], view.va_to_file_offset(last_pointer), min_length)
                    yield string
                except ValueError:
                    pass
                break


def extract_go_strings_elf(sample, min_length: int) -> List[StaticString]:
    """
    Extract Go strings from the given ELF file.
    """
    view = ELF(sample)
    return list(get_string_blob_strings_elf(view, min_length))


def get_static_strings_from_blob_range_elf(sample, static_strings: List[StaticString]) -> List[StaticString]:
    view = ELF(sample)

    deduped_candidates: Dict[int, Tuple[StructString, int]] = {}
    for struct_string, ptr in get_struct_string_candidates_elf(view):
        deduped_candidates.setdefault(struct_string.address, (struct_string, ptr))

    struct_string_candidates = list(sorted(deduped_candidates.values(), key=lambda candidate: candidate[0].address))
    struct_strings = [struct_string for struct_string, _ in struct_string_candidates]
    ptrs_by_struct_va = {struct_string.address: ptr for struct_string, ptr in struct_string_candidates}

    if not struct_strings:
        return []

    try:
        string_blob_start, string_blob_end = find_string_blob_range_elf(view, struct_strings, ptrs_by_struct_va)
    except ValueError:
        return []

    string_blob_start = view.va_to_file_offset(string_blob_start)
    string_blob_end = view.va_to_file_offset(string_blob_end)

    return list(filter(lambda s: string_blob_start <= s.offset < string_blob_end, static_strings))
