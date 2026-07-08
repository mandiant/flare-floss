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

import gzip
import json
import logging
import pathlib
import sys

SCRIPTS_DIR = pathlib.Path(__file__).resolve().parent.parent / "scripts"
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

import build_oss_db  # noqa: E402


SAMPLE_DB_PATH = pathlib.Path(__file__).resolve().parent.parent / "floss" / "qs" / "db" / "data" / "oss"


def _capture_warnings(logger_name: str) -> list:
    """Attach a recording handler at WARNING level to the named logger.

    Returns a list that the caller can read after invoking the system under
    test. Each call installs an independent handler with its own list, so
    tests do not interfere with each other.
    """
    records: list = []
    handler = logging.Handler(level=logging.WARNING)

    def emit(record):
        records.append(record)

    handler.emit = emit  # type: ignore[assignment]
    logger = logging.getLogger(logger_name)
    logger.addHandler(handler)
    logger.setLevel(logging.WARNING)
    return records


def _row(path, function, feat_type, value):
    return json.dumps({"path": path, "function": function, "type": feat_type, "value": value})


# ---------------------------------------------------------------------------
# make_db_entry
# ---------------------------------------------------------------------------


def test_make_db_entry_uses_standard_schema():
    e = build_oss_db.make_db_entry("s", "lib", "1.0", "f.c", "fn")
    assert e == {
        "string": "s",
        "library_name": "lib",
        "library_version": "1.0",
        "file_path": "f.c",
        "function_name": "fn",
        "line_number": None,
    }


def test_make_db_entry_line_number_default_is_none():
    e = build_oss_db.make_db_entry("s", "lib", "1.0", "f.c", "fn")
    assert e["line_number"] is None


def test_make_db_entry_preserves_explicit_line_number():
    e = build_oss_db.make_db_entry("s", "lib", "1.0", "f.c", "fn", 42)
    assert e["line_number"] == 42


# ---------------------------------------------------------------------------
# Converter.parse: structure
# ---------------------------------------------------------------------------


def test_parse_returns_parse_result_with_expected_fields():
    jh = _row("a.c", "foo", "string", "hello")
    result = build_oss_db.Converter().parse(jh, "lib", "1.0")
    assert isinstance(result, build_oss_db.ParseResult)
    assert hasattr(result, "entries")
    assert hasattr(result, "num_objects")
    assert hasattr(result, "num_functions")


# ---------------------------------------------------------------------------
# Converter.parse: single-pass counts
# ---------------------------------------------------------------------------


def test_parse_counts_unique_objects_and_functions():
    # Three rows: two paths, two functions, with one duplicate row.
    jh = "\n".join(
        [
            _row("a.c", "foo", "string", "hello"),
            _row("a.c", "foo", "string", "world"),
            _row("b.c", "bar", "string", "baz"),
        ]
    )
    result = build_oss_db.Converter().parse(jh, "lib", "1.0")
    assert result.num_objects == 2
    assert result.num_functions == 2


def test_parse_counts_include_duplicate_rows():
    # Same row repeated should not inflate the unique counts.
    jh = "\n".join(
        [
            _row("a.c", "foo", "string", "hello"),
            _row("a.c", "foo", "string", "hello"),
        ]
    )
    result = build_oss_db.Converter().parse(jh, "lib", "1.0")
    assert result.num_objects == 1
    assert result.num_functions == 1


def test_parse_counts_exclude_rows_without_function():
    jh = "\n".join(
        [
            _row("a.c", "foo", "string", "hello"),
            _row("b.c", None, "string", "ignored"),
            _row("c.c", "", "string", "ignored"),
        ]
    )
    result = build_oss_db.Converter().parse(jh, "lib", "1.0")
    assert result.num_objects == 1
    assert result.num_functions == 1


def test_parse_counts_none_path_counts_as_an_object():
    # Rows with `path == None` are still attributed to an "object" (a None path),
    # matching the previous count_jsonl_rows behavior.
    jh = _row(None, "foo", "string", "hello")
    result = build_oss_db.Converter().parse(jh, "lib", "1.0")
    assert result.num_objects == 1
    assert result.num_functions == 1


# ---------------------------------------------------------------------------
# Converter.parse: entry list
# ---------------------------------------------------------------------------


def test_parse_emits_string_and_synthetic_function_name_entries():
    jh = "\n".join(
        [
            _row("a.c", "foo", "string", "hello"),
            _row("b.c", "bar", "string", "baz"),
        ]
    )
    result = build_oss_db.Converter().parse(jh, "lib", "1.0")
    strings = {e["string"] for e in result.entries}
    # Two real strings plus the two synthesized function-name entries.
    assert strings == {"hello", "baz", "foo", "bar"}
    # All entries carry the library/version passed in.
    for e in result.entries:
        assert e["library_name"] == "lib"
        assert e["library_version"] == "1.0"
        assert e["line_number"] is None


def test_parse_dedup_collapses_identical_strings_by_default():
    jh = "\n".join(
        [
            _row("a.c", "foo", "string", "hello"),
            _row("a.c", "foo", "string", "hello"),
        ]
    )
    result = build_oss_db.Converter().parse(jh, "lib", "1.0")
    assert sum(1 for e in result.entries if e["string"] == "hello") == 1


def test_parse_dedup_false_keeps_all_rows():
    jh = "\n".join(
        [
            _row("a.c", "foo", "string", "hello"),
            _row("a.c", "foo", "string", "hello"),
        ]
    )
    converter = build_oss_db.Converter(deduplicate=False)
    result = converter.parse(jh, "lib", "1.0")
    # 2 string rows + 1 synthetic function-name row for "foo"
    # (synthetic rows are deduped by their function_name, not affected by deduplicate).
    assert len(result.entries) == 3
    assert sum(1 for e in result.entries if e["string"] == "hello") == 2


def test_parse_dedup_false_keeps_all_function_name_rows():
    # Two distinct function_name rows on different functions, with deduplicate off,
    # should all be retained (no dedup of the synthetic entries either).
    jh = "\n".join(
        [
            _row("a.c", "foo", "string", "hello"),
            _row("a.c", "bar", "string", "world"),
        ]
    )
    converter = build_oss_db.Converter(deduplicate=False)
    result = converter.parse(jh, "lib", "1.0")
    # 2 string rows + 2 synthetic function-name rows (foo, bar)
    assert len(result.entries) == 4
    strings = sorted(e["string"] for e in result.entries)
    assert strings == ["bar", "foo", "hello", "world"]


def test_parse_emit_function_names_false_skips_synthetic_entries():
    jh = _row("a.c", "foo", "string", "hello")
    converter = build_oss_db.Converter(emit_function_names=False)
    result = converter.parse(jh, "lib", "1.0")
    assert len(result.entries) == 1
    assert result.entries[0]["string"] == "hello"
    assert result.num_functions == 1  # counts are still tracked


def test_parse_explicit_function_name_row_is_not_duplicated():
    jh = _row("a.c", "foo", "function_name", "fn_x")
    result = build_oss_db.Converter().parse(jh, "lib", "1.0")
    # The explicit function_name row should appear once, and "fn_x" should
    # NOT be re-emitted as a synthetic entry.
    fn_entries = [e for e in result.entries if e["string"] == "fn_x"]
    assert len(fn_entries) == 1
    assert fn_entries[0]["function_name"] == "fn_x"


# ---------------------------------------------------------------------------
# Converter.parse: error tolerance
# ---------------------------------------------------------------------------


def test_parse_skips_malformed_jsonl_lines():
    jh = "\n".join(
        [
            _row("a.c", "foo", "string", "hello"),
            "this is not json",
            _row("b.c", "bar", "string", "world"),
        ]
    )
    records = _capture_warnings("build_oss_db")
    converter = build_oss_db.Converter()
    result = converter.parse(jh, "lib", "1.0")
    # Counts still cover the well-formed rows.
    assert result.num_objects == 2
    assert result.num_functions == 2
    # A warning was logged for the bad line.
    assert any("malformed" in record.message.lower() for record in records)


def test_parse_skips_empty_lines():
    jh = "\n".join(
        [
            _row("a.c", "foo", "string", "hello"),
            "",
            "   ",
            _row("b.c", "bar", "string", "world"),
        ]
    )
    result = build_oss_db.Converter().parse(jh, "lib", "1.0")
    assert result.num_objects == 2
    assert result.num_functions == 2


# ---------------------------------------------------------------------------
# load_existing_entries
# ---------------------------------------------------------------------------


def _write_gz_jsonl(path: pathlib.Path, rows) -> None:
    """Write each row to a gzipped JSONL file, preserving its raw form.

    Pass dicts to be JSON-serialized, or pass pre-serialized strings to inject
    malformed/non-JSON content for negative-path tests.
    """
    with gzip.open(path, "wt", encoding="utf-8") as f:
        for row in rows:
            if isinstance(row, str):
                f.write(row + "\n")
            else:
                f.write(json.dumps(row) + "\n")


def test_load_existing_entries_round_trips_make_db_entry(tmp_path):
    path = tmp_path / "lib.jsonl.gz"
    entries = [
        build_oss_db.make_db_entry("s1", "lib", "1.0", "f.c", "fn"),
        build_oss_db.make_db_entry("s2", "lib", "1.0", None, None, 5),
    ]
    _write_gz_jsonl(path, entries)
    assert build_oss_db.load_existing_entries(path) == entries


def test_load_existing_entries_missing_file_returns_empty():
    path = pathlib.Path("/nonexistent/path/to/lib.jsonl.gz")
    assert build_oss_db.load_existing_entries(path) == []


def test_load_existing_entries_skips_malformed_lines(tmp_path):
    path = tmp_path / "lib.jsonl.gz"
    _write_gz_jsonl(
        path,
        [
            build_oss_db.make_db_entry("s1", "lib", "1.0", "f.c", "fn"),
            "this is not json",
            build_oss_db.make_db_entry("s2", "lib", "1.0", "f.c", "fn"),
        ],
    )
    records = _capture_warnings("build_oss_db")
    loaded = build_oss_db.load_existing_entries(path)
    assert len(loaded) == 2
    assert [e["string"] for e in loaded] == ["s1", "s2"]
    assert any("malformed" in record.message.lower() for record in records)


def test_load_existing_entries_skips_non_dict_and_missing_string(tmp_path):
    path = tmp_path / "lib.jsonl.gz"
    with gzip.open(path, "wt", encoding="utf-8") as f:
        f.write(json.dumps([1, 2, 3]) + "\n")  # non-dict
        f.write(json.dumps({"library_name": "lib"}) + "\n")  # missing "string"
        f.write(json.dumps({"string": "ok", "library_name": "lib"}) + "\n")
    loaded = build_oss_db.load_existing_entries(path)
    assert len(loaded) == 1
    assert loaded[0]["string"] == "ok"


def test_load_existing_entries_ignores_unknown_keys_and_fills_missing(tmp_path):
    path = tmp_path / "lib.jsonl.gz"
    _write_gz_jsonl(
        path,
        [
            {"string": "s", "library_name": "l", "extra_key": "ignored"},
        ],
    )
    loaded = build_oss_db.load_existing_entries(path)
    assert loaded == [
        {
            "string": "s",
            "library_name": "l",
            "library_version": None,
            "file_path": None,
            "function_name": None,
            "line_number": None,
        }
    ]


def test_load_existing_entries_handles_empty_file(tmp_path):
    path = tmp_path / "empty.jsonl.gz"
    path.write_bytes(b"")
    # Empty file is not valid gzip; load_existing_entries should warn and return [].
    assert build_oss_db.load_existing_entries(path) == []
