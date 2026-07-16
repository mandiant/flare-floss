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

import scripts.tags.build_oss_db as build_oss_db

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


# ---------------------------------------------------------------------------
# merge_entries
# ---------------------------------------------------------------------------


def _entry(string, library="lib", version="1.0", function_name="fn"):
    return build_oss_db.make_db_entry(string, library, version, "f.c", function_name)


def test_merge_entries_new_wins_on_collision_when_dedup():
    new = [_entry("hello", version="2.0"), _entry("world", version="2.0")]
    existing = [_entry("hello", version="1.0"), _entry("other", version="1.0")]
    merged = build_oss_db.merge_entries(new, existing, deduplicate=True)

    by_string = {e["string"]: e for e in merged}
    # New "hello" wins (version 2.0), "world" is new, "other" is from existing.
    assert by_string["hello"]["library_version"] == "2.0"
    assert by_string["world"]["library_version"] == "2.0"
    assert by_string["other"]["library_version"] == "1.0"
    assert len(merged) == 3


def test_merge_entries_dedup_false_keeps_duplicates():
    new = [_entry("hello"), _entry("world")]
    existing = [_entry("hello"), _entry("other")]
    merged = build_oss_db.merge_entries(new, existing, deduplicate=False)
    # All four rows preserved. Without dedup the function concatenates
    # existing first, then new; the order is purely cosmetic (the loader
    # indexes by string).
    assert [e["string"] for e in merged] == ["hello", "other", "hello", "world"]


def test_merge_entries_both_empty_returns_empty():
    assert build_oss_db.merge_entries([], [], deduplicate=True) == []
    assert build_oss_db.merge_entries([], [], deduplicate=False) == []


def test_merge_entries_only_new_returns_copy_of_new():
    new = [_entry("a"), _entry("b")]
    result = build_oss_db.merge_entries(new, [], deduplicate=True)
    assert result == new
    assert result is not new  # callers rely on a fresh list


def test_merge_entries_only_existing_returns_copy_of_existing():
    existing = [_entry("a"), _entry("b")]
    result = build_oss_db.merge_entries([], existing, deduplicate=True)
    assert result == existing
    assert result is not existing


# ---------------------------------------------------------------------------
# main() orchestration
# ---------------------------------------------------------------------------


class _FakeVcpkg:
    """Stand-in for Vcpkg: records the install calls but does nothing."""

    def __init__(self, *args, **kwargs):
        self.installed = []

    def install(self, library, triplet):
        self.installed.append((library, triplet))

    def get_installed_version(self, library, triplet):
        return "1.0#1"

    def find_package_libs(self, library, triplet):
        return []


class _FakeJH:
    def __init__(self, *args, **kwargs):
        pass


def _stub_build_library(library, config, vcpkg, jh, converter):
    """Replacement for build_library that returns the library's name as its only entry."""
    metrics = build_oss_db.LibraryMetrics(
        library=library,
        version="1.0#1",
        triplet=config.triplet,
        num_objects=0,
        num_functions=0,
        num_raw_entries=1,
        total_entries=1,
        duration_seconds=0.0,
    )
    entry = build_oss_db.make_db_entry(
        f"hello-from-{library}",
        library,
        "1.0#1",
        "f.c",
        f"fn_{library}",
    )
    return metrics, [entry]


def _make_config(output_dir, libraries, *, continue_on_error=False):
    return build_oss_db.BuildConfig(
        triplet="x64-windows-static",
        compiler="msvc143",
        profile="release",
        libraries=list(libraries),
        output_dir=output_dir,
        vcpkg_root=None,
        jh_path=None,
        lancelot_dir=None,
        emit_function_names=True,
        deduplicate=True,
        continue_on_error=continue_on_error,
    )


def _invoke_run_build(
    output_dir, libraries, *, continue_on_error=False, existing=None, build_library_fn=_stub_build_library
):
    """Invoke run_build() with build_library stubbed to return one entry per library.

    ``existing`` is a dict of {library_name: [entry, ...]} to write to the
    output dir as if they were previously built.
    """
    config = _make_config(output_dir, libraries, continue_on_error=continue_on_error)

    if existing:
        for lib, entries in existing.items():
            path = output_dir / f"{lib}.jsonl.gz"
            with gzip.open(path, "wt", encoding="utf-8") as f:
                for e in entries:
                    f.write(json.dumps(e) + "\n")

    return build_oss_db.run_build(
        config,
        _FakeVcpkg(),  # type: ignore[arg-type]
        _FakeJH(),  # type: ignore[arg-type]
        build_oss_db.Converter(),
        build_library_fn=build_library_fn,
    )


def _read_gz_jsonl(path: pathlib.Path):
    with gzip.open(path, "rt", encoding="utf-8") as f:
        return [json.loads(line) for line in f if line.strip()]


def test_main_writes_one_database_per_library(tmp_path):
    rc = _invoke_run_build(tmp_path, ["zlib", "curl"])
    assert rc == 0
    for lib in ("zlib", "curl"):
        entries = _read_gz_jsonl(tmp_path / f"{lib}.jsonl.gz")
        assert len(entries) == 1
        assert entries[0]["string"] == f"hello-from-{lib}"
        assert entries[0]["library_name"] == lib


def test_main_merges_existing_database_with_fresh_entries(tmp_path):
    existing_entry = build_oss_db.make_db_entry("old-string", "zlib", "0.9#1", "f.c", "old_fn")
    rc = _invoke_run_build(
        tmp_path,
        ["zlib"],
        existing={"zlib": [existing_entry]},
    )
    assert rc == 0
    entries = _read_gz_jsonl(tmp_path / "zlib.jsonl.gz")
    strings = {e["string"] for e in entries}
    # Old entry from disk is preserved; new entry from the stubbed build is added.
    assert strings == {"old-string", "hello-from-zlib"}


def test_main_preserves_existing_libraries_not_in_current_run(tmp_path):
    # Pre-existing database for a library we are NOT rebuilding this run.
    preexisting = [build_oss_db.make_db_entry("preexisting", "other", "1.0", "f.c", "fn")]
    rc = _invoke_run_build(
        tmp_path,
        ["zlib"],
        existing={"other": preexisting},
    )
    assert rc == 0
    # "other" database was not rewritten; its content is unchanged.
    entries = _read_gz_jsonl(tmp_path / "other.jsonl.gz")
    assert entries == preexisting
    # "zlib" was rebuilt.
    zlib_entries = _read_gz_jsonl(tmp_path / "zlib.jsonl.gz")
    assert {e["string"] for e in zlib_entries} == {"hello-from-zlib"}


def test_main_exits_zero_on_partial_success_with_continue_on_error(tmp_path):
    def stub_partial(library, config, vcpkg, jh, converter):
        if library == "broken":
            metrics = build_oss_db.LibraryMetrics(
                library=library,
                version="unknown",
                triplet=config.triplet,
                error="boom",
            )
            return metrics, []
        return _stub_build_library(library, config, vcpkg, jh, converter)

    rc = _invoke_run_build(
        tmp_path,
        ["zlib", "broken"],
        continue_on_error=True,
        build_library_fn=stub_partial,
    )
    # At least one library succeeded, so the workflow should see a green step.
    assert rc == 0
    # The successful library's database was still written.
    zlib_entries = _read_gz_jsonl(tmp_path / "zlib.jsonl.gz")
    assert {e["string"] for e in zlib_entries} == {"hello-from-zlib"}


def test_main_exits_nonzero_when_all_libraries_fail_with_continue_on_error(tmp_path):
    def stub_all_fail(library, config, vcpkg, jh, converter):
        metrics = build_oss_db.LibraryMetrics(
            library=library,
            version="unknown",
            triplet=config.triplet,
            error="boom",
        )
        return metrics, []

    rc = _invoke_run_build(
        tmp_path,
        ["broken1", "broken2"],
        continue_on_error=True,
        build_library_fn=stub_all_fail,
    )
    # Everything failed, even with --continue-on-error: must exit non-zero so
    # the CI step doesn't silently go green on a total pipeline failure.
    assert rc == 1


def test_main_exits_nonzero_on_any_failure_without_continue_on_error(tmp_path):
    def stub_one_fail(library, config, vcpkg, jh, converter):
        if library == "broken":
            metrics = build_oss_db.LibraryMetrics(
                library=library,
                version="unknown",
                triplet=config.triplet,
                error="boom",
            )
            return metrics, []
        return _stub_build_library(library, config, vcpkg, jh, converter)

    rc = _invoke_run_build(
        tmp_path,
        ["zlib", "broken"],
        build_library_fn=stub_one_fail,
    )
    assert rc == 1


def test_main_writes_build_metrics_summary(tmp_path):
    rc = _invoke_run_build(tmp_path, ["zlib", "curl"])
    assert rc == 0
    summary = json.loads((tmp_path / "build_metrics.json").read_text())
    assert summary["triplet"] == "x64-windows-static"
    assert summary["compiler"] == "msvc143"
    assert summary["profile"] == "release"
    assert summary["successful"] == 2
    assert summary["failed"] == 0
    names = {m["library"] for m in summary["libraries"]}
    assert names == {"zlib", "curl"}


def test_diff_library_entries_added_removed_and_changed():
    old = [
        build_oss_db.make_db_entry("keep", "zlib", "1.0", "a.c", "fn_a"),
        build_oss_db.make_db_entry("gone", "zlib", "1.0", "b.c", "fn_b"),
        build_oss_db.make_db_entry("meta", "zlib", "1.0", "c.c", "old_fn"),
    ]
    new = [
        build_oss_db.make_db_entry("keep", "zlib", "1.0", "a.c", "fn_a"),
        build_oss_db.make_db_entry("fresh", "zlib", "2.0", "d.c", "fn_d"),
        build_oss_db.make_db_entry("meta", "zlib", "2.0", "c.c", "new_fn"),
    ]
    diff = build_oss_db.diff_library_entries("zlib", old, new)
    assert diff.library == "zlib"
    assert diff.old_count == 3
    assert diff.new_count == 3
    assert {e["string"] for e in diff.added} == {"fresh"}
    assert {e["string"] for e in diff.removed} == {"gone"}
    assert len(diff.changed) == 1
    assert diff.changed[0][0]["string"] == "meta"
    assert diff.changed[0][1]["function_name"] == "new_fn"
    assert diff.has_changes


def test_diff_library_entries_no_changes():
    entries = [build_oss_db.make_db_entry("s", "zlib", "1.0", "f.c", "fn")]
    diff = build_oss_db.diff_library_entries("zlib", entries, list(entries))
    assert not diff.has_changes
    assert diff.added == []
    assert diff.removed == []
    assert diff.changed == []


def test_format_build_diff_truncates_per_library():
    added = [build_oss_db.make_db_entry(f"s{i}", "zlib", "1.0", "f.c", "fn") for i in range(50)]
    diff = build_oss_db.LibraryDiff(
        library="zlib",
        old_count=0,
        new_count=50,
        added=added,
        removed=[],
        changed=[],
    )
    text = build_oss_db.format_build_diff([diff], max_lines_per_library=10)
    lines = text.splitlines()
    # Header for the library + 10 body lines + truncation notice.
    assert any(line.startswith("## zlib") for line in lines)
    body_lines = [line for line in lines if line.startswith(("+ ", "- ", "~ "))]
    assert len(body_lines) == 10
    assert any("truncated" in line and "zlib" in line for line in lines)
    assert "more line(s) omitted" in text


def test_format_build_diff_truncates_each_library_independently():
    text = build_oss_db.format_build_diff(
        [_lib_diff("zlib", 30), _lib_diff("curl", 30)],
        max_lines_per_library=5,
    )
    for lib in ("zlib", "curl"):
        body = [line for line in text.splitlines() if line.startswith("+ ") and lib in line]
        # Body lines are "+ zlib-0" etc.; count lines for that library.
        assert len(body) == 5
        assert f"omitted for {lib}" in text


def test_format_build_diff_markdown_reserves_actual_omission_footer_size():
    keep = build_oss_db.LibraryDiff(
        library="keep",
        old_count=0,
        new_count=1,
        added=[build_oss_db.make_db_entry("keep-string", "keep", "1.0", "f.c", "fn")],
        removed=[],
        changed=[],
    )
    omitted_name = "lib-" + ("x" * 180)
    omitted = build_oss_db.LibraryDiff(
        library=omitted_name,
        old_count=0,
        new_count=1,
        added=[build_oss_db.make_db_entry("omit-string", omitted_name, "1.0", "f.c", "fn")],
        removed=[],
        changed=[],
    )
    keep_text = build_oss_db.format_build_diff_markdown([keep], max_lines_per_library=5, max_chars=10_000)
    footer = build_oss_db._omission_footer([omitted_name])
    text = build_oss_db.format_build_diff_markdown(
        [keep, omitted],
        max_lines_per_library=5,
        max_chars=len(keep_text) + len(footer),
    )

    assert len(text) <= len(keep_text) + len(footer)
    assert "## keep" in text
    assert omitted_name in text
    assert "```diff" in text
    assert text.count("```") % 2 == 0


def _lib_diff(name: str, n: int) -> build_oss_db.LibraryDiff:
    added = [build_oss_db.make_db_entry(f"{name}-{i}", name, "1.0", "f.c", "fn") for i in range(n)]
    return build_oss_db.LibraryDiff(
        library=name,
        old_count=0,
        new_count=n,
        added=added,
        removed=[],
        changed=[],
    )


def test_format_build_diff_markdown_heads_outside_fences():
    text = build_oss_db.format_build_diff_markdown(
        [_lib_diff("zlib", 25), _lib_diff("curl", 25)],
        max_lines_per_library=5,
    )
    # Headings are markdown, not inside the fenced blocks.
    assert "## zlib" in text
    assert "## curl" in text
    assert text.count("```diff") == 2
    assert text.count("```") == 4  # open + close per library

    # Each ```diff ... ``` block should not contain a ## heading.
    for part in text.split("```"):
        if part.startswith("diff"):
            assert "## " not in part
            body_lines = [line for line in part.splitlines() if line.startswith(("+ ", "- ", "~ "))]
            assert len(body_lines) == 5


def test_format_build_diff_markdown_never_exceeds_github_limit_constant():
    # Stress: 80 libraries x 20 long lines — must still stay under DIFF_PR_MAX_CHARS.
    long = "x" * 200
    diffs = []
    for i in range(80):
        added = [build_oss_db.make_db_entry(f"{long}-{j}", f"lib{i}", "1.0", "f.c", "fn") for j in range(30)]
        diffs.append(
            build_oss_db.LibraryDiff(
                library=f"lib{i}",
                old_count=0,
                new_count=30,
                added=added,
                removed=[],
                changed=[],
            )
        )
    text = build_oss_db.format_build_diff_markdown(diffs)
    assert len(text) <= build_oss_db.DIFF_PR_MAX_CHARS


def test_clip_to_max_chars_closes_unclosed_code_fence():
    text = "Before\n```diff\n+ " + ("x" * 100)
    clipped = build_oss_db._clip_to_max_chars(text, 80)

    assert len(clipped) <= 80
    assert clipped.count("```") % 2 == 0
    assert clipped.endswith("... truncated to stay under GitHub's PR body length limit.\n")


def test_clip_to_max_chars_omits_fence_when_its_closing_fence_does_not_fit():
    notice = "\n... truncated to stay under GitHub's PR body length limit.\n"
    clipped = build_oss_db._clip_to_max_chars("```diff" + ("x" * 100), len(notice) + 3)

    assert len(clipped) <= len(notice) + 3
    assert clipped.count("```") % 2 == 0


def test_format_build_diff_empty_and_no_changes():
    assert "No libraries were rebuilt" in build_oss_db.format_build_diff([])
    unchanged = build_oss_db.LibraryDiff(
        library="zlib",
        old_count=1,
        new_count=1,
        added=[],
        removed=[],
        changed=[],
    )
    assert "No entry-level changes" in build_oss_db.format_build_diff([unchanged])
    assert "No entry-level changes" in build_oss_db.format_build_diff_markdown([unchanged])


def test_format_build_diff_escapes_control_characters_backticks_and_long_strings():
    entry = build_oss_db.make_db_entry("hello\nworld\rcolumn\tvalue```" + ("x" * 200), "zlib", "1.0", "f.c", "fn")
    diff = build_oss_db.diff_library_entries("zlib", [], [entry])
    text = build_oss_db.format_build_diff([diff])
    assert "\\n" in text
    assert "\\r" in text
    assert "\\t" in text
    assert "` ` `" in text
    # Long strings are truncated with ellipsis; each +/-/~ line stays single-line.
    assert "..." in text
    for line in text.splitlines():
        if line.startswith(("+ ", "- ", "~ ")):
            assert "\n" not in line[2:]
            assert len(line) < 200


def test_main_writes_build_diff_for_new_and_merged_libraries(tmp_path):
    existing_entry = build_oss_db.make_db_entry("old-string", "zlib", "0.9#1", "f.c", "old_fn")
    rc = _invoke_run_build(
        tmp_path,
        ["zlib", "curl"],
        existing={"zlib": [existing_entry]},
    )
    assert rc == 0
    # Plain-text log report.
    log_text = (tmp_path / "build_diff.txt").read_text(encoding="utf-8")
    assert "## zlib" in log_text
    assert "## curl" in log_text
    assert "+ hello-from-zlib" in log_text
    assert "+ hello-from-curl" in log_text
    assert "- old-string" not in log_text

    # PR markdown: headings outside per-library ```diff fences.
    pr_text = (tmp_path / "build_diff_pr.txt").read_text(encoding="utf-8")
    assert "## zlib" in pr_text
    assert "## curl" in pr_text
    assert "```diff" in pr_text
    assert "+ hello-from-zlib" in pr_text
    assert "+ hello-from-curl" in pr_text
    assert "- old-string" not in pr_text
    for part in pr_text.split("```"):
        if part.startswith("diff"):
            assert "## " not in part


def test_main_build_diff_reports_no_changes_when_entries_identical(tmp_path):
    # Rebuild with the same entry the stub always produces: after merge, the
    # only string is still hello-from-zlib with identical metadata... but the
    # stub always emits version 1.0#1, so seed with that exact entry.
    existing = [build_oss_db.make_db_entry("hello-from-zlib", "zlib", "1.0#1", "f.c", "fn_zlib")]
    rc = _invoke_run_build(tmp_path, ["zlib"], existing={"zlib": existing})
    assert rc == 0
    text = (tmp_path / "build_diff.txt").read_text(encoding="utf-8")
    assert "No entry-level changes detected" in text
