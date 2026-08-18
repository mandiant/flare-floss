import os
import json
import tempfile
from pathlib import Path

import pytest

import floss.cache
from floss.results import (
    Strings,
    Analysis,
    Metadata,
    AddressType,
    StackString,
    TightString,
    ResultLayout,
    ResultString,
    StaticString,
    DecodedString,
    ResultDocument,
    StringEncoding,
)
from floss.version import __version__


def make_doc(
    sha256="a" * 64,
    version=__version__,
    min_length=4,
    enable_static=True,
    enable_stack=False,
    enable_tight=False,
    enable_decoded=False,
    enable_language=False,
    enable_layout=True,
    enable_tags=True,
):
    layout = ResultLayout(name="pe", offset=0, length=8) if enable_layout else None
    return ResultDocument(
        metadata=Metadata(
            file_path="sample.exe",
            md5="0" * 32,
            sha1="0" * 40,
            sha256=sha256,
            version=version,
            min_length=min_length,
        ),
        analysis=Analysis(
            enable_static_strings=enable_static,
            enable_stack_strings=enable_stack,
            enable_tight_strings=enable_tight,
            enable_decoded_strings=enable_decoded,
            enable_language_strings=enable_language,
            enable_layout=enable_layout,
            enable_tags=enable_tags,
        ),
        strings=Strings(
            static_strings=[StaticString(string="hello", offset=0, encoding=StringEncoding.ASCII)],
        ),
        layout=layout,
    )


def make_full_doc():
    layout = ResultLayout(
        name="pe",
        offset=0,
        length=8,
        strings=[ResultString(string="layout", offset=0, size=6, encoding="ASCII", tags=["#winapi"])],
    )
    return ResultDocument(
        metadata=Metadata(file_path="sample.exe", sha256="a" * 64, version=__version__, min_length=4),
        analysis=Analysis(
            enable_static_strings=True,
            enable_stack_strings=True,
            enable_tight_strings=True,
            enable_decoded_strings=True,
            enable_language_strings=True,
            enable_layout=True,
            enable_tags=True,
        ),
        strings=Strings(
            static_strings=[StaticString(string="hello", offset=0, encoding=StringEncoding.ASCII, tags=["#common"])],
            stack_strings=[
                StackString(
                    function=0,
                    string="stack",
                    encoding=StringEncoding.ASCII,
                    program_counter=0,
                    stack_pointer=0,
                    original_stack_pointer=0,
                    offset=0,
                    frame_offset=0,
                )
            ],
            tight_strings=[
                TightString(
                    function=0,
                    string="tight",
                    encoding=StringEncoding.ASCII,
                    program_counter=0,
                    stack_pointer=0,
                    original_stack_pointer=0,
                    offset=0,
                    frame_offset=0,
                )
            ],
            decoded_strings=[
                DecodedString(
                    address=0,
                    address_type=AddressType.STACK,
                    string="decoded",
                    encoding=StringEncoding.ASCII,
                    decoded_at=0,
                    decoding_routine=0,
                )
            ],
            language_strings=[StaticString(string="gostring", offset=0, encoding=StringEncoding.UTF8, tags=["#go"])],
            language_strings_missed=[StaticString(string="missed", offset=0, encoding=StringEncoding.UTF8)],
        ),
        layout=layout,
    )


def wanted(
    enable_static=True,
    enable_stack=False,
    enable_tight=False,
    enable_decoded=False,
    enable_language=False,
    enable_layout=True,
    enable_tags=True,
):
    return Analysis(
        enable_static_strings=enable_static,
        enable_stack_strings=enable_stack,
        enable_tight_strings=enable_tight,
        enable_decoded_strings=enable_decoded,
        enable_language_strings=enable_language,
        enable_layout=enable_layout,
        enable_tags=enable_tags,
    )


def test_cache_enabled_default(monkeypatch):
    monkeypatch.delenv(floss.cache.ENV_CACHE_ENABLE, raising=False)
    assert floss.cache.cache_enabled()


@pytest.mark.parametrize("value", ("0", "false", "no", "n", ""))
def test_cache_enabled_disabled(monkeypatch, value):
    monkeypatch.setenv(floss.cache.ENV_CACHE_ENABLE, value)
    assert not floss.cache.cache_enabled()


def test_cache_refresh_default(monkeypatch):
    monkeypatch.delenv(floss.cache.ENV_CACHE_REFRESH, raising=False)
    assert not floss.cache.cache_refresh()


@pytest.mark.parametrize("value", ("1", "true", "yes", "y"))
def test_cache_refresh_enabled(monkeypatch, value):
    monkeypatch.setenv(floss.cache.ENV_CACHE_REFRESH, value)
    assert floss.cache.cache_refresh()


def test_get_cache_dir_override(monkeypatch, tmp_path):
    monkeypatch.setenv(floss.cache.ENV_CACHE_DIR, str(tmp_path))
    assert floss.cache.get_cache_dir() == tmp_path


def test_get_cache_dir_default(monkeypatch):
    from platformdirs import user_cache_dir

    monkeypatch.delenv(floss.cache.ENV_CACHE_DIR, raising=False)
    assert floss.cache.get_cache_dir() == Path(user_cache_dir("floss"))


def test_compute_key():
    sha256 = "a" * 64
    assert floss.cache.compute_key(sha256, "1.0") == f"{sha256}-1.0"


def test_cache_file_path(tmp_path):
    assert floss.cache.cache_file_path(tmp_path, "key") == tmp_path / "key.json"


def test_store_and_load_roundtrip(tmp_path):
    doc = make_doc()
    key = floss.cache.compute_key(doc.metadata.sha256, __version__)

    assert floss.cache.store(tmp_path, key, doc)
    assert (tmp_path / f"{key}.json").is_file()

    loaded = floss.cache.load(tmp_path, key, doc.metadata.sha256, __version__)
    assert loaded is not None
    assert loaded.metadata.sha256 == doc.metadata.sha256
    assert loaded.metadata.version == __version__
    assert loaded.strings.static_strings[0].string == "hello"


def test_store_writes_json_schema(tmp_path):
    doc = make_doc()
    key = floss.cache.compute_key(doc.metadata.sha256, __version__)

    floss.cache.store(tmp_path, key, doc)
    payload = json.loads((tmp_path / f"{key}.json").read_text())
    assert set(("metadata", "analysis", "strings")) <= set(payload.keys())


def test_load_missing(tmp_path):
    key = floss.cache.compute_key("a" * 64, __version__)
    assert floss.cache.load(tmp_path, key, "a" * 64, __version__) is None


def test_load_drops_invalid_json(tmp_path):
    key = floss.cache.compute_key("a" * 64, __version__)
    (tmp_path / f"{key}.json").write_text("{not json")

    assert floss.cache.load(tmp_path, key, "a" * 64, __version__) is None
    assert not (tmp_path / f"{key}.json").exists()


def test_load_drops_checksum_mismatch(tmp_path):
    doc = make_doc(sha256="a" * 64)
    key = floss.cache.compute_key("a" * 64, __version__)
    floss.cache.store(tmp_path, key, doc)

    assert floss.cache.load(tmp_path, key, "b" * 64, __version__) is None
    assert not (tmp_path / f"{key}.json").exists()


def test_load_ignores_unlink_failure_on_invalid_entry(tmp_path, monkeypatch):
    key = floss.cache.compute_key("a" * 64, __version__)
    (tmp_path / f"{key}.json").write_text("{not json")

    def raising_unlink(self, *args, **kwargs):
        raise PermissionError("held open by another process")

    monkeypatch.setattr(Path, "unlink", raising_unlink)
    assert floss.cache.load(tmp_path, key, "a" * 64, __version__) is None


def test_load_ignores_unlink_failure_on_stale_entry(tmp_path, monkeypatch):
    doc = make_doc(sha256="a" * 64)
    key = floss.cache.compute_key("a" * 64, __version__)
    floss.cache.store(tmp_path, key, doc)

    def raising_unlink(self, *args, **kwargs):
        raise PermissionError("held open by another process")

    monkeypatch.setattr(Path, "unlink", raising_unlink)
    assert floss.cache.load(tmp_path, key, "b" * 64, __version__) is None


def test_store_skips_when_replace_fails(tmp_path, monkeypatch):
    doc = make_doc()
    key = floss.cache.compute_key(doc.metadata.sha256, __version__)

    def raising_replace(src, dst):
        raise PermissionError("destination held open by antivirus")

    monkeypatch.setattr(os, "replace", raising_replace)
    assert floss.cache.store(tmp_path, key, doc) is False
    assert not (tmp_path / f"{key}.json").exists()
    # the temporary file is cleaned up
    assert list(tmp_path.glob("*.tmp")) == []


def test_store_skips_when_mkdir_fails(tmp_path, monkeypatch):
    doc = make_doc()
    key = floss.cache.compute_key(doc.metadata.sha256, __version__)
    cache_dir = tmp_path / "cache"

    def raising_mkdir(self, *args, **kwargs):
        raise PermissionError("no write access to cache directory")

    monkeypatch.setattr(Path, "mkdir", raising_mkdir)
    assert floss.cache.store(cache_dir, key, doc) is False


def test_store_skips_when_mkstemp_fails(tmp_path, monkeypatch):
    doc = make_doc()
    key = floss.cache.compute_key(doc.metadata.sha256, __version__)

    def raising_mkstemp(*args, **kwargs):
        raise OSError("no space left on device")

    monkeypatch.setattr(tempfile, "mkstemp", raising_mkstemp)
    assert floss.cache.store(tmp_path, key, doc) is False
    assert not (tmp_path / f"{key}.json").exists()


def test_load_drops_version_mismatch(tmp_path):
    doc = make_doc(version="9.9.9")
    key = floss.cache.compute_key(doc.metadata.sha256, __version__)
    floss.cache.store(tmp_path, key, doc)

    assert floss.cache.load(tmp_path, key, doc.metadata.sha256, __version__) is None
    assert not (tmp_path / f"{key}.json").exists()


def test_store_skips_when_locked(tmp_path):
    doc = make_doc()
    key = floss.cache.compute_key(doc.metadata.sha256, __version__)
    lock_path = tmp_path / f"{key}.lock"

    fd = floss.cache._acquire_lock(lock_path)
    assert fd is not None
    try:
        assert floss.cache.store(tmp_path, key, doc) is False
        assert not (tmp_path / f"{key}.json").exists()
    finally:
        floss.cache._release_lock(fd, lock_path)


def test_covers_matches():
    doc = make_doc()
    assert floss.cache.covers(doc, wanted(), 4)


def test_covers_missing_requested_type_is_miss():
    doc = make_doc(enable_static=True, enable_stack=False)
    assert not floss.cache.covers(doc, wanted(enable_stack=True), 4)


def test_covers_min_length_below_stored_is_miss():
    doc = make_doc(min_length=8)
    assert not floss.cache.covers(doc, wanted(), 4)


def test_covers_layout_enabled_mismatch_is_miss():
    doc = make_doc(enable_layout=False)
    assert not floss.cache.covers(doc, wanted(enable_layout=True), 4)


def test_covers_layout_disabled_is_hit():
    # a cached layout can satisfy a no-layout request: materialize() drops it
    doc = make_doc(enable_layout=True)
    assert floss.cache.covers(doc, wanted(enable_layout=False), 4)


def test_covers_tags_enabled_mismatch_is_miss():
    doc = make_doc(enable_tags=False)
    assert not floss.cache.covers(doc, wanted(enable_tags=True), 4)


def test_covers_tags_disabled_is_hit():
    # a tags-enabled document satisfies a no-tags request: materialize redacts
    doc = make_doc(enable_tags=True)
    assert floss.cache.covers(doc, wanted(enable_tags=False), 4)


def test_materialize_sets_file_path_and_filters(tmp_path):
    doc = make_doc(min_length=4)
    key = floss.cache.compute_key(doc.metadata.sha256, __version__)
    floss.cache.store(tmp_path, key, doc)
    loaded = floss.cache.load(tmp_path, key, doc.metadata.sha256, __version__)
    assert loaded is not None

    sample = tmp_path / "run" / "sample.exe"
    mat = floss.cache.materialize(loaded, sample, wanted(), 8)
    assert mat.metadata.file_path == str(sample)
    # "hello" is 5 chars, below the requested -n 8
    assert mat.strings.static_strings == []


def test_materialize_drops_layout_when_disabled(tmp_path):
    doc = make_doc(enable_layout=True)
    key = floss.cache.compute_key(doc.metadata.sha256, __version__)
    floss.cache.store(tmp_path, key, doc)
    loaded = floss.cache.load(tmp_path, key, doc.metadata.sha256, __version__)
    assert loaded is not None
    assert loaded.layout is not None

    mat = floss.cache.materialize(loaded, tmp_path / "sample.exe", wanted(enable_layout=False), 4)
    assert mat.layout is None


def test_materialize_clears_disabled_string_types():
    mat = floss.cache.materialize(make_full_doc(), Path("sample.exe"), wanted(), 4)
    assert mat.analysis.enable_static_strings is True
    assert mat.strings.static_strings

    disabled = Analysis(
        enable_static_strings=False,
        enable_stack_strings=False,
        enable_tight_strings=False,
        enable_decoded_strings=False,
        enable_language_strings=False,
    )
    mat = floss.cache.materialize(make_full_doc(), Path("sample.exe"), disabled, 4)
    assert mat.strings.static_strings == []
    assert mat.strings.stack_strings == []
    assert mat.strings.tight_strings == []
    assert mat.strings.decoded_strings == []
    assert mat.strings.language_strings == []
    assert mat.strings.language_strings_missed == []
    # static strings are disabled, so the layout that holds them is gone too
    assert mat.layout is None


def test_materialize_clears_only_disabled_types():
    disabled_stack = Analysis(enable_stack_strings=False)
    mat = floss.cache.materialize(make_full_doc(), Path("sample.exe"), disabled_stack, 4)
    assert mat.strings.stack_strings == []
    assert mat.strings.static_strings
    assert mat.strings.tight_strings
    assert mat.strings.decoded_strings
    assert mat.layout is not None


def test_materialize_syncs_layout_and_tag_flags():
    doc = make_full_doc()
    mat = floss.cache.materialize(doc, Path("sample.exe"), Analysis(enable_layout=False, enable_tags=False), 4)
    assert mat.analysis.enable_layout is False
    assert mat.analysis.enable_tags is False


def test_materialize_updates_metadata_min_length():
    # a -n 6 hit against a -n 4 cache entry must report the requested length
    mat = floss.cache.materialize(make_full_doc(), Path("sample.exe"), wanted(), 6)
    assert mat.metadata.min_length == 6
    assert all(len(s.string) >= 6 for s in mat.strings.static_strings)


def test_materialize_clears_tags_when_disabled():
    doc = make_full_doc()
    assert doc.strings.static_strings[0].tags == ["#common"]
    assert doc.layout.strings[0].tags == ["#winapi"]

    # Analysis(enable_tags=False) keeps every string type enabled, tags off
    mat = floss.cache.materialize(doc, Path("sample.exe"), Analysis(enable_tags=False), 4)
    assert mat.layout is not None
    assert mat.strings.static_strings[0].tags == []
    assert mat.strings.language_strings[0].tags == []
    assert mat.layout.strings[0].tags == []


def test_materialize_keeps_tags_when_enabled():
    mat = floss.cache.materialize(make_full_doc(), Path("sample.exe"), wanted(), 4)
    assert mat.layout is not None
    assert mat.strings.static_strings[0].tags == ["#common"]
    assert mat.layout.strings[0].tags == ["#winapi"]
