import json
from pathlib import Path

import pytest

import floss.cache
from floss.results import (
    Strings,
    Analysis,
    Metadata,
    ResultLayout,
    StaticString,
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


def test_covers_layout_disabled_mismatch_is_miss():
    doc = make_doc(enable_layout=True)
    assert not floss.cache.covers(doc, wanted(enable_layout=False), 4)


def test_covers_tags_enabled_mismatch_is_miss():
    doc = make_doc(enable_tags=False)
    assert not floss.cache.covers(doc, wanted(enable_tags=True), 4)


def test_covers_tags_disabled_mismatch_is_miss():
    doc = make_doc(enable_tags=True)
    assert not floss.cache.covers(doc, wanted(enable_tags=False), 4)


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
