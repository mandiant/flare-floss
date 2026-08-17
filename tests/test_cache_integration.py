import hashlib
import logging
from pathlib import Path

from fixtures import scfile, exefile

import floss.main
import floss.cache
import floss.render.json
from floss.results import Strings, Analysis, Metadata, ResultDocument
from floss.version import __version__


def cache_entries(cache_dir):
    return list(cache_dir.rglob("*.json"))


def test_cache_hit_skips_analysis_and_matches_output(capsys, caplog, tmp_path, monkeypatch, exefile):
    caplog.set_level(logging.DEBUG)
    cache_dir = tmp_path / "cache"
    monkeypatch.setenv(floss.cache.ENV_CACHE_DIR, str(cache_dir))

    assert floss.main.main([exefile, "--summary"]) == 0
    out1 = capsys.readouterr().out

    sha256 = hashlib.sha256(Path(exefile).read_bytes()).hexdigest()
    key = floss.cache.compute_key(sha256, __version__)
    assert (cache_dir / f"{key}.json").is_file()
    assert len(cache_entries(cache_dir)) == 1

    caplog.clear()
    assert floss.main.main([exefile, "--summary", "-d"]) == 0
    assert any("using cached results" in r.getMessage() for r in caplog.records)
    assert capsys.readouterr().out == out1


def test_cache_disabled_writes_nothing(capsys, tmp_path, monkeypatch, exefile):
    cache_dir = tmp_path / "cache"
    monkeypatch.setenv(floss.cache.ENV_CACHE_DIR, str(cache_dir))
    monkeypatch.setenv(floss.cache.ENV_CACHE_ENABLE, "0")

    assert floss.main.main([exefile, "--summary"]) == 0
    assert cache_entries(cache_dir) == []


def test_cache_not_written_for_results_document(capsys, tmp_path, monkeypatch):
    cache_dir = tmp_path / "cache"
    monkeypatch.setenv(floss.cache.ENV_CACHE_DIR, str(cache_dir))

    doc = ResultDocument(
        metadata=Metadata(file_path="sample.exe", min_length=4),
        analysis=Analysis(enable_static_strings=False),
        strings=Strings(),
    )
    results_path = tmp_path / "results.json"
    results_path.write_text(floss.render.json.render(doc))

    assert floss.main.main([str(results_path)]) == 0
    assert cache_entries(cache_dir) == []


def test_analysis_variant_disables_cache(capsys, tmp_path, monkeypatch, scfile):
    cache_dir = tmp_path / "cache"
    monkeypatch.setenv(floss.cache.ENV_CACHE_DIR, str(cache_dir))

    # an explicit --format is a non-default analysis variant, so no caching
    assert floss.main.main([scfile, "-f", "sc32", "--summary"]) == 0
    assert cache_entries(cache_dir) == []
