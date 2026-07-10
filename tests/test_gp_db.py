import pathlib

import floss.qs.db.gp

CD = pathlib.Path(__file__).parent


def test_load_db():
    path = pathlib.Path(floss.qs.db.gp.__file__).parent / "data" / "gp" / "gp.jsonl.gz"
    db = floss.qs.db.gp.StringGlobalPrevalenceDatabase.from_file(path)

    assert len(db) > 0  # 21 entries at time of writing


def test_query_db():
    path = pathlib.Path(floss.qs.db.gp.__file__).parent / "data" / "gp" / "gp.jsonl.gz"
    db = floss.qs.db.gp.StringGlobalPrevalenceDatabase.from_file(path)
    res = db.metadata_by_string["!This program cannot be run in DOS mode."]

    assert len(res) == 1
    s = res[0]

    assert s is not None
    assert s.string == "!This program cannot be run in DOS mode."
    assert s.encoding == "ascii"
    assert s.global_count == 424466
    assert s.location == None


def test_load_hash_db():
    path = pathlib.Path(floss.qs.db.gp.__file__).parent / "data" / "gp" / "xaa-hashes.bin"
    db = floss.qs.db.gp.StringHashDatabase.from_file(path)

    assert len(db) > 0


def test_query_hash_db():
    path = pathlib.Path(floss.qs.db.gp.__file__).parent / "data" / "gp" / "xaa-hashes.bin"
    db = floss.qs.db.gp.StringHashDatabase.from_file(path)

    assert "!This program cannot be run in DOS mode." in db
    assert "Willi rules" not in db
