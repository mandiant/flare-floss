import pathlib

import floss.qs.db.oss


def test_load_db():
    path = pathlib.Path(floss.qs.db.oss.__file__).parent / "data" / "oss" / "zlib.jsonl.gz"
    db = floss.qs.db.oss.OpenSourceStringDatabase.from_file(path)
    assert len(db) > 0  # 21 entries at time of writing


def test_query_db():
    path = pathlib.Path(floss.qs.db.oss.__file__).parent / "data" / "oss" / "zlib.jsonl.gz"
    db = floss.qs.db.oss.OpenSourceStringDatabase.from_file(path)

    s = db.metadata_by_string["invalid distance code"]

    assert s is not None
    assert s.string == "invalid distance code"
    assert s.library_name == "zlib"
    assert s.library_version == "1.2.13"
    assert s.file_path == "CMakeFiles/zlib.dir/inffast.obj"
    assert s.function_name == "inflate_fast"
    assert s.line_number is None
