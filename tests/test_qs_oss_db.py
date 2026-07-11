import pathlib

import floss.tags.oss


def test_load_db():
    path = pathlib.Path(floss.tags.oss.__file__).resolve().parents[1] / "qs" / "db" / "data" / "oss" / "zlib.jsonl.gz"
    db = floss.tags.oss.OpenSourceStringDatabase.from_file(path)
    assert len(db) > 0  # 21 entries at time of writing


def test_query_db():
    path = pathlib.Path(floss.tags.oss.__file__).resolve().parents[1] / "qs" / "db" / "data" / "oss" / "zlib.jsonl.gz"
    db = floss.tags.oss.OpenSourceStringDatabase.from_file(path)

    s = db.metadata_by_string["invalid distance code"]

    assert s is not None
    assert s.string == "invalid distance code"
    assert s.library_name == "zlib"
    assert s.library_version == "1.2.13"
    assert s.file_path == "CMakeFiles/zlib.dir/inffast.obj"
    assert s.function_name == "inflate_fast"
    assert s.line_number is None
