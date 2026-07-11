import pathlib

import floss.tags.winapi


def test_load_db():
    path = pathlib.Path(floss.tags.winapi.__file__).resolve().parents[1] / "qs" / "db" / "data" / "winapi"
    db = floss.tags.winapi.WindowsApiStringDatabase.from_dir(path)
    assert len(db) > 0


def test_query_db():
    path = pathlib.Path(floss.tags.winapi.__file__).resolve().parents[1] / "qs" / "db" / "data" / "winapi"
    db = floss.tags.winapi.WindowsApiStringDatabase.from_dir(path)

    assert "kernel32.dll" in db.dll_names
    assert "kernel33.dll" not in db.dll_names

    assert "CreateFileA" in db.api_names
    assert "CreateFileB" not in db.api_names
