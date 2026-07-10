import pathlib

import floss.qs.db.winapi


def test_load_db():
    path = pathlib.Path(floss.qs.db.winapi.__file__).parent / "data" / "winapi"
    db = floss.qs.db.winapi.WindowsApiStringDatabase.from_dir(path)
    assert len(db) > 0


def test_query_db():
    path = pathlib.Path(floss.qs.db.winapi.__file__).parent / "data" / "winapi"
    db = floss.qs.db.winapi.WindowsApiStringDatabase.from_dir(path)

    assert "kernel32.dll" in db.dll_names
    assert "kernel33.dll" not in db.dll_names

    assert "CreateFileA" in db.api_names
    assert "CreateFileB" not in db.api_names
