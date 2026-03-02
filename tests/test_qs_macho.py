from pathlib import Path

from floss.qs.main import Slice, compute_layout


CD = Path(__file__).resolve().parent
MACHO_DIR = CD / "data" / "macho"


def _load_layout(name: str):
    path = MACHO_DIR / name
    data = path.read_bytes()
    return compute_layout(Slice.from_bytes(data))


def test_thin_macho_layout():
    layout = _load_layout("ls")
    assert layout.name.startswith("macho:")
    assert layout.children


def test_fat_macho_layout():
    layout = _load_layout("true")
    assert layout.name == "macho (fat)"
    assert len(layout.children) == 2
    assert {child.name for child in layout.children} == {"macho: x86_64", "macho: arm64e"}
