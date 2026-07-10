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


def test_thin_macho_segment_names():
    layout = _load_layout("regdmp")
    names = {child.name for child in layout.children}
    assert "__TEXT" in names
    assert "__LINKEDIT" in names


def test_macho_structures_present():
    layout = _load_layout("ls")
    assert getattr(layout, "structures_by_address", None)


def test_fat_macho_layout():
    layout = _load_layout("true")
    assert layout.name == "macho (fat)"
    assert len(layout.children) == 2
    assert {child.name for child in layout.children} == {"macho: x86_64", "macho: arm64e"}


def test_entitlements_plist_layout():
    layout = _load_layout("true")
    found = []
    for arch in layout.children:
        for child in arch.children:
            if child.name == "__LINKEDIT":
                for code_sig in child.children:
                    if code_sig.name != "code signature":
                        continue
                    for cert in code_sig.children:
                        if any(sub.name == "plist: entitlements" for sub in cert.children):
                            found.append(arch.name)
    assert set(found) == {"macho: x86_64", "macho: arm64e"}


def test_entitlements_plist_parse():
    import plistlib

    path = MACHO_DIR / "true"
    data = path.read_bytes()
    layout = compute_layout(Slice.from_bytes(data))

    parsed = 0
    for arch in layout.children:
        for child in arch.children:
            if child.name == "__LINKEDIT":
                for code_sig in child.children:
                    if code_sig.name != "code signature":
                        continue
                    for cert in code_sig.children:
                        for subchild in cert.children:
                            if subchild.name == "plist: entitlements":
                                blob = data[subchild.offset : subchild.end]
                                plistlib.loads(blob)
                                parsed += 1

    assert parsed == 2
