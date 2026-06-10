from pathlib import Path

from floss.qs.main import ELFLayout, Slice, compute_layout

CD = Path(__file__).resolve().parent
ELF_DIR = CD / "data" / "elf"

# x86-64 PIE, dynamically linked, not stripped
X86_64_PIE = "055da8e6ccfe5a9380231ea04b850e18.elf"
# ARM64 shared object, dynamically linked, stripped, Android linker
ARM64_SO = "687e79cde5b0ced75ac229465835054931f9ec438816f2827a8be5f3bd474929.elf"
# ARM64 PIE, dynamically linked, stripped
ARM64_LS = "ls"


def _load_layout(name: str):
    path = ELF_DIR / name
    data = path.read_bytes()
    return compute_layout(Slice.from_bytes(data))


def test_elf_layout():
    layout = _load_layout(X86_64_PIE)
    assert isinstance(layout, ELFLayout)
    assert layout.name == "elf"
    assert layout.children


def test_elf_section_names():
    # x86-64, not stripped: executable code section, dynamic string table, and symbol table all present
    layout = _load_layout(X86_64_PIE)
    names = {child.name for child in layout.children}
    assert ".text" in names
    assert ".dynstr" in names
    assert ".symtab" in names


def test_elf_structures_present():
    layout = _load_layout(X86_64_PIE)
    assert layout.structures_by_address


def test_elf_code_and_reloc_offsets():
    layout = _load_layout(X86_64_PIE)
    assert layout.code_offsets.ranges
    assert layout.relocation_offsets.ranges


def test_arm64_so_android_note_section():
    # Android shared object has an Android-specific note section absent from standard Linux ELFs
    layout = _load_layout(ARM64_SO)
    names = {child.name for child in layout.children}
    assert ".note.android.ident" in names


def test_arm64_ls_stripped():
    # stripped binary has no symbol table
    layout = _load_layout(ARM64_LS)
    names = {child.name for child in layout.children}
    assert ".symtab" not in names
