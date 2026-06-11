from pathlib import Path

from floss.qs.main import Slice, ELFLayout, compute_layout

CD = Path(__file__).resolve().parent
ELF_DIR = CD / "data" / "elf"

# x86-64 Position Independent Executable (PIE), dynamically linked, not stripped
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
    text_sections = [c for c in layout.children if c.name == ".text"]
    assert len(text_sections) == 1
    assert text_sections[0].offset == 0x10A0
    assert text_sections[0].slice.range.length == 0x1C5


def test_elf_section_names():
    # x86-64, not stripped: executable code section, dynamic string table, and symbol table all present
    layout = _load_layout(X86_64_PIE)
    names = {child.name for child in layout.children}
    assert ".text" in names
    assert ".dynstr" in names
    assert ".symtab" in names


def test_elf_structures_present():
    layout = _load_layout(X86_64_PIE)
    assert layout.structures_by_address[0x0].name == "elf header"
    assert layout.structures_by_address[0x40].name == "program header"
    assert layout.structures_by_address[0x39D0].name == "section header"
    assert layout.structures_by_address[0x3C8].name == "symbol table"  # .dynsym
    assert layout.structures_by_address[0x4A0].name == "string table"  # .dynstr


def test_elf_code_and_reloc_offsets():
    layout = _load_layout(X86_64_PIE)
    # .text (offset 0x10a0, size 0x1c5) is fully covered by code ranges;
    # it merges with adjacent exec sections (.plt etc.) so we check coverage, not exact range
    assert layout.code_offsets.overlaps(0x10A0, 0x10A0 + 0x1C5 - 1)
    assert (0x568, 0x66F) in layout.relocation_offsets.ranges      # .rela.dyn + .rela.plt merged


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
