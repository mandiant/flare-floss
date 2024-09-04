# /// script
# dependencies = [
#     "textual==0.29.0",
#     "rich==13.4.2",
#     "dissect.cstruct==3.6",
#     "pefile==2023.2.7",
# ]
# ///
# TODO:
#   - other structures
#   - structure & hexview side by side
#   - on hover structure highlight the hex
import re
import asyncio
import logging
import pathlib
import textwrap
import itertools
import dataclasses
from typing import Any, Set, List, Tuple, Literal, Mapping, Callable, Iterable, Optional, Sequence
from dataclasses import dataclass

import pefile
import rich.table
import rich.console
from dissect import cstruct
from rich.text import Text
from rich.style import Style
from textual.app import App, ComposeResult
from rich.segment import Segment
from textual.strip import Strip
from textual.screen import Screen
from textual.widget import Widget
from textual.binding import Binding
from textual.widgets import Label, Footer, Static, TabPane, TabbedContent
from textual.widgets._tooltip import Tooltip
from textual.geometry import Size
from textual.reactive import reactive
from textual.containers import Horizontal, VerticalScroll
from textual.css.styles import Styles
from textual.scroll_view import ScrollView
from dissect.cstruct.types.enum import EnumInstance

logger = logging.getLogger("mz")


ASCII_BYTE = r" !\"#\$%&\'\(\)\*\+,-\./0123456789:;<=>\?@ABCDEFGHIJKLMNOPQRSTUVWXYZ\[\]\^_`abcdefghijklmnopqrstuvwxyz\{\|\}\\\~\t".encode(
    "ascii"
)
ASCII_RE_4 = re.compile(b"([%s]{%d,})" % (ASCII_BYTE, 4))
UNICODE_RE_4 = re.compile(b"((?:[%s]\x00){%d,})" % (ASCII_BYTE, 4))


@dataclass
class String:
    s: str
    offset: int
    flavor: Literal["ascii", "unicode"]


def extract_ascii_strings(buf: bytes, n: int = 4) -> Iterable[String]:
    """Extract ASCII strings from the given binary data."""

    if not buf:
        return

    r = None
    if n == 4:
        r = ASCII_RE_4
    else:
        reg = b"([%s]{%d,})" % (ASCII_BYTE, n)
        r = re.compile(reg)
    for match in r.finditer(buf):
        yield String(match.group().decode("ascii"), match.start(), "ascii")


def extract_unicode_strings(buf: bytes, n: int = 4) -> Iterable[String]:
    """Extract naive UTF-16 strings from the given binary data."""
    if not buf:
        return

    if n == 4:
        r = UNICODE_RE_4
    else:
        reg = b"((?:[%s]\x00){%d,})" % (ASCII_BYTE, n)
        r = re.compile(reg)
    for match in r.finditer(buf):
        try:
            yield String(match.group().decode("utf-16"), match.start(), "unicode")
        except UnicodeDecodeError:
            pass


@dataclass
class Context:
    path: pathlib.Path
    buf: bytearray
    # sorted by offset
    strings: List[String]
    pe: pefile.PE
    cparser: cstruct.cstruct

    # specialized renderers for fields parsed by cstruct,
    # such as timestamp from number of seconds.
    #
    # maps from {structure name}.{field name} to a renderer.
    # def render(field: Any) -> str: ...
    renderers: Mapping[str, Callable[[Any], str]]

    # the fields to show when a structure is minimized.
    #
    # maps from structure name to a set of field names.
    key_fields: Mapping[str, Set[str]]

    @property
    def bitness(self):
        if self.pe.FILE_HEADER.Machine == pefile.MACHINE_TYPE["IMAGE_FILE_MACHINE_I386"]:
            return 32
        elif self.pe.FILE_HEADER.Machine == pefile.MACHINE_TYPE["IMAGE_FILE_MACHINE_AMD64"]:
            return 64
        else:
            raise ValueError("unknown bitness")

    @classmethod
    def from_bytes(cls, path: pathlib.Path, buf: bytes):
        # premature optimization consideration:
        # do the parsing within the app, in case the file is really large and this is laggy.
        # we can introduce background parsing later.
        pe = pefile.PE(data=buf, fast_load=False)

        cparser = cstruct.cstruct()
        cparser.load(STRUCTURES)

        renderers = {
            "IMAGE_FILE_HEADER.TimeDateStamp": render_timestamp,
            "IMAGE_FILE_HEADER.Characteristics": render_characteristics,
            "IMAGE_OPTIONAL_HEADER32.DllCharacteristics": render_dll_characteristics,
            "IMAGE_OPTIONAL_HEADER32.CheckSum": render_u32,
            "IMAGE_OPTIONAL_HEADER64.DllCharacteristics": render_dll_characteristics,
            "IMAGE_OPTIONAL_HEADER64.CheckSum": render_u32,
            # parsed in more detail elsewhere.
            "IMAGE_OPTIONAL_HEADER32.DataDirectory": dont_render,
            "IMAGE_OPTIONAL_HEADER64.DataDirectory": dont_render,
        }

        key_fields = {
            "IMAGE_FILE_HEADER": {"Machine", "TimeDateStamp", "Characteristics"},
            "IMAGE_OPTIONAL_HEADER32": {"ImageBase", "Subsystem", "CheckSum", "DllCharacteristics"},
            "IMAGE_OPTIONAL_HEADER64": {"ImageBase", "Subsystem", "CheckSum", "DllCharacteristics"},
            "IMAGE_DATA_DIRECTORY": {"VirtualAddress", "Size"},
        }

        strings = list(
            sorted(itertools.chain(extract_ascii_strings(buf), extract_unicode_strings(buf)), key=lambda s: s.offset)
        )

        return cls(path, buf, strings, pe, cparser, renderers, key_fields)


def get_global_style(node, classname: str) -> Styles:
    """
    find the style with the given class name defined at the App level.

    this is needed for widgets that use rich formatting, rather than CSS formatting/classes,
     and need to access the style provided by the application.
    its only useful to fetch simple styles defined at the application global level.
    much more logic would be needed to extract styles with scopes like `app > widget > child`.

    use the `.partial_rich_style` property on the result to translate to something usable by rich.
    for example:

        return Text("foo", style=get_global_style(self, "decoration").partial_rich_style)

    see also `get_effective_global_color` when you need alpha-aware colors.
    """
    key = f".{classname}"
    rules = node.app.stylesheet.rules_map.get(key, [])
    assert len(rules) == 1
    # not sure what happens if there's more than one candidate,
    # lets try to avoid that, by convention.
    return rules[0].styles


def get_effective_global_color(node, classname: str) -> Style:
    """
    fetch the color style for the given global class name and merge it with the current style.
    this is alpha aware, unlike get_global_style, so it'll handle muted text nicely
    (which relies upon alpha to progressively dim text).

    note: rich styles don't understand alpha. colors with alpha are a textual construct.
    hence, this routine.
    """
    global_style = get_global_style(node, classname)
    color = global_style.get_rule("color")

    # (base_background, base_color, background, color)
    _, _, background, _ = node.colors

    # see DOMNode.rich_style for inspiration
    return Style.from_color(
        (background + color).rich_color if (background.a or color.a) else None,
        background.rich_color if background.a else None,
    )


def w(s: str) -> Text:
    """wrapper for multi-line text"""
    return Text.from_markup(textwrap.dedent(s.lstrip("\n")).strip())


class Line(Horizontal):
    """A line of text. Children should be Static widgets."""

    DEFAULT_CSS = """
        Line {
            /* ensure each line doesn't overflow to subsequent row */
            height: 1;
        }

        Line > Static {
            /* by default, the widget will expand to fill the available space */
            width: auto;
        }
    """


class MetadataView(Static):
    def __init__(self, ctx: Context, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.ctx = ctx

    def compose(self) -> ComposeResult:
        yield Label("metadata:", classes="peapp--title")
        yield Line(
            Static("  name: ", classes="peapp--key"),
            Static(self.ctx.path.name),
        )
        yield Line(
            Static("  size: ", classes="peapp--key"),
            Static(hex(len(self.ctx.buf))),
        )

        warnings = self.ctx.pe.get_warnings()
        if warnings:
            yield Label("  warnings:", classes="peapp--key")
            for warning in warnings:
                yield Label(f"    - {warning}")


class HexView(ScrollView):
    # TODO: label/title
    # TODO: make this width the application global width?
    # TODO: make it easy to copy from

    # refer directly to line api documentation here:
    # https://textual.textualize.io/guide/widgets/#line-api
    COMPONENT_CLASSES = {
        "hexview--address",
        "hexview--padding",
        "hexview--hex-nonzero",
        "hexview--hex-zero",
        "hexview--ascii-printable",
        "hexview--ascii-nonprintable",
    }

    DEFAULT_CSS = """
        HexView {
            /* take up full height of hex view, unless specified otherwise */
            height: auto;
        }

        HexView .hexview--address {
            color: $accent;
        }

        HexView .hexview--padding {
            /* nothing special, empty space */
        }

        HexView .hexview--hex-nonzero {
            color: $text;
        }

        HexView .hexview--hex-zero {
            color: $text-muted;
        }

        HexView .hexview--ascii-printable {
            color: $text;
        }

        HexView .hexview--ascii-nonprintable {
            color: $text-muted;
        }
    """

    def __init__(self, ctx: Context, address: int, length: int, row_length: int = 0x10, *args, **kwargs):
        if length < 0:
            raise ValueError("length must be >= 0")

        if address < 0:
            raise ValueError("address must be >= 0")

        if address > len(ctx.buf):
            raise ValueError("address must be <= len(ctx.buf)")

        if address + length > len(ctx.buf):
            raise ValueError("address + length must be <= len(ctx.buf)")

        if row_length <= 0:
            raise ValueError("row_length must be > 0")

        super().__init__(*args, **kwargs)

        self.ctx = ctx
        self.address = address
        self.length = length
        self.row_length = row_length

        self.has_aligned_start = self.address % self.row_length == 0
        self.has_aligned_end = (self.address + self.length) % self.row_length == 0

        DEFAULT_WIDTH = 76

        self.row_count = (self.length // self.row_length) + 1
        if self.has_aligned_start and self.length % self.row_length == 0:
            self.row_count -= 1

        self.virtual_size = Size(width=DEFAULT_WIDTH, height=self.row_count)

    def render_line(self, y: int) -> Strip:
        scroll_x, scroll_y = self.scroll_offset
        row_index = y + scroll_y

        if row_index >= self.row_count:
            return Strip.blank(self.size.width)

        # row_offset is the aligned row offset into buf, which is a multiple of 16.
        row_offset = row_index * self.row_length

        if row_index == 0:
            # number of bytes of padding at the start of the line
            # when the region start is unaligned.
            padding_start_length = self.address % self.row_length

            # number of bytes of data to display on this line.
            row_data_length = min(self.row_length - padding_start_length, self.length)

        else:
            padding_start_length = 0

            row_data_length = min(self.row_length, self.address + self.length - row_offset)

        # the offset in to the buf to find the bytes shown on this line.
        row_data_offset = row_offset + padding_start_length

        # number of bytes of padding at the end of the line
        # when the region start is unaligned.
        padding_end_length = self.row_length - row_data_length - padding_start_length

        # the bytes of data to show on this line.
        row_buf = self.ctx.buf[self.address + row_data_offset : self.address + row_data_offset + row_data_length]

        segments: List[Segment] = []

        style_address = self.get_component_rich_style("hexview--address")
        style_padding = self.get_component_rich_style("hexview--padding")
        style_hex_nonzero = self.get_component_rich_style("hexview--hex-nonzero")
        style_hex_zero = self.get_component_rich_style("hexview--hex-zero")
        style_ascii_printable = self.get_component_rich_style("hexview--ascii-printable")
        style_ascii_nonprintable = self.get_component_rich_style("hexview--ascii-nonprintable")

        # render address column.
        # like:
        #
        #     0x00000000:
        #     0x00000010:
        #
        # TODO: make this 8 bytes for x64
        segments.append(Segment(f"{self.address + row_offset:08x}:", style_address))
        segments.append(Segment("  ", style_padding))

        # render hex column.
        # there may be padding at the start and/or end of line.
        # like:
        #
        #                    FF 00 00 B8 00 00 00 00 00 00 00
        #     04 00 00 00 FF FF 00 00 B8 00 00 00 00 00 00 00
        #     04 00 00 00 FF FF 00 00 B8 00 00 00
        for _ in range(padding_start_length):
            # width of a hex value is 2 characters.
            segments.append(Segment("  ", style_padding))
            # space-separate hex values.
            segments.append(Segment(" ", style_padding))

        # render hex value,
        # bright when non-zero, muted when zero.
        for b in row_buf:
            if b == 0x0:
                segments.append(Segment("00", style_hex_zero))
            else:
                segments.append(Segment(f"{b:02X}", style_hex_nonzero))
            segments.append(Segment(" ", style_padding))

        for _ in range(padding_end_length):
            segments.append(Segment("  ", style_padding))
            segments.append(Segment(" ", style_padding))

        # remove the trailing space thats usually used
        # to separate each hex byte value.
        segments.pop()

        # separate the hex data from the ascii data
        segments.append(Segment("  ", style_padding))

        # render ascii column.
        # there may be padding at the start and/or end of line.
        # like:
        #
        #          .....ABCD...
        #      MZ.......ABCD...
        #      MZ.......ABC
        for _ in range(padding_start_length):
            # the width of an ascii value is one character,
            # and these are not separated by spaces.
            segments.append(Segment(" ", style_padding))

        # render ascii value,
        # bright when printable, muted when non-printable.
        for b in row_buf:
            if 0x20 <= b <= 0x7E:
                segments.append(Segment(chr(b), style_ascii_printable))
            else:
                segments.append(Segment(".", style_ascii_nonprintable))

        for _ in range(padding_end_length):
            segments.append(Segment(" ", style_padding))

        strip = Strip(segments)
        strip = strip.crop(scroll_x, scroll_x + self.size.width)
        return strip


class HexTestView(Widget):
    DEFAULT_CSS = """
        HexTestView > Label {
            padding-top: 1;
        }

        HexTestView > HexView.tall {
            height: 6;  /* margin-top: 1 + four lines of content + margin-bottom: 1 */
        }
    """

    def __init__(self, ctx: Context, *args, **kwargs):
        super().__init__()
        self.add_class("peapp--pane")

        self.ctx = ctx

    def compose(self) -> ComposeResult:
        yield Label("0, 4: single line, end padding")
        yield HexView(self.ctx, 0x0, 0x4)

        yield Label("0, 10: single line, aligned")
        yield HexView(self.ctx, 0x0, 0x10)

        yield Label("0, 18: two lines, end padding")
        yield HexView(self.ctx, 0x0, 0x18)

        yield Label("0, 20: two lines, aligned")
        yield HexView(self.ctx, 0x0, 0x20)

        yield Label("0, 28: three lines, end padding")
        yield HexView(self.ctx, 0x0, 0x28)

        yield Label("0, 30: three lines, aligned")
        yield HexView(self.ctx, 0x0, 0x30)

        yield Label("3, 4: one line, start padding, end padding")
        yield HexView(self.ctx, 0x3, 0x4)

        yield Label("3, D: one line, start padding")
        yield HexView(self.ctx, 0x3, 0xD)

        yield Label("3, 10: two lines, start padding, end padding")
        yield HexView(self.ctx, 0x3, 0x10)

        yield Label("3, 1D: two lines, start padding")
        yield HexView(self.ctx, 0x3, 0x1D)

        yield Label("3, 20: three lines, start padding, end padding")
        yield HexView(self.ctx, 0x3, 0x20)

        yield Label("3, 2D: three lines, start padding")
        yield HexView(self.ctx, 0x3, 0x2D)

        yield Label("0, 4, 7: single line, end padding")
        yield HexView(self.ctx, 0x0, 0x4, row_length=7)

        yield Label("0, 7, 7: single line, aligned")
        yield HexView(self.ctx, 0x0, 0x10, row_length=7)

        yield Label("0, 13, 7: two lines, end padding")
        yield HexView(self.ctx, 0x0, 0x18, row_length=7)

        yield Label("0, 100: tall, overflowing")
        yield HexView(self.ctx, 0x0, len(self.ctx.buf), classes="tall")


class StringsView(VerticalScroll):
    DEFAULT_CSS = """
        StringsView {
            /* let the container set our size */
            height: auto;
        }
    """

    def __init__(self, ctx: Context, address: int, length: int, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.ctx = ctx
        self.address = address
        self.length = length
        self.strings = list(filter(lambda s: s.offset >= address and s.offset < address + length, self.ctx.strings))

    def compose(self) -> ComposeResult:
        address_style = get_effective_global_color(self, "peapp--address")
        flavor_style = get_effective_global_color(self, "peapp--decoration")
        decoration_style = get_effective_global_color(self, "peapp--decoration")

        has_strings = False
        t = Text()
        for s in self.strings:
            t.append(f"{self.address + s.offset:08x}", style=address_style)
            t.append(": ", style=decoration_style)
            t.append("ascii" if s.flavor == "ascii" else "utf16", style=flavor_style)
            t.append(": ", style=decoration_style)
            t.append(s.s)
            t.append("\n")
            has_strings = True

        if not has_strings:
            t.append("(none)", style=decoration_style)

        yield Static(t)
        return


class BinaryView(Widget):
    DEFAULT_CSS = """
        BinaryView {
            /* let the container set our size */
            height: auto;
        }

        BinaryView StringsView,
        BinaryView HexView {
            max-height: 32;
        }

        BinaryView TabPane {
            /* align the tab content with the first tab title */
            padding: 0;
            padding-left: 1;
        }

        /* condense the tab layout: remove the empty line above the tab row */
        /* */
        BinaryView Tabs {
            /* tab row is height two: 1 for the tab title, 1 for the underline */
            height: 2;
        }

        BinaryView Tabs Horizontal Tab {
            /* the tab title is height one, no extra padding */
            height: 1;
            padding: 0 1 0 1;
        }

        BinaryView Tabs #tabs-list {
            /* the tabs list should only have one line */
            min-height: 1;
        }
        /* */
        /* end tab layout fix */
    """

    def __init__(self, ctx: Context, address: int, length: int, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.ctx = ctx
        self.address = address
        self.length = length

    def compose(self) -> ComposeResult:
        sv = StringsView(self.ctx, self.address, self.length)
        hv = HexView(self.ctx, self.address, self.length)

        # when there are strings, prefer to show those.
        # otherwise, show the hex data.
        if sv.strings:
            with TabbedContent():
                with TabPane(f"strings ({len(sv.strings)})"):
                    yield sv
                with TabPane("hex"):
                    yield hv
        else:
            with TabbedContent():
                with TabPane("hex"):
                    yield hv
                with TabPane("strings (0)"):
                    yield Label("(none)")


STRUCTURES = """
    struct IMAGE_DOS_HEADER {               // DOS .EXE header
        WORD   e_magic;                     // Magic number
        WORD   e_cblp;                      // Bytes on last page of file
        WORD   e_cp;                        // Pages in file
        WORD   e_crlc;                      // Relocations
        WORD   e_cparhdr;                   // Size of header in paragraphs
        WORD   e_minalloc;                  // Minimum extra paragraphs needed
        WORD   e_maxalloc;                  // Maximum extra paragraphs needed
        WORD   e_ss;                        // Initial (relative) SS value
        WORD   e_sp;                        // Initial SP value
        WORD   e_csum;                      // Checksum
        WORD   e_ip;                        // Initial IP value
        WORD   e_cs;                        // Initial (relative) CS value
        WORD   e_lfarlc;                    // File address of relocation table
        WORD   e_ovno;                      // Overlay number
        WORD   e_res[4];                    // Reserved words
        WORD   e_oemid;                     // OEM identifier (for e_oeminfo)
        WORD   e_oeminfo;                   // OEM information; e_oemid specific
        WORD   e_res2[10];                  // Reserved words
        LONG   e_lfanew;                    // File address of new exe header
    };

    enum IMAGE_FILE_MACHINE : uint16 {
        IMAGE_FILE_MACHINE_UNKNOWN = 0x0,
        IMAGE_FILE_MACHINE_I386 = 0x14c,
        IMAGE_FILE_MACHINE_IA64 = 0x200,
        IMAGE_FILE_MACHINE_AMD64 = 0x8664,
    };

    struct IMAGE_FILE_HEADER {
        IMAGE_FILE_MACHINE Machine;
        WORD  NumberOfSections;
        DWORD TimeDateStamp;
        DWORD PointerToSymbolTable;
        DWORD NumberOfSymbols;
        WORD  SizeOfOptionalHeader;
        WORD  Characteristics;
    };

    enum HDR_MAGIC : uint16 {
        IMAGE_NT_OPTIONAL_HDR32_MAGIC = 0x10B,
        IMAGE_NT_OPTIONAL_HDR64_MAGIC = 0x20B,
        IMAGE_ROM_OPTIONAL_HDR_MAGIC = 0x107,
    };

    enum HDR_SUBSYSTEM : uint16 {
        IMAGE_SUBSYSTEM_UNKNOWN = 0,
        IMAGE_SUBSYSTEM_NATIVE = 1,
        IMAGE_SUBSYSTEM_WINDOWS_GUI = 2,
        IMAGE_SUBSYSTEM_WINDOWS_CUI = 3,
        IMAGE_SUBSYSTEM_OS2_CUI = 5,
        IMAGE_SUBSYSTEM_POSIX_CUI = 7,
        IMAGE_SUBSYSTEM_WINDOWS_CE_GUI = 9,
        IMAGE_SUBSYSTEM_EFI_APPLICATION = 10,
        IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER = 11,
        IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER = 12,
        IMAGE_SUBSYSTEM_EFI_ROM = 13,
        IMAGE_SUBSYSTEM_XBOX = 14,
        IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION = 16,
    };

    struct IMAGE_DATA_DIRECTORY {
        DWORD VirtualAddress;
        DWORD Size;
    };

    #define IMAGE_NUMBEROF_DIRECTORY_ENTRIES 16

    enum IMAGE_DIRECTORY_ENTRY : uint8 {
        IMAGE_DIRECTORY_ENTRY_EXPORT = 0,
        IMAGE_DIRECTORY_ENTRY_IMPORT = 1,
        IMAGE_DIRECTORY_ENTRY_RESOURCE = 2,
        IMAGE_DIRECTORY_ENTRY_EXCEPTION = 3,
        IMAGE_DIRECTORY_ENTRY_SECURITY = 4,
        IMAGE_DIRECTORY_ENTRY_BASERELOC = 5,
        IMAGE_DIRECTORY_ENTRY_DEBUG = 6,
        IMAGE_DIRECTORY_ENTRY_ARCHITECTURE = 7,
        IMAGE_DIRECTORY_ENTRY_GLOBALPTR = 8,
        IMAGE_DIRECTORY_ENTRY_TLS = 9,
        IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG = 10,
        IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT = 11,
        IMAGE_DIRECTORY_ENTRY_IAT = 12,
        IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT = 13,
        IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR = 14,
    };

    struct IMAGE_OPTIONAL_HEADER32 {
        HDR_MAGIC            Magic;
        BYTE                 MajorLinkerVersion;
        BYTE                 MinorLinkerVersion;
        DWORD                SizeOfCode;
        DWORD                SizeOfInitializedData;
        DWORD                SizeOfUninitializedData;
        DWORD                AddressOfEntryPoint;
        DWORD                BaseOfCode;
        DWORD                BaseOfData;
        DWORD                ImageBase;
        DWORD                SectionAlignment;
        DWORD                FileAlignment;
        WORD                 MajorOperatingSystemVersion;
        WORD                 MinorOperatingSystemVersion;
        WORD                 MajorImageVersion;
        WORD                 MinorImageVersion;
        WORD                 MajorSubsystemVersion;
        WORD                 MinorSubsystemVersion;
        DWORD                Win32VersionValue;
        DWORD                SizeOfImage;
        DWORD                SizeOfHeaders;
        DWORD                CheckSum;
        HDR_SUBSYSTEM        Subsystem;
        WORD                 DllCharacteristics;
        DWORD                SizeOfStackReserve;
        DWORD                SizeOfStackCommit;
        DWORD                SizeOfHeapReserve;
        DWORD                SizeOfHeapCommit;
        DWORD                LoaderFlags;
        DWORD                NumberOfRvaAndSizes;
        IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
    };

    struct IMAGE_OPTIONAL_HEADER64 {
        HDR_MAGIC            Magic;
        BYTE                 MajorLinkerVersion;
        BYTE                 MinorLinkerVersion;
        DWORD                SizeOfCode;
        DWORD                SizeOfInitializedData;
        DWORD                SizeOfUninitializedData;
        DWORD                AddressOfEntryPoint;
        DWORD                BaseOfCode;
        ULONGLONG            ImageBase;
        DWORD                SectionAlignment;
        DWORD                FileAlignment;
        WORD                 MajorOperatingSystemVersion;
        WORD                 MinorOperatingSystemVersion;
        WORD                 MajorImageVersion;
        WORD                 MinorImageVersion;
        WORD                 MajorSubsystemVersion;
        WORD                 MinorSubsystemVersion;
        DWORD                Win32VersionValue;
        DWORD                SizeOfImage;
        DWORD                SizeOfHeaders;
        DWORD                CheckSum;
        HDR_SUBSYSTEM        Subsystem;
        WORD                 DllCharacteristics;
        ULONGLONG            SizeOfStackReserve;
        ULONGLONG            SizeOfStackCommit;
        ULONGLONG            SizeOfHeapReserve;
        ULONGLONG            SizeOfHeapCommit;
        DWORD                LoaderFlags;
        DWORD                NumberOfRvaAndSizes;
        IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
    };

    #define IMAGE_SIZEOF_SHORT_NAME 8

    struct IMAGE_SECTION_HEADER {
        uint8_t	Name[IMAGE_SIZEOF_SHORT_NAME];
        union {
            uint32_t PhysicalAddress;
            uint32_t VirtualSize;
        } Misc;
        uint32_t VirtualAddress;
        uint32_t SizeOfRawData;
        uint32_t PointerToRawData;
        uint32_t PointerToRelocations;
        uint32_t PointerToLinenumbers;
        uint16_t NumberOfRelocations;
        uint16_t NumberOfLinenumbers;
        uint32_t Characteristics;
    };
"""


class StructureView(Static):
    is_minimized = reactive(True, layout=True)

    def __init__(self, ctx: Context, address: int, typename: str, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.ctx = ctx
        self.address = address

        self.type = self.ctx.cparser.typedefs[typename]

        buf = self.ctx.buf[self.address : self.address + self.type.size]
        self.structure = self.type(buf)

    def action_toggle_is_minimized(self):
        self.is_minimized = not self.is_minimized

    def on_click(self, ev):
        self.action_toggle_is_minimized()

    def render(self) -> Text:
        t = Text()

        style_decoration = get_effective_global_color(self, "peapp--decoration")
        style_type = get_effective_global_color(self, "peapp--title")
        style_name = get_effective_global_color(self, "peapp--key")
        style_offset = get_effective_global_color(self, "peapp--decoration")

        # like: struct IMAGE_DOS_HEADER {
        t.append("struct ", style=style_decoration)
        t.append(self.type.name, style=style_type)
        t.append(" @ ", style=style_decoration)
        t.append(f"{self.address:08x}:", style=style_decoration)
        t.append("\n")

        # use a table for formatting the structure fields,
        # so that alignment is easy.

        # like:
        #
        #     Machine          =  IMAGE_FILE_MACHINE_AMD64          @  +0x0
        #     TimeDateStamp    =  2020-02-14T09:27:34Z              @  +0x4
        #     Characteristics  =  IMAGE_FILE_EXECUTABLE_IMAGE       @  +0x12
        table = rich.table.Table(box=None, show_header=False)
        table.add_column("name", style=style_name)
        table.add_column("=", style=style_decoration)
        table.add_column("value")
        table.add_column("@", style=style_decoration)
        table.add_column("offset", style=style_offset)

        has_hidden = False
        key_fields = self.ctx.key_fields.get(self.type.name, set())
        for field in self.type.fields:
            if self.is_minimized:
                if field.name not in key_fields:
                    has_hidden = True
                    continue

            value = getattr(self.structure, field.name)

            key = f"{self.type.name}.{field.name}"
            if key in self.ctx.renderers:
                try:
                    value = self.ctx.renderers[key](value)
                except DontRender:
                    continue
            elif isinstance(value, int):
                value = hex(value)
            elif isinstance(value, EnumInstance):
                # strip of enum name, leaving just the value.
                # like IMAGE_FILE_MACHINE_I386
                value = value.name

            table.add_row(
                str(field.name),
                "=",
                str(value),
                "@",
                "+" + hex(field.offset),
            )

        if self.is_minimized and has_hidden:
            table.add_row(
                "...",
                "",
                "...",
                "",
                "",
            )

        # this is a hack to emit the table into a Text object.
        # the table is supposed to be rendered to a console, which requires a size,
        # so we emulate it here.
        console = rich.console.Console(width=self.size.width, force_terminal=True)
        with console.capture() as capture:
            console.print(table)
        t.append(Text.from_ansi(capture.get()))

        return t


def render_timestamp(v: int) -> str:
    import datetime

    try:
        return datetime.datetime.fromtimestamp(v).isoformat("T") + "Z"
    except ValueError:
        return "(invalid)"


def render_u32(v: int) -> str:
    return f"{v:08x}"


def render_bitflags(bits: List[Tuple[str, int]], v: int) -> str:
    if not v:
        return "(empty)"

    ret = []

    for flag, bit in bits:
        if (v & bit) == bit:
            ret.append(flag)

    return " |\n".join(ret)


def render_characteristics(v: int) -> str:
    bits = [
        ("IMAGE_FILE_RELOCS_STRIPPED", 0x0001),
        ("IMAGE_FILE_EXECUTABLE_IMAGE", 0x0002),
        ("IMAGE_FILE_LINE_NUMS_STRIPPED", 0x0004),
        ("IMAGE_FILE_LOCAL_SYMS_STRIPPED", 0x0008),
        ("IMAGE_FILE_AGGRESIVE_WS_TRIM", 0x0010),
        ("IMAGE_FILE_LARGE_ADDRESS_AWARE", 0x0020),
        ("IMAGE_FILE_16BIT_MACHINE", 0x0040),
        ("IMAGE_FILE_BYTES_REVERSED_LO", 0x0080),
        ("IMAGE_FILE_32BIT_MACHINE", 0x0100),
        ("IMAGE_FILE_DEBUG_STRIPPED", 0x0200),
        ("IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP", 0x0400),
        ("IMAGE_FILE_NET_RUN_FROM_SWAP", 0x0800),
        ("IMAGE_FILE_SYSTEM", 0x1000),
        ("IMAGE_FILE_DLL", 0x2000),
        ("IMAGE_FILE_UP_SYSTEM_ONLY", 0x4000),
        ("IMAGE_FILE_BYTES_REVERSED_HI", 0x8000),
    ]
    return render_bitflags(bits, v)


def render_dll_characteristics(v: int) -> str:
    bits = [
        ("IMAGE_LIBRARY_PROCESS_INIT", 0x0001),  # reserved
        ("IMAGE_LIBRARY_PROCESS_TERM", 0x0002),  # reserved
        ("IMAGE_LIBRARY_THREAD_INIT", 0x0004),  # reserved
        ("IMAGE_LIBRARY_THREAD_TERM", 0x0008),  # reserved
        ("IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA", 0x0020),
        ("IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE", 0x0040),
        ("IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY", 0x0080),
        ("IMAGE_DLLCHARACTERISTICS_NX_COMPAT", 0x0100),
        ("IMAGE_DLLCHARACTERISTICS_NO_ISOLATION", 0x0200),
        ("IMAGE_DLLCHARACTERISTICS_NO_SEH", 0x0400),
        ("IMAGE_DLLCHARACTERISTICS_NO_BIND", 0x0800),
        ("IMAGE_DLLCHARACTERISTICS_APPCONTAINER", 0x1000),
        ("IMAGE_DLLCHARACTERISTICS_WDM_DRIVER", 0x2000),
        ("IMAGE_DLLCHARACTERISTICS_GUARD_CF", 0x4000),
        ("IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE", 0x8000),
    ]
    return render_bitflags(bits, v)


class DontRender(Exception):
    pass


def dont_render(v: Any) -> str:
    raise DontRender()


class SectionView(Widget):
    DEFAULT_CSS = """
        SectionView {
            height: auto;
        }
    """

    def __init__(
        self,
        ctx: Context,
        section: pefile.SectionStructure,
        section_children: Optional[Sequence[Widget]] = None,
        *args,
        **kwargs,
    ):
        super().__init__(*args, **kwargs)

        self.ctx = ctx
        self.section = section
        self.section_children = section_children or []

    @property
    def section_name(self) -> str:
        try:
            return self.section.Name.partition(b"\x00")[0].decode("ascii")
        except UnicodeDecodeError:
            return "(invalid)"

    def compose(self) -> ComposeResult:
        raw_address = self.section.get_PointerToRawData_adj()
        raw_size = self.section.SizeOfRawData

        base_address = self.ctx.pe.OPTIONAL_HEADER.ImageBase
        virtual_address = base_address + self.section.get_VirtualAddress_adj()
        virtual_size = self.section.Misc_VirtualSize

        yield Line(
            Static(self.section_name, classes="peapp--title"),
            Static(f" section @ {raw_address:08x}-{raw_address + raw_size:08x}:", classes="peapp--decoration"),
        )

        table = rich.table.Table(box=None, show_header=False)

        style_key = get_effective_global_color(self, "peapp--key")

        table.add_column("key", style=style_key)
        table.add_column("value")

        table.add_row("virtual address:", f"{virtual_address:08x}")
        table.add_row("virtual size:", f"{virtual_size:#x}")
        # rstrip the section data before computing entropy
        # otherwise the padding biases the results.
        entropy = self.section.entropy_H(self.section.get_data().rstrip(b"\x00"))
        table.add_row("entropy:", "%.02f" % entropy)

        bits = [
            ("IMAGE_SCN_RESERVED_1", 0x00000001),
            ("IMAGE_SCN_RESERVED_2", 0x00000002),
            ("IMAGE_SCN_RESERVED_4", 0x00000004),
            ("IMAGE_SCN_TYPE_NO_PAD", 0x00000008),
            ("IMAGE_SCN_RESERVED_10", 0x00000010),
            ("IMAGE_SCN_CNT_CODE", 0x00000020),
            ("IMAGE_SCN_CNT_INITIALIZED_DATA", 0x00000040),
            ("IMAGE_SCN_CNT_UNINITIALIZED_DATA", 0x00000080),
            ("IMAGE_SCN_LNK_OTHER", 0x00000100),
            ("IMAGE_SCN_LNK_INFO", 0x00000200),
            ("IMAGE_SCN_RESERVED_400", 0x00000400),
            ("IMAGE_SCN_LNK_REMOVE", 0x00000800),
            ("IMAGE_SCN_LNK_COMDAT", 0x00001000),
            ("IMAGE_SCN_GPREL", 0x00008000),
            ("IMAGE_SCN_MEM_PURGEABLE", 0x00020000),
            ("IMAGE_SCN_MEM_16BIT", 0x00020000),
            ("IMAGE_SCN_MEM_LOCKED", 0x00040000),
            ("IMAGE_SCN_MEM_PRELOAD", 0x00080000),
            ("IMAGE_SCN_ALIGN_1BYTES", 0x00100000),
            ("IMAGE_SCN_ALIGN_2BYTES", 0x00200000),
            ("IMAGE_SCN_ALIGN_4BYTES", 0x00300000),
            ("IMAGE_SCN_ALIGN_8BYTES", 0x00400000),
            ("IMAGE_SCN_ALIGN_16BYTES", 0x00500000),
            ("IMAGE_SCN_ALIGN_32BYTES", 0x00600000),
            ("IMAGE_SCN_ALIGN_64BYTES", 0x00700000),
            ("IMAGE_SCN_ALIGN_128BYTES", 0x00800000),
            ("IMAGE_SCN_ALIGN_256BYTES", 0x00900000),
            ("IMAGE_SCN_ALIGN_512BYTES", 0x00A00000),
            ("IMAGE_SCN_ALIGN_1024BYTES", 0x00B00000),
            ("IMAGE_SCN_ALIGN_2048BYTES", 0x00C00000),
            ("IMAGE_SCN_ALIGN_4096BYTES", 0x00D00000),
            ("IMAGE_SCN_ALIGN_8192BYTES", 0x00E00000),
            ("IMAGE_SCN_LNK_NRELOC_OVFL", 0x01000000),
            ("IMAGE_SCN_MEM_DISCARDABLE", 0x02000000),
            ("IMAGE_SCN_MEM_NOT_CACHED", 0x04000000),
            ("IMAGE_SCN_MEM_NOT_PAGED", 0x08000000),
            ("IMAGE_SCN_MEM_SHARED", 0x10000000),
            ("IMAGE_SCN_MEM_EXECUTE", 0x20000000),
            ("IMAGE_SCN_MEM_READ", 0x40000000),
            ("IMAGE_SCN_MEM_WRITE", 0x80000000),
        ]
        table.add_row("characteristics:", render_bitflags(bits, self.section.Characteristics))

        yield Static(table)

        for child in self.section_children:
            yield child

        offset = self.section.get_PointerToRawData_adj()
        length = self.section.SizeOfRawData

        if offset + length > len(self.ctx.buf):
            # the last section may be truncated and rely upon page/section alignment in memory
            length = len(self.ctx.buf) - offset

        yield BinaryView(self.ctx, offset, length, classes="peapp--pane")


class SegmentView(Widget):
    """a view used for regions of the file not covered by a section"""

    DEFAULT_CSS = """
        SegmentView {
            height: auto;
        }
    """

    def __init__(
        self,
        ctx: Context,
        segment: str,
        address: int,
        length: int,
        segment_children: Optional[Sequence[Widget]] = None,
        *args,
        **kwargs,
    ):
        super().__init__(*args, **kwargs)

        self.ctx = ctx
        self.segment = segment
        self.address = address
        self.length = length
        self.segment_children = segment_children or []

    def compose(self) -> ComposeResult:
        yield Line(
            Static(self.segment, classes="peapp--title"),
            Static(f" segment @ {self.address:08x}-{self.address + self.length:08x}:", classes="peapp--decoration"),
        )

        for child in self.segment_children:
            yield child

        yield BinaryView(self.ctx, self.address, self.length, classes="peapp--pane")


class ImportsView(Static):
    def __init__(
        self,
        ctx: Context,
        address: int,
        *args,
        **kwargs,
    ):
        super().__init__(*args, **kwargs)
        self.ctx = ctx
        self.address = address

    def render(self) -> Text:
        t = Text()

        style_title = get_effective_global_color(self, "peapp--title")
        style_decoration = get_effective_global_color(self, "peapp--decoration")
        style_key = get_effective_global_color(self, "peapp--key")

        t.append("import directory table", style=style_title)
        t.append(":", style=style_decoration)
        t.append("\n")

        t.append("  ")
        t.append("imphash", style=style_key)
        t.append(": ", style=style_decoration)
        t.append(self.ctx.pe.get_imphash())
        t.append("\n")

        for dll in self.ctx.pe.DIRECTORY_ENTRY_IMPORT:
            try:
                dll_name = dll.dll.decode("ascii")
            except UnicodeDecodeError:
                dll_name = "(invalid)"

            t.append("  ")
            t.append(dll_name, style=style_key)
            t.append(": ", style=style_decoration)
            t.append("\n")

            for entry in dll.imports:
                if entry.name is None:
                    symbol_name = f"#{entry.ordinal}"
                else:
                    try:
                        symbol_name = entry.name.decode("ascii")
                    except UnicodeDecodeError:
                        symbol_name = "(invalid)"

                t.append("    ")
                t.append(symbol_name)
                t.append("\n")

        return t


class ExportsView(Static):
    def __init__(
        self,
        ctx: Context,
        address: int,
        *args,
        **kwargs,
    ):
        super().__init__(*args, **kwargs)
        self.ctx = ctx
        self.address = address

    def render(self) -> Text:
        t = Text()

        style_title = get_effective_global_color(self, "peapp--title")
        style_decoration = get_effective_global_color(self, "peapp--decoration")
        style_key = get_effective_global_color(self, "peapp--key")

        t.append("export directory table", style=style_title)
        t.append(":", style=style_decoration)
        t.append("\n")

        if not hasattr(self.ctx.pe, "DIRECTORY_ENTRY_EXPORT"):
            t.append("  ")
            t.append("(empty)", style=style_decoration)
            t.append("\n")

        else:
            try:
                dll_name = self.ctx.pe.DIRECTORY_ENTRY_EXPORT.name.partition(b"\x00")[0].decode("ascii")
            except UnicodeDecodeError:
                dll_name = "(invalid)"

            t.append("  ")
            t.append("name", style=style_key)
            t.append(":      ", style=style_decoration)
            t.append(dll_name)
            t.append("\n")

            ts = self.ctx.pe.DIRECTORY_ENTRY_EXPORT.struct.TimeDateStamp
            t.append("  ")
            t.append("timestamp", style=style_key)
            t.append(": ", style=style_decoration)
            t.append(render_timestamp(ts))
            t.append("\n")

            t.append("  ")
            t.append("symbols", style=style_key)
            t.append(":", style=style_decoration)
            t.append("\n")

            for entry in self.ctx.pe.DIRECTORY_ENTRY_EXPORT.symbols:
                try:
                    symbol_name = entry.name.decode("ascii")
                except UnicodeDecodeError:
                    symbol_name = "(invalid)"

                if entry.forwarder is None:
                    t.append("    ")
                    t.append(symbol_name)
                    t.append("\n")
                else:
                    t.append("    ")
                    t.append(symbol_name)
                    t.append(" -> ", style=style_decoration)
                    t.append(entry.forwarder.partition(b"\x00")[0].decode("ascii"))
                    t.append("\n")
        return t


class NavView(Static):
    DEFAULT_CSS = """
        NavView {
            height: 100%;
            width: 24;
            dock: left;

            border-right: tall $background;

            background: $boost;

            border-right: tall $background;
            border-top: tall $background;
            border-bottom: tall $background;

            /* padding: inside the bounding box */
            padding: 0 1;

            /* margin: outside the bounding box */
            margin: 0;
            margin-right: 1;
            margin-top: 1;
            margin-bottom: 1;

            link-style: none;
            link-color: $text-muted;
        }
    """

    def __init__(
        self,
        ctx: Context,
        *args,
        **kwargs,
    ):
        super().__init__(*args, **kwargs)
        self.ctx = ctx

    def action_navigate_to(self, id: str):
        # only an App will not have a parent
        parent = self.parent
        assert parent is not None

        target = parent.query_one(f"#{id}")
        # scroll to top, so the widget is placed in a consistent place.
        # otherwise, sometimes its at the top, or middle, or bottom.
        # animation is distracting (and sometimes janky)
        target.scroll_visible(top=True, animate=False)

    def render(self) -> str:
        lines = []

        for sibling in self.siblings:
            children: Sequence[Widget]
            if isinstance(sibling, MetadataView):
                sibling_name = "metadata"
                children = []
            elif isinstance(sibling, SegmentView):
                sibling_name = f"{sibling.segment} segment"
                children = sibling.segment_children
            elif isinstance(sibling, SectionView):
                sibling_name = f"{sibling.section_name} section"
                children = sibling.section_children
            elif isinstance(sibling, Footer):
                continue
            elif isinstance(sibling, Tooltip):
                # textual may inject these
                continue
            else:
                raise ValueError("unknown sibling type: " + str(type(sibling)))

            lines.append(f"[@click=navigate_to('{sibling.id}')]{sibling_name}[/]")

            for child in children:
                if isinstance(child, StructureView):
                    child_name = (child.name or child.type.name).replace("IMAGE_", "")
                elif isinstance(child, ImportsView):
                    child_name = "import table"
                elif isinstance(child, ExportsView):
                    child_name = "export table"
                else:
                    raise ValueError("unknown child type: " + str(type(child)))

                lines.append(f"  [@click=navigate_to('{child.id}')]{child_name}[/]")

        return "\n".join(lines)


@dataclass
class StructureAt:
    address: int
    type: str


@dataclass
class Region:
    address: int
    length: int
    type: Literal["segment"] | Literal["section"]
    section: Optional[pefile.SectionStructure] = None
    children: List[StructureAt] = dataclasses.field(default_factory=list)

    @property
    def end(self) -> int:
        return self.address + self.length


class MainScreen(Screen):
    DEFAULT_CSS = """
        MainScreen {
            height: 100%;
            width: 100%;
        }
    """

    BINDINGS = [
        Binding("m", "nav_metadata", "Metadata"),
        Binding("i", "nav_imports", "Imports"),
        Binding("e", "nav_exports", "Exports"),
        Binding("q", "quit", "Quit"),
        # vim-like bindings: line, page, home/end
        Binding("j", "scroll_down", "Down", show=False),
        Binding("k", "scroll_up", "Up", show=False),
        Binding("ctrl+f,space", "scroll_page_down", "Page Down", show=False),
        Binding("ctrl+b", "scroll_page_up", "Page Up", show=False),
        Binding("g", "scroll_home", "home", show=False),
        Binding("G", "scroll_end", "end", show=False),
    ]

    def __init__(self, ctx, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.ctx = ctx

    def action_nav_metadata(self):
        target = self.query_one("MetadataView")

        # scroll to top, so the widget is placed in a consistent place.
        # otherwise, sometimes its at the top, or middle, or bottom.
        # animation is distracting (and sometimes janky)
        target.scroll_visible(top=True, animate=False)

    def action_nav_imports(self):
        try:
            target = self.query_one("ImportsView")
        except textual.css.query.NoMatches:
            pass
        else:
            target.scroll_visible(top=True, animate=False)

    def action_nav_exports(self):
        try:
            target = self.query_one("ExportsView")
        except textual.css.query.NoMatches:
            pass
        else:
            target.scroll_visible(top=True, animate=False)

    def action_scroll_down(self):
        self.scroll_relative(
            y=2,
            animate=False,
        )

    def action_scroll_up(self):
        self.scroll_relative(
            y=-2,
            animate=False,
        )

    def action_scroll_page_up(self):
        self.scroll_page_up(
            animate=False,
        )

    def action_scroll_page_down(self):
        self.scroll_page_down(
            animate=False,
        )

    def action_scroll_home(self):
        self.scroll_home(
            animate=False,
        )

    def action_scroll_end(self):
        self.scroll_end(
            animate=False,
        )

    def action_quit(self):
        self.app.exit()

    def collect_file_structures(self) -> Iterable[StructureAt]:
        yield StructureAt(self.ctx.pe.DOS_HEADER.get_file_offset(), "IMAGE_DOS_HEADER")
        yield StructureAt(self.ctx.pe.FILE_HEADER.get_file_offset(), "IMAGE_FILE_HEADER")

        if self.ctx.bitness == 32:
            yield StructureAt(self.ctx.pe.OPTIONAL_HEADER.get_file_offset(), "IMAGE_OPTIONAL_HEADER32")
        elif self.ctx.bitness == 64:
            yield StructureAt(self.ctx.pe.OPTIONAL_HEADER.get_file_offset(), "IMAGE_OPTIONAL_HEADER64")
        else:
            raise ValueError(f"unknown bitness: {self.ctx.bitness}")

        for i, directory in enumerate(self.ctx.pe.OPTIONAL_HEADER.DATA_DIRECTORY):
            if directory.VirtualAddress == 0 or directory.Size == 0:
                continue

            enum = self.ctx.cparser.typedefs["IMAGE_DIRECTORY_ENTRY"]
            name = enum.reverse[i]

            directory_offset = self.ctx.pe.get_offset_from_rva(directory.VirtualAddress)

            if name == "IMAGE_DIRECTORY_ENTRY_IMPORT":
                yield StructureAt(directory_offset, "DIRECTORY_ENTRY_IMPORT")

            elif name == "IMAGE_DIRECTORY_ENTRY_EXPORT":
                yield StructureAt(directory_offset, "DIRECTORY_ENTRY_EXPORT")

            # DIRECTORY_ENTRY_RESOURCE (ResourceDirData instance)
            # DIRECTORY_ENTRY_DEBUG (list of DebugData instances)
            # DIRECTORY_ENTRY_BASERELOC (list of BaseRelocationData instances)
            # DIRECTORY_ENTRY_TLS
            # DIRECTORY_ENTRY_BOUND_IMPORT (list of BoundImportData instances)

    def compute_file_regions(self) -> Tuple[Region, ...]:
        regions = []

        for section in sorted(self.ctx.pe.sections, key=lambda s: s.PointerToRawData):
            regions.append(Region(section.get_PointerToRawData_adj(), section.SizeOfRawData, "section", section))

        # segment that contains all data until the first section
        regions.insert(0, Region(0, regions[0].address, "segment"))

        # segment that contains all data after the last section
        # aka. "overlay"
        last_section = regions[-1]
        if last_section.end < len(self.ctx.buf):
            regions.append(Region(last_section.end, len(self.ctx.buf) - last_section.end, "segment"))

        # add segments for any gaps between sections.
        # note that we append new items to the end of the list and then resort,
        # to avoid mutating the list while we're iterating over it.
        for i in range(1, len(regions)):
            prior = regions[i - 1]
            region = regions[i]

            if prior.end != region.address:
                regions.append(Region(prior.end, region.address - prior.end, "segment"))
        regions.sort(key=lambda s: s.address)

        for structure in self.collect_file_structures():
            for region in regions:
                if structure.address >= region.address and structure.address < region.end:
                    region.children.append(structure)
                    break

        return tuple(regions)

    def compose(self) -> ComposeResult:
        id_generator = map(lambda i: f"id-{i}", range(1000))

        yield NavView(self.ctx, id=next(id_generator))
        yield MetadataView(self.ctx, classes="peapp--pane", id=next(id_generator))

        # sections
        # TODO: rich header (hex, parsed)
        # TODO: resources

        regions = self.compute_file_regions()
        for i, region in enumerate(regions):
            children: List[Widget] = []

            for child in region.children:
                if child.type == "DIRECTORY_ENTRY_IMPORT":
                    children.append(ImportsView(self.ctx, child.address, classes="peapp--pane", id=next(id_generator)))
                elif child.type == "DIRECTORY_ENTRY_EXPORT":
                    children.append(ExportsView(self.ctx, child.address, classes="peapp--pane", id=next(id_generator)))
                else:
                    children.append(
                        StructureView(self.ctx, child.address, child.type, classes="peapp--pane", id=next(id_generator))
                    )

            if region.type == "segment":
                if i == 0:
                    name = "header"
                elif i == len(regions) - 1:
                    name = "overlay"
                else:
                    name = "gap"

                if self.ctx.buf[region.address : region.end].count(0) == region.length:
                    # if segment is all NULLs, don't show it (header/gap/overlay)
                    continue

                yield SegmentView(
                    self.ctx,
                    name,
                    region.address,
                    region.length,
                    segment_children=children,
                    classes="peapp--pane",
                    id=next(id_generator),
                )

            elif region.type == "section":
                yield SectionView(
                    self.ctx, region.section, section_children=children, classes="peapp--pane", id=next(id_generator)
                )

            else:
                raise ValueError(f"unknown region type: {region.type}")

        yield Footer()


class TitleScreen(Screen):
    DEFAULT_CSS = """
        TitleScreen {
            height: 100%;
            width: 100%;
            align: center middle;
        }
    """

    def compose(self) -> ComposeResult:
        yield Label(textwrap.dedent("""\
          _____                   _____          
         /\    \                 /\    \         
        /::\____\               /::\    \        
       /::::|   |               \:::\    \       
      /:::::|   |                \:::\    \      
     /::::::|   |                 \:::\    \     
    /:::/|::|   |                  \:::\    \    
   /:::/ |::|   |                   \:::\    \   
  /:::/  |::|___|______              \:::\    \  
 /:::/   |::::::::\    \              \:::\    \ 
/:::/    |:::::::::\____\______________\:::\____\ 
\::/    / ~~~~~/:::/    \::::::::::::::::::/    /
 \/____/      /:::/    / \::::::::::::::::/    / 
             /:::/    /   \:::\~~~~\~~~~~~-----
            /:::/    /     \:::\    \            
           /:::/    /       \:::\    \           
          /:::/    /         \:::\    \          
         /:::/    /           \:::\    \         
        /:::/    /             \:::\____\        
        \::/    /               \::/    /        
         \/____/                 \/____/         

            mz: yet another PE viewer



           drag 'n drop a PE file here
        """.rstrip()), classes="logo")
        # TODO: don't ask for DnD when on console
        # or handle that event.


class PEApp(App):
    TITLE = "pe"
    DEFAULT_CSS = """
        /* major name, such as structure or section name */
        .peapp--title {
            color: $secondary;
        }

        /* minor name, such as import dll name */
        .peapp--key {
            color: $accent;
        }

        .peapp--address {
            color: $accent;
        }

        .peapp--decoration {
            color: $text-muted;
        }

        .peapp--muted {
            color: $text-muted;
        }

        .peapp--pane {
            /* appear as a new layer on top of the screen */
            background: $boost;

            /* border takes an extra line, but is visually nicer for regions. */
            /* use `tall` or `wide` only with background: boost */
            /* use other styles when there's not a boost/new layer */
            border: tall $background;

            /* padding: inside the bounding box */
            /* padding-y: 0 */
            /* padding-x: 1 */
            padding: 0 1;

            /* margin: outside the bounding box */
            /* margin: 0 on all sides but top */
            margin: 0;
            margin-top: 1;
        }
    """

    def __init__(self, path: pathlib.Path | None = None, buf: bytearray | None = None, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.title = "mz"
        self.path = path
        self.buf = buf

    def on_mount(self):
        if self.path and self.buf:
            # if the App was initialized with path/buf, render them immediately
            # otherwise, see on_notified
            ctx = Context.from_bytes(self.path, self.buf)
            self.push_screen(MainScreen(ctx))
        else:
            self.push_screen(TitleScreen())

    def on_notified(self, message):
        """application-specific message provided by the application host"""
        try:
            import js
        except ImportError:
            # not in pyodide environment,
            # so we won't be getting these messages
            return

        path = pathlib.Path(message.data.path)
        buf = bytes(message.data.buf.to_py())

        try:
            ctx = Context.from_bytes(path, buf)
        except Exception as e:
            js.console.log("error: failed to parse PE: " + str(e))
            return

        # either TitleScreen or existing MainScreen
        self.pop_screen()
        self.push_screen(MainScreen(ctx))


async def main(argv=None):
    from textual.logging import TextualHandler

    if argv is None:
        argv = sys.argv[1:]

    parser = argparse.ArgumentParser(description="Portable Executable viewer.")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable debug logging")
    parser.add_argument("-q", "--quiet", action="store_true", help="Disable all output but errors")
    parser.add_argument("--dev", action="store_true", help="Run app in textual dev mode")
    parser.add_argument("path", type=str, help="path to PE file to inspect")
    args = parser.parse_args(args=argv)

    if args.verbose:
        logging.basicConfig(level=logging.DEBUG, handlers=[TextualHandler()])
    elif args.quiet:
        logging.basicConfig(level=logging.CRITICAL, handlers=[TextualHandler()])
    else:
        logging.basicConfig(level=logging.INFO, handlers=[TextualHandler()])

    if args.dev:
        # so we can use the textual console.
        #
        # undocumented, so probably subject to change:
        # https://github.com/Textualize/textual/blob/d9a229ff0f6b77171fbf61cefc851c4d7498b200/src/textual/cli/cli.py#LL77C5-L77C55
        os.environ["TEXTUAL"] = ",".join(sorted(["debug", "devtools"]))

    path = pathlib.Path(args.path)
    if not path.exists():
        logging.error("%s does not exist", path)
        return 1

    with path.open("rb") as f:
        WHOLE_FILE = 0
        with mmap.mmap(f.fileno(), length=WHOLE_FILE, access=mmap.ACCESS_READ) as mm:
            # treat the mmap as a readable bytearray
            buf: bytearray = mm  # type: ignore

            app = PEApp(path, buf)
            await app.run_async()

    # silly graceful shutdown to avoid ResourceWarning
    # see here: https://docs.aiohttp.org/en/stable/client_advanced.html#graceful-shutdown
    await asyncio.sleep(0.125)


if __name__ == "__main__":
    import os
    import sys
    import mmap
    import argparse


    sys.exit(asyncio.run(main()))
elif __name__ == "__pyodide__":
    app = PEApp()

    # pyodide provides an async event loop
    # (in fact, we're already running in a coroutine)
    # so we need to use that one, and not directly call app.run().
    loop = asyncio.get_running_loop()
    
    asyncio.run_coroutine_threadsafe(
        app.run_async(),
        loop=loop,
    )
