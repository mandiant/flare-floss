import gzip
import pathlib
from typing import Dict, Sequence
from dataclasses import dataclass

import msgspec

import floss.qs.db


class OpenSourceString(msgspec.Struct):
    string: str
    library_name: str
    library_version: str
    file_path: str | None = None
    function_name: str | None = None
    line_number: int | None = None


@dataclass
class OpenSourceStringDatabase:
    metadata_by_string: Dict[str, OpenSourceString]

    def __len__(self) -> int:
        return len(self.metadata_by_string)

    @classmethod
    def from_file(cls, path: pathlib.Path) -> "OpenSourceStringDatabase":
        metadata_by_string: Dict[str, OpenSourceString] = {}
        decoder = msgspec.json.Decoder(type=OpenSourceString)
        for line in gzip.decompress(path.read_bytes()).split(b"\n"):
            if not line:
                continue
            s = decoder.decode(line)
            metadata_by_string[s.string] = s

        return cls(metadata_by_string=metadata_by_string)


DEFAULT_FILENAMES = (
    "brotli.jsonl.gz",
    "bzip2.jsonl.gz",
    "cryptopp.jsonl.gz",
    "curl.jsonl.gz",
    "detours.jsonl.gz",
    "jemalloc.jsonl.gz",
    "jsoncpp.jsonl.gz",
    "kcp.jsonl.gz",
    "liblzma.jsonl.gz",
    "libsodium.jsonl.gz",
    "libpcap.jsonl.gz",
    "mbedtls.jsonl.gz",
    "openssl.jsonl.gz",
    "sqlite3.jsonl.gz",
    "tomcrypt.jsonl.gz",
    "wolfssl.jsonl.gz",
    "zlib.jsonl.gz",
)

DEFAULT_PATHS = tuple(
    pathlib.Path(floss.qs.db.__file__).parent / "data" / "oss" / filename for filename in DEFAULT_FILENAMES
) + (pathlib.Path(floss.qs.db.__file__).parent / "data" / "crt" / "msvc_v143.jsonl.gz",)


def get_default_databases() -> Sequence[OpenSourceStringDatabase]:
    return [OpenSourceStringDatabase.from_file(path) for path in DEFAULT_PATHS]
