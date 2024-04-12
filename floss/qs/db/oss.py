import gzip
import pathlib
import pkgutil
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
    def load_database(cls, buf: bytes) -> "OpenSourceStringDatabase":
        metadata_by_string: Dict[str, OpenSourceString] = {}
        decoder = msgspec.json.Decoder(type=OpenSourceString)
        for line in gzip.decompress(buf).split(b"\n"):
            if not line:
                continue
            s = decoder.decode(line)
            metadata_by_string[s.string] = s

        return cls(metadata_by_string=metadata_by_string)

    @classmethod
    def from_file(cls, path: pathlib.Path) -> "OpenSourceStringDatabase":
        return cls.load_database(path.read_bytes())

    @classmethod
    def from_pkgutil(cls, package: str, path: str) -> "OpenSourceStringDatabase":
        return cls.load_database(pkgutil.get_data(package, path))


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

DEFAULT_PATHS = tuple("data/oss/" + f for f in DEFAULT_FILENAMES) + ("data/crt/msvc_v143.jsonl.gz",)


def get_default_databases() -> Sequence[OpenSourceStringDatabase]:
    # To use from_file
    # return [OpenSourceStringDatabase.from_file(pathlib.Path(floss.qs.db.__file__).parent / path) for path in DEFAULT_PATHS]

    return [OpenSourceStringDatabase.from_pkgutil("floss.qs.db", path) for path in DEFAULT_PATHS]
