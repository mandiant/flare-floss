import gzip
import hashlib
import pathlib
import pkgutil
import datetime
from typing import Set, Dict, List, Literal, Optional, Sequence
from collections import defaultdict
from dataclasses import dataclass

import msgspec

import floss.qs.db

Encoding = Literal["ascii"] | Literal["utf-16le"] | Literal["unknown"]
# header | gap | overlay
# or section name
Location = Literal["header"] | Literal["gap"] | Literal["overlay"] | str


class Metadata(msgspec.Struct):
    note: str | None
    timestamp: str | None
    type: str = "global_prevalence"
    version: str = "1.0"


class StringGlobalPrevalence(msgspec.Struct):
    string: str
    encoding: Encoding
    global_count: int
    location: Location | None


@dataclass
class StringGlobalPrevalenceDatabase:
    meta: Metadata
    metadata_by_string: Dict[str, List[StringGlobalPrevalence]]

    def __len__(self) -> int:
        return len(self.metadata_by_string)

    def insert(self, str_gp: StringGlobalPrevalence):
        # TODO combine if existing data
        self.metadata_by_string[str_gp.string].append(str_gp)

    def query(self, string):
        return self.metadata_by_string.get(string, [])

    def update(self, other: "StringGlobalPrevalenceDatabase"):
        # TODO combine if existing data
        self.metadata_by_string.update(other.metadata_by_string)

    @classmethod
    def new_db(cls, note: Optional[str] = None):
        return cls(
            meta=Metadata(timestamp=datetime.datetime.now().isoformat(), note=note),
            metadata_by_string=defaultdict(list),
        )

    @classmethod
    def load_database(cls, buf: bytes, compress: bool = True) -> "StringGlobalPrevalenceDatabase":
        metadata_by_string: Dict[str, List[StringGlobalPrevalence]] = defaultdict(list)

        if compress:
            lines = gzip.decompress(buf).split(b"\n")
        else:
            lines = buf.split(b"\n")

        decoder = msgspec.json.Decoder(type=StringGlobalPrevalence)
        for line in lines[1:]:
            if not line:
                continue
            s = decoder.decode(line)

            metadata_by_string[s.string].append(s)

        return cls(
            meta=msgspec.json.Decoder(type=Metadata).decode(lines[0]),
            metadata_by_string=metadata_by_string,
        )
    
    @classmethod
    def from_file(cls, path: pathlib.Path, compress: bool = True) -> "StringGlobalPrevalenceDatabase":
        return cls.load_database(path.read_bytes(), compress)
    
    @classmethod
    def from_pkgutil(cls, package: str, path: str, compress: bool = True) -> "StringGlobalPrevalenceDatabase":
        return cls.load_database(pkgutil.get_data(package, path), compress)

    def to_file(self, outfile: str, compress: bool = True):
        if compress:
            with gzip.open(outfile, "w") as f:
                f.write(msgspec.json.encode(self.meta) + b"\n")
                for k, v in sorted(self.metadata_by_string.items(), key=lambda x: x[1][0].global_count, reverse=True):
                    # TODO needs fixing to write most common to least common
                    for e in v:
                        f.write(msgspec.json.encode(e) + b"\n")
        else:
            with open(outfile, "w", encoding="utf-8") as f:
                f.write(msgspec.json.encode(self.meta).decode("utf-8") + "\n")
                for k, v in sorted(self.metadata_by_string.items(), key=lambda x: x[1][0].global_count, reverse=True):
                    for e in v:
                        f.write(msgspec.json.encode(e).decode("utf-8") + "\n")


@dataclass
class StringHashDatabase:
    string_hashes: Set[bytes]

    def __len__(self) -> int:
        return len(self.string_hashes)

    def __contains__(self, other: bytes | str) -> bool:
        if isinstance(other, bytes):
            return other in self.string_hashes
        elif isinstance(other, str):
            m = hashlib.md5()
            m.update(other.encode("utf-8"))
            return m.digest()[:8] in self.string_hashes
        else:
            raise ValueError("other must be bytes or str")

    @classmethod
    def load_database(cls, buf: bytes) -> "StringHashDatabase":
        string_hashes: Set[bytes] = set()

        for i in range(0, len(buf), 8):
            string_hashes.add(buf[i : i + 8])

        return cls(
            string_hashes=string_hashes,
        )
    
    @classmethod
    def from_file(cls, path: pathlib.Path) -> "StringHashDatabase":
        return cls.load_database(path.read_bytes())
    
    @classmethod
    def from_pkgutil(cls, package: str, path: str) -> "StringHashDatabase":
        return cls.load_database(pkgutil.get_data(package, path))


DEFAULT_PATHS = (
    "data/gp/gp.jsonl.gz",
    "data/gp/cwindb-native.jsonl.gz",
    "data/gp/cwindb-dotnet.jsonl.gz",
    "data/gp/xaa-hashes.bin",
    "data/gp/yaa-hashes.bin",
)


def get_default_databases() -> Sequence[StringGlobalPrevalenceDatabase | StringHashDatabase]:
    # To use from_file
    # return [
    #     StringGlobalPrevalenceDatabase.from_file(pathlib.Path(floss.qs.db.__file__).parent / path)
    #     if path.endswith(".jsonl.gz")
    #     else StringHashDatabase.from_file(pathlib.Path(floss.qs.db.__file__).parent / path)
    #     for path in DEFAULT_PATHS
    # ]

    return [
         StringGlobalPrevalenceDatabase.from_pkgutil("floss.qs.db", path)
         if path.endswith(".jsonl.gz")
         else StringHashDatabase.from_pkgutil("floss.qs.db", path)
         for path in DEFAULT_PATHS
    ]
