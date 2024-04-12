import gzip
import pathlib
import pkgutil
from typing import Set, Sequence
from dataclasses import dataclass

import floss.qs.db


@dataclass
class WindowsApiStringDatabase:
    dll_names: Set[str]
    api_names: Set[str]

    def __len__(self) -> int:
        return len(self.dll_names) + len(self.api_names)

    @classmethod
    def load_database(cls, buf: bytes) -> Set[str]:
        names: Set[str] = set()
        for line in gzip.decompress(buf).decode("utf-8").splitlines():
            if not line:
                continue
            names.add(line)

        return names

    @classmethod
    def from_dir(cls, path: pathlib.Path) -> "WindowsApiStringDatabase":
        dll_names = cls.load_database((path / "dlls.txt.gz").read_bytes())
        api_names = cls.load_database((path / "apis.txt.gz").read_bytes())

        return cls(dll_names=dll_names, api_names=api_names)

    @classmethod
    def from_pkgutil(cls, package: str, path: str) -> "WindowsApiStringDatabase":
        dll_names = cls.load_database(pkgutil.get_data(package, (path + "dlls.txt.gz")))
        api_names = cls.load_database(pkgutil.get_data(package, (path + "apis.txt.gz")))
        return cls(dll_names=dll_names, api_names=api_names)


DEFAULT_PATHS = ("data/winapi/",)


def get_default_databases() -> Sequence[WindowsApiStringDatabase]:
    # To use from_file
    # return [WindowsApiStringDatabase.from_dir(pathlib.Path(floss.qs.db.__file__).parent / path) for path in DEFAULT_PATHS]

    return [WindowsApiStringDatabase.from_pkgutil('floss.qs.db', path) for path in DEFAULT_PATHS]
