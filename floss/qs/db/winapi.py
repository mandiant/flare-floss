import gzip
import pkgutil
from typing import Set, Sequence
from dataclasses import dataclass


@dataclass
class WindowsApiStringDatabase:
    dll_names: Set[str]
    api_names: Set[str]

    def __len__(self) -> int:
        return len(self.dll_names) + len(self.api_names)

    @classmethod
    def from_dir(cls, package: str, path: str) -> "WindowsApiStringDatabase":
        dll_names: Set[str] = set()
        api_names: Set[str] = set()

        for line in gzip.decompress(pkgutil.get_data(package, path + "/dlls.txt.gz")).decode("utf-8").splitlines():
            if not line:
                continue
            dll_names.add(line)

        for line in gzip.decompress(pkgutil.get_data(package, path + "/apis.txt.gz")).decode("utf-8").splitlines():
            if not line:
                continue
            api_names.add(line)

        return cls(dll_names=dll_names, api_names=api_names)


DEFAULT_PATHS = (
    'data/winapi/',
)


def get_default_databases() -> Sequence[WindowsApiStringDatabase]:
    return [WindowsApiStringDatabase.from_dir("floss.qs.db", path) for path in DEFAULT_PATHS]
