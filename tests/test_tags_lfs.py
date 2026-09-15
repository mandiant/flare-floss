# Copyright 2026 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import pytest

import floss.tags.gp
import floss.tags.oss
import floss.tags.expert
import floss.tags.winapi
from floss.tags import ensure_not_lfs_pointer

LFS_POINTER = b"version https://git-lfs.github.com/spec/v1\noid sha256:0" * 4 + b"\nsize 123\n"


def test_ensure_not_lfs_pointer_raises(tmp_path):
    path = tmp_path / "db.bin"
    path.write_bytes(LFS_POINTER)
    with pytest.raises(ValueError, match="Git LFS pointer detected"):
        ensure_not_lfs_pointer(path)


def test_ensure_not_lfs_pointer_ok(tmp_path):
    path = tmp_path / "db.bin"
    path.write_bytes(b"not an lfs pointer")
    ensure_not_lfs_pointer(path)


def test_oss_loader_rejects_lfs_pointer(tmp_path):
    path = tmp_path / "oss.jsonl.gz"
    path.write_bytes(LFS_POINTER)
    with pytest.raises(ValueError, match="Git LFS pointer detected"):
        floss.tags.oss.OpenSourceStringDatabase.from_file(path)


def test_expert_loader_rejects_lfs_pointer(tmp_path):
    path = tmp_path / "expert.jsonl.gz"
    path.write_bytes(LFS_POINTER)
    with pytest.raises(ValueError, match="Git LFS pointer detected"):
        floss.tags.expert.ExpertStringDatabase.from_file(path)


def test_winapi_loader_rejects_lfs_pointer(tmp_path):
    path = tmp_path / "winapi"
    path.mkdir()
    (path / "dlls.txt.gz").write_bytes(LFS_POINTER)
    (path / "apis.txt.gz").write_bytes(LFS_POINTER)
    with pytest.raises(ValueError, match="Git LFS pointer detected"):
        floss.tags.winapi.WindowsApiStringDatabase.from_dir(path)


def test_gp_loader_rejects_lfs_pointer(tmp_path):
    path = tmp_path / "hashes.bin"
    path.write_bytes(LFS_POINTER)
    with pytest.raises(ValueError, match="Git LFS pointer detected"):
        floss.tags.gp.StringHashDatabase.from_file(path)
