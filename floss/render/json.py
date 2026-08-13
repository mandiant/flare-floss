# Copyright 2022 Google LLC
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


import json
import datetime
import dataclasses

from floss.results import ResultDocument


class FlossJSONEncoder(json.JSONEncoder):
    """
    serializes FLOSS data structures into JSON.
    specifically:
      - dataclasses into their dict representation
      - datetimes to ISO8601 strings
    """

    def default(self, o):
        if dataclasses.is_dataclass(o):
            return dataclasses.asdict(o)  # type: ignore [arg-type]
        if isinstance(o, datetime.datetime):
            if o.tzinfo is not None:
                o = o.astimezone(datetime.timezone.utc)
                return o.isoformat("T").replace("+00:00", "Z")
            return o.isoformat("T") + "Z"
        return super().default(o)


def sort_nested(obj):
    """recursively sort dict keys, preserving the given top-level ordering.

    the top level of a results document is kept in a fixed field order so the
    small ``metadata`` block always appears near the start of the file; nested
    dict keys are still emitted in sorted order.
    """
    if isinstance(obj, dict):
        return {key: sort_nested(value) for key, value in sorted(obj.items())}
    if isinstance(obj, list):
        return [sort_nested(value) for value in obj]
    return obj


# top-level key order of a results document.
# metadata is deliberately first: it is small, so a results document is always
# recognizable from its leading bytes by detect_file_type.
TOP_LEVEL_KEYS = ("metadata", "analysis", "strings", "layout")


def render(doc: ResultDocument) -> str:
    data = dataclasses.asdict(doc)
    top = {key: sort_nested(data[key]) for key in TOP_LEVEL_KEYS if key in data}
    return json.dumps(top, cls=FlossJSONEncoder, sort_keys=False)
