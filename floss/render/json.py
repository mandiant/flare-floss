# Copyright (C) 2022 Mandiant, Inc. All Rights Reserved.

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
            return dataclasses.asdict(o)
        if isinstance(o, datetime.datetime):
            return o.isoformat("T") + "Z"
        return super().default(o)


def render(doc: ResultDocument) -> str:
    return json.dumps(
        doc,
        cls=FlossJSONEncoder,
        sort_keys=True,
    )
