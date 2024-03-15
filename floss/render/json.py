# Copyright (C) 2022 Mandiant, Inc. All Rights Reserved.

import json
import datetime
import dataclasses

from floss.results import ResultDocument


class FlossJSONEncoder(json.JSONEncoder):
    """
    Custom JSON encoder for serializing FLOSS data structures.

    Handles the following special cases:

    *   Dataclasses: Converts dataclass instances into their dictionary representations.
    *   Datetimes: Encodes datetime objects into ISO 8601 formatted strings (with timezone information).
    """

    def default(self, o):
        """
        Overrides the default JSON encoding behavior to handle dataclasses and datetime objects.

        Args:
            o: The object to encode.

        Returns:
            The JSON-serializable representation of the object. 

        """
        if dataclasses.is_dataclass(o):
            return dataclasses.asdict(o)
        if isinstance(o, datetime.datetime):
            return o.isoformat("T") + "Z"
        return super().default(o)


def render(doc: ResultDocument) -> str:
    """
    Serializes a ResultDocument into a JSON string.

    Uses the custom `FlossJSONEncoder` to ensure correct handling of dataclasses and datetime objects within the analysis results.

    Args:
        doc: The ResultDocument object containing analysis results.

    Returns:
        str: A JSON-formatted string representation of the ResultDocument.
    """
    return json.dumps(
        doc,
        cls=FlossJSONEncoder,
        sort_keys=True,
    )
