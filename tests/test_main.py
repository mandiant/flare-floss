# Copyright (C) 2020 Mandiant, Inc. All Rights Reserved.

import pytest
import fixtures
from fixtures import exefile

import floss.main


def test_main_help():
    for help_str in ("-h", "-H"):
        # via https://medium.com/python-pandemonium/testing-sys-exit-with-pytest-10c6e5f7726f
        with pytest.raises(SystemExit) as pytest_wrapped_e:
            floss.main.main([help_str])
        assert pytest_wrapped_e.type == SystemExit
        assert pytest_wrapped_e.value.code == 0


def test_main(exefile):
    assert floss.main.main([exefile]) == 0
