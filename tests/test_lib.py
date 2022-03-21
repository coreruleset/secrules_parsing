# -*- coding: utf-8 -*-
import secrules_parsing


def test_version():
    """ Test we export the correct version """
    assert (secrules_parsing.__version__) == "0.1.0", \
        "Incorrect version found"
