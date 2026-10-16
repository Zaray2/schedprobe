"""Test package for schedprobe.

The suite runs on the standard library alone::

    python -m unittest discover -s tests -t . -v

``pytest`` works too (``pytest -q``) because the tests are plain ``unittest`` cases,
but it is not required - an offensive-security tool whose test-suite needs a plugin
ecosystem is a tool nobody runs in a locked-down environment.
"""
