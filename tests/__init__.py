"""Test package bootstrap - makes the suite run from a FRESH CLONE."""

import os
import sys

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _c in (os.path.join(_ROOT, "src"), _ROOT):
    if os.path.isdir(os.path.join(_c, "jumpper")):
        if _c not in sys.path:
            sys.path.insert(0, _c)
        break
