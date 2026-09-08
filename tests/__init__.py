"""Test package bootstrap.

Makes `python -m unittest tests.test_jumpper` work from a FRESH CLONE, where the
package lives at src/jumpper and nothing is installed. Without this the suite is
green only on a developer machine that happens to have the right sys.path - which
is exactly the failure mode this project exists to prevent.
"""

import os
import sys

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _cand in (os.path.join(_ROOT, "src"), _ROOT):
    if os.path.isdir(os.path.join(_cand, "jumpper")):
        if _cand not in sys.path:
            sys.path.insert(0, _cand)
        break
