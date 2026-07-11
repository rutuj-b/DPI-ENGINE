"""Test suite for the DPI engine.

Ensures the ``src`` layout is importable regardless of the test runner.
"""

import os
import sys

_SRC = os.path.join(os.path.dirname(os.path.dirname(__file__)), "src")
if _SRC not in sys.path:
    sys.path.insert(0, _SRC)
