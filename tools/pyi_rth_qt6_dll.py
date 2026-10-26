"""Keep the bundled Qt 6 DLL directory available for the app lifetime."""

import os
import sys


if sys.platform == "win32" and getattr(sys, "frozen", False):
    _qt6_bin = os.path.join(sys._MEIPASS, "PyQt6", "Qt6", "bin")
    if os.path.isdir(_qt6_bin):
        _qt6_dll_directory_cookie = os.add_dll_directory(_qt6_bin)
        os.environ["PATH"] = _qt6_bin + os.pathsep + os.environ.get("PATH", "")
