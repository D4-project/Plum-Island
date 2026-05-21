#!/usr/bin/env python3
"""
Root wrapper for tools/tag_mgmt.py.
"""

import runpy
import os
import sys
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
VENV_PYTHON = BASE_DIR / ".venv" / "bin" / "python"
if VENV_PYTHON.exists() and Path(sys.executable) != VENV_PYTHON:
    os.execv(str(VENV_PYTHON), [str(VENV_PYTHON), __file__, *sys.argv[1:]])

TOOLS_DIR = BASE_DIR / "tools"
sys.path.insert(0, str(TOOLS_DIR))
runpy.run_path(str(TOOLS_DIR / "tag_mgmt.py"), run_name="__main__")
