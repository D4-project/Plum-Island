#!/usr/bin/env python3
"""
Run all Python unit tests in this directory.
"""

import os
import sys
import unittest
from pathlib import Path


def main():
    """
    Discover and run test_*.py unittest modules from the test directory.
    """
    test_dir = Path(__file__).resolve().parent
    repo_dir = test_dir.parent
    webapp_dir = repo_dir / "webapp"

    sys.path.insert(0, str(webapp_dir))
    os.chdir(repo_dir)

    suite = unittest.defaultTestLoader.discover(
        start_dir=str(test_dir),
        pattern="test_*.py",
        top_level_dir=str(repo_dir),
    )
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    raise SystemExit(main())
