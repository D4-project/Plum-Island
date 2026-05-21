#!/usr/bin/env python3
"""
Compatibility wrapper for tag reindexing.

Use tools/tag_mgmt.py for the merged tag management CLI.
"""

from tag_mgmt import run_legacy_reindex

if __name__ == "__main__":
    run_legacy_reindex()
