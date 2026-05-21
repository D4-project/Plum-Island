#!/usr/bin/env python3
"""
Compatibility wrapper for tag YAML import.

Use tools/tag_mgmt.py for the merged tag management CLI.
"""

from tag_mgmt import import_rules, run_legacy_import

if __name__ == "__main__":
    run_legacy_import()
