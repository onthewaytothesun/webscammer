#!/usr/bin/env python3
"""Tiny test runner (no pytest dependency): runs every tests/test_*.py."""
import glob
import importlib
import os
import unittest

os.chdir(os.path.dirname(os.path.abspath(__file__)))
total = failed = skipped = 0
for path in sorted(glob.glob("tests/test_*.py")):
    module = importlib.import_module(path[:-3].replace(os.sep, "."))
    for name in sorted(n for n in dir(module) if n.startswith("test_")):
        total += 1
        try:
            getattr(module, name)()
        except unittest.SkipTest as why:
            skipped += 1
            print("skip", f"{module.__name__}.{name}", "-", why)
        except Exception as exc:  # noqa: BLE001
            failed += 1
            print("FAIL", f"{module.__name__}.{name}", "->", repr(exc))
print(f"{total - failed - skipped}/{total} passed" + (f", {skipped} skipped" if skipped else ""))
raise SystemExit(1 if failed else 0)
