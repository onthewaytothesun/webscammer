#!/usr/bin/env python3
"""Tiny test runner (no pytest dependency)."""
import tests.test_core as t

fns = [f for f in dir(t) if f.startswith("test_")]
fail = 0
for name in fns:
    try:
        getattr(t, name)()
    except Exception as exc:  # noqa: BLE001
        fail += 1
        print("FAIL", name, "->", exc)
print(f"{len(fns) - fail}/{len(fns)} passed")
raise SystemExit(1 if fail else 0)
