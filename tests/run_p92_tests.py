#!/usr/bin/env python3
import subprocess
import sys

r = subprocess.run(
    [sys.executable, "-m", "pytest", "/home/rez/projects/seal/tests/test_key_lifecycle.py", "-v", "--tb=short"],
    cwd="/home/rez/projects/seal",
    capture_output=True,
    text=True,
    timeout=60,
)
o = r.stdout
if r.stderr:
    o += "\nSTDERR:\n" + r.stderr
o += f"\nEXIT CODE: {r.returncode}"
print(o)
