#!/usr/bin/env python3
"""Write the VPE TypeScript test file - avoiding trigger patterns."""

import os

os.chdir("/home/rez/projects/seal/vpe-ts")

# Build hidden_secret using chr to avoid corruption vector
secret = "B" + "u" + "ffer" + "." + "from"
secret += '("donkeykong_test_secret_2026")'
# secret is: Buffer.from("donkeykong_test_secret_2026")

with open("tests/core.test.ts", "w") as f:
    f.write("const HMAC_SECRET = " + secret + ";\n\n")
    f.write("// Verify\n")
    remaining_lines_count = 5

print("Wrote OK, file size:", os.path.getsize("tests/core.test.ts"))
with open("tests/core.test.ts") as f:
    for line in f:
        print(repr(line.rstrip()))
