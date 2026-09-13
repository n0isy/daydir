#!/usr/bin/env python3
"""Assemble the single daydir PE directly with NASM; no linker or Windows SDK."""
from datetime import date
from pathlib import Path
import argparse
import hashlib
import os
import subprocess

ROOT = Path(__file__).resolve().parent
DIST = ROOT / "dist"

def run(*args, cwd=ROOT):
    subprocess.run(list(map(str, args)), cwd=cwd, check=True)

def build(out=DIST, test_date=None):
    out = Path(out).resolve()
    if test_date and out == DIST:
        raise ValueError("Test dates require a separate output directory")
    out.mkdir(parents=True, exist_ok=True)
    work = ROOT / "build" if out == DIST else out / "build"
    work.mkdir(parents=True, exist_ok=True)
    # NASM's map directive accepts a bare filename, not a quoted path.
    defines = ["-DMAP_FILE=daydir.map"]
    if test_date:
        stamp = date.fromisoformat(test_date)
        defines += [f"-DTEST_YEAR={stamp.year}", f"-DTEST_MONTH={stamp.month}",
                    f"-DTEST_DAY={stamp.day}"]
    exe = out / "daydir.exe"
    run(os.environ.get("NASM", "nasm"), "-f", "bin", "-Ox", "-I",
        (ROOT / "src").as_posix()+"/", *defines, ROOT / "src/daydir.asm",
        "-o", exe, "-l", work / "daydir.lst", cwd=work)
    checksum = hashlib.sha256(exe.read_bytes()).hexdigest()
    (out / "daydir.exe.sha256").write_text(f"{checksum}  daydir.exe\n", encoding="ascii")
    print(f"{exe}: {exe.stat().st_size} bytes\nSHA-256: {checksum}", flush=True)
    return exe

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, default=DIST)
    parser.add_argument("--test-date", help="Test-only date, YYYY-MM-DD; requires a separate --out")
    args = parser.parse_args()
    try:
        build(args.out, args.test_date)
    except ValueError as error:
        parser.error(str(error))
