#!/usr/bin/env python3
"""Real PE filesystem tests on Windows/Wine, plus a full Gregorian cycle on Linux."""
from pathlib import Path
from datetime import date, datetime, timedelta
import ctypes
import os
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import build
from check_pe import check_pe

WINE = os.environ.get("WINE") or ("/usr/lib/wine/wine64" if Path("/usr/lib/wine/wine64").exists() else "wine")
ENV = dict(os.environ, WINEDEBUG="-all")
if os.name != "nt":
    ENV.setdefault("WINEPREFIX", str(ROOT / ".wine-test"))
    ENV.setdefault("XDG_RUNTIME_DIR", str(Path(tempfile.gettempdir()) / f"daydir-runtime-{os.getuid()}"))
    Path(ENV["XDG_RUNTIME_DIR"]).mkdir(mode=0o700, parents=True, exist_ok=True)
RUNS = 0

def run_exe(exe, cwd, expected=0, extended=False):
    global RUNS
    path = str(exe)
    if extended:
        path = "\\\\?\\" + (path if os.name == "nt" else "Z:" + path.replace("/", "\\"))
    command = [path] if os.name == "nt" else [WINE, path]
    # Wine services may inherit stdout/stderr and outlive the target process.
    # A regular file avoids waiting for EOF from those unrelated services.
    with tempfile.TemporaryFile() as log:
        p = subprocess.run(command, cwd=cwd, env=ENV, stdout=subprocess.DEVNULL,
                           stderr=log, timeout=45)
        log.seek(0)
        error = log.read().decode(errors="replace")
    assert p.returncode == expected, (exe, p.returncode, expected, error)
    RUNS += 1

def scenario(binary, when, work, kind="empty"):
    work.mkdir(parents=True)
    exe_dir = work / "Application folder with spaces caf\u00e9 \u65e5\u672c\u8a9e"
    if kind == "long":
        exe_dir = exe_dir / ("segment_" * 12) / ("another_" * 12) / ("third_" * 10)
    exe_dir.mkdir(parents=True)
    exe = exe_dir / "x.exe"        # replacement date is longer than EXE's name
    shutil.copy2(binary, exe)
    cwd = work / "different-cwd"
    cwd.mkdir()
    today_name = when.strftime("%Y_%m_%d")
    yesterday_name = (when - timedelta(days=1)).strftime("%Y_%m_%d")
    today, yesterday = exe_dir / today_name, exe_dir / yesterday_name
    older = exe_dir / (when - timedelta(days=2)).strftime("%Y_%m_%d")
    older.mkdir()
    # A directory with the same name in CWD must remain untouched.
    (cwd / yesterday_name).mkdir()
    if kind == "file-yesterday":
        yesterday.write_text("keep me")
    elif kind == "symlink":
        target = work / "link-target"
        target.mkdir()
        (target / "keep.txt").write_text("keep me")
        yesterday.symlink_to(target, target_is_directory=True)
    elif kind != "missing":
        yesterday.mkdir()
    if kind == "nonempty":
        (yesterday / "keep.txt").write_text("keep me")
    elif kind == "subdir":
        (yesterday / "empty-child").mkdir()
    elif kind == "exists":
        today.mkdir()
        (today / "keep.txt").write_text("keep today")
    elif kind == "file-today":
        today.write_text("same name, but a file")
    expected = 183 if kind == "file-today" else 0
    run_exe(exe, cwd, expected, kind == "extended")
    assert older.is_dir() and (cwd / yesterday_name).is_dir()
    assert not (cwd / today_name).exists()
    if kind == "file-today":
        assert today.read_text() == "same name, but a file"
        assert yesterday.is_dir(), "creation failure must prevent cleanup"
    else:
        assert today.is_dir(), (binary, when, kind, list(exe_dir.iterdir()))
        if kind in ("nonempty", "subdir", "symlink", "file-yesterday"):
            assert yesterday.exists(), (kind, yesterday)
            if kind == "nonempty":
                assert (yesterday / "keep.txt").read_text() == "keep me"
            if kind == "symlink":
                assert yesterday.is_symlink() and (target / "keep.txt").read_text() == "keep me"
        else:
            assert not yesterday.exists(), (binary, when, kind)
        if kind == "exists":
            assert (today / "keep.txt").read_text() == "keep today"
    # Repeat to test idempotence and the already-created-today branch.
    run_exe(exe, cwd, expected)

def exhaustive_calendar(tmp):
    if sys.platform != "linux":
        print("SKIP native exhaustive calendar test (Linux x64 only)", flush=True)
        return
    obj, lib = tmp / "calendar.o", tmp / "calendar.so"
    build.run("nasm", "-f", "elf64", "-Ox", "-I", "src/", "tests/calendar-native.asm", "-o", obj)
    build.run("ld.lld", "-shared", obj, "-o", lib)
    fn = ctypes.CDLL(str(lib)).calendar_test
    fn.argtypes = [ctypes.POINTER(ctypes.c_uint16), ctypes.POINTER(ctypes.c_uint16)]
    fn.restype = None
    t = (ctypes.c_uint16 * 8)()
    buf = (ctypes.c_uint16 * 12)()
    day = date(2000, 1, 1)
    end = date(2400, 1, 1)
    count = 0
    while day < end:
        t[0], t[1], t[3] = day.year, day.month, day.day
        buf[11] = 0xface
        fn(t, buf)
        expected = day - timedelta(days=1)
        assert (t[0], t[1], t[3]) == (expected.year, expected.month, expected.day), day
        result = bytes(buf)[:20].decode("utf-16-le")
        assert result == expected.strftime("%Y_%m_%d"), (day, result)
        assert buf[10] == 0 and buf[11] == 0xface
        day += timedelta(days=1)
        count += 1
    print(f"PASS {count:,} consecutive dates: Gregorian decrement and UTF-16 format", flush=True)

def main():
    check_pe(ROOT / "dist" / "daydir.exe")
    # Start Wine's test server explicitly so each short EXE need not boot Wine.
    server = None
    if os.name != "nt":
        server = subprocess.Popen([os.environ.get("WINESERVER") or ("/usr/lib/wine/wineserver64" if Path("/usr/lib/wine/wineserver64").exists() else "wineserver"),
                                   "-f", "-p120"], env=ENV,
                                  stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    with tempfile.TemporaryDirectory(prefix="daydir-test-") as temp:
        tmp = Path(temp)
        exhaustive_calendar(tmp)
        # Unmodified release binaries, real GetLocalTime.
        now = datetime.now().date()
        kinds = ["empty", "missing", "nonempty", "subdir", "exists", "file-today",
                 "file-yesterday", "long", "extended"]
        if os.name != "nt":
            kinds.append("symlink")
        for kind in kinds:
            scenario(ROOT / "dist/daydir.exe", now, tmp / "release" / kind, kind)
        print(f"PASS release: {len(kinds)} filesystem scenarios, each twice", flush=True)
        # Only the date acquisition is replaced. The real filesystem APIs, calendar,
        # formatter and PE layout are the same as in production.
        dates = ["2026-01-01", "2026-03-01", "2024-03-01", "2000-03-01",
                 "2100-03-01", "2400-03-01", "2026-05-01", "2026-12-31",
                 "2026-03-29", "2026-10-25"]
        for stamp in dates:
            dest = tmp / "binaries" / stamp
            # Keep build chatter out of the concise test log.
            subprocess.run([sys.executable, str(ROOT / "build.py"), "--test-date", stamp,
                            "--out", str(dest)], check=True, capture_output=True)
            scenario(dest / "daydir.exe", date.fromisoformat(stamp), tmp / "dates" / stamp)
            print(f"PASS calendar boundary {stamp}", flush=True)
        print(f"PASS {RUNS} PE process runs; release binaries were not modified", flush=True)
    if server is not None and server.poll() is None:
        server.terminate()
        server.wait(timeout=10)

if __name__ == "__main__":
    main()
