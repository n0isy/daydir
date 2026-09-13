# daydir

[![Latest release](https://img.shields.io/badge/release-latest-blue)](https://github.com/n0isy/daydir/releases/latest)

A **984-byte Windows x64 executable** that creates today's directory next to itself
and removes yesterday's directory if it is empty.

Written in NASM assembly. NASM emits the entire PE32+ image directly: headers,
instructions and imports. No external linker, CRT, Windows SDK or packer is needed.

## Usage

Place `daydir.exe` in the directory you want to maintain, then run it.
For example, on September 13, 2026:

```text
work/
  daydir.exe
  2026_09_13/    created if missing
  2026_09_12/    removed only if empty
```

The program uses the executable's location, independently of the current working
directory. It reads the computer's local date once per run. Previous-day calculation
handles month boundaries, year boundaries and Gregorian leap years.

- Existing content in today's directory is preserved.
- A nonempty yesterday directory is preserved, including one containing only an empty subdirectory.
- Older directories, files, junctions and symbolic links are not removed.
- If today's directory cannot be created, yesterday's directory is left alone.
- Repeated runs are safe. Unicode and extended-length Windows paths are supported.

There is no console window, command-line configuration or automatic scheduling.
One launch performs one operation. The executable has no runtime dependencies
outside the Windows system DLLs.

### Exit codes

`0` means success, including an absent or nonempty yesterday directory.
Failures return a Win32 error code, for example:

| Code | Meaning |
| ---: | --- |
| 5 | Access denied |
| 183 | Today's name is already occupied by a file |
| 206 | The executable path exceeds the supported buffer length |

Wait for this GUI-subsystem program and inspect its exit code in PowerShell:

```powershell
$process = Start-Process -FilePath .\daydir.exe -Wait -PassThru
$process.ExitCode
```

## Build

Install **NASM** and **Python 3.10 or later**, and put them on `PATH`.
The same command works on Windows and Linux:

```text
python build.py
```

Outputs:

```text
dist/daydir.exe
```

`dist/` is generated and ignored by Git. To choose another output
directory, use `python build.py --out path/to/output`. `NASM` can override the
assembler executable path.

The essential assembly command, with `dist/` already present, is:

```text
nasm -f bin -Ox -I src/ src/daydir.asm -o dist/daydir.exe
```

Built with NASM 2.16.03. The resulting executable is 984 bytes.

## Implementation

| File | Purpose |
| --- | --- |
| [src/daydir.asm](src/daydir.asm) | PE32+ headers, section layout and imports |
| [src/program.inc](src/program.inc) | Path handling and directory operations |
| [src/calendar.inc](src/calendar.inc) | Previous-day calculation and UTF-16 date formatting |
| [build.py](build.py) | Assemble the executable |
| [tests/](tests/) | Directory behavior and calendar tests |

The file has a 256-byte header area and one 728-byte section. It uses 4-byte file
and section alignment, a fixed image base, and two data-directory slots. There is
no DOS program, relocation table, debug data or unwind metadata. The section header
declares code/read/execute permissions and the PE declares NX compatibility.

Seven functions are imported by name from KERNEL32.dll. With `OriginalFirstThunk`
set to zero, the loader uses the IAT for lookup as well, avoiding a second table.
The program itself does not search the PEB or resolve DLL exports manually.

The PE header reserves 1 MiB of stack and commits 128 KiB. That commit is required
for the long-path buffer; do not lower it without adding stack probing.
Calls into WinAPI provide 32-byte shadow space and 16-byte stack alignment.
The program exits through `ExitProcess` and does not return to its caller.

The user confirmed the executable works on Windows; the Windows version was not
recorded. Local automated execution was checked in Wine 10.0 on Linux x64.
This is not a claim of testing every Windows version. Network UNC shares have not
been exercised by the local suite.

## Byte analysis

[HEX-ANALISYS.md](HEX-ANALISYS.md) documents this exact binary: each header field,
instruction, import, padding range and the complete hex dump.
There are **420 zero bytes**, but only **9 bytes of alignment padding**.
The other zeros belong to data structures and instruction operands.

## Program tests

```text
python tests/test.py
```

The filesystem suite runs the real PE directly on Windows or through Wine on Linux.
It checks creation, repeated execution, a different current directory, Unicode,
long/extended paths, empty/nonempty directories, file-name conflicts and preservation
of older directories. Wine runs also exercise symbolic links.

Test-only builds inject dates for calendar boundaries into separate temporary output
directories. They do not modify the release executable. On Linux x64, the suite also
executes the production calendar instructions for all **146,097 days** of a complete
400-year Gregorian cycle, comparing them with Python `datetime`.
That native calendar check additionally needs `ld.lld` from LLVM.

The suite covers directory operations in **40 program runs** and the full calendar cycle.
Use `WINE`, `WINESERVER` and `WINEPREFIX` to select a Wine installation or prefix;
the default isolated prefix is `.wine-test/` in the repository.
All filesystem scenarios use temporary directories.

## GitHub Actions

[.github/workflows/build.yml](.github/workflows/build.yml) defines an Ubuntu build
for pushes to `main`, version tags (`v*`), pull requests and manual dispatch. It installs
NASM, assembles the EXE and uploads it as the
`daydir-windows-x64` artifact.

For a version tag, a dependent release job downloads the artifact and publishes
a GitHub Release containing `daydir.exe`. Documentation stays in the repository. For example:

```text
git tag -a v1.0.0 -m "daydir v1.0.0"
git push origin main v1.0.0
```
