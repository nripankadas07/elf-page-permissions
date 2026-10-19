# elf-page-permissions

Explain ELF LOAD ranges, zero-fill and declared page-permission unions without executing a binary.

For Build and release engineers reviewing a small ELF handoff. Individual segment flags do not explain shared-page permission unions or overlapping virtual mappings.

## Quickstart

Python3.10+; zero runtime dependencies. Wheel builds require setuptools from the normal Python registry.

```sh
git clone https://github.com/nripankadas07/elf-page-permissions.git
cd elf-page-permissions
python3 -m venv .venv
.venv/bin/python -m pip install .
.venv/bin/elf-page-permissions --make-example example.elf
.venv/bin/elf-page-permissions example.elf
```

Exit1 intentionally: separate RX/RW LOAD byte ranges share a4096-byte page, whose declared flag union is RWX; zero-fill ranges remain explicit.

Example generators create only an explicitly named new file and refuse overwrite. Reports never modify the input. Windows equivalents use `.venv\Scripts\python.exe` and the installed `.exe`; Windows/macOS have not been executed by this release's Linux CI.

## Contract

ELF32/64, little/big endian, identification/version1, EXEC/DYN, standard header/program-entry sizes and1..128 program headers. LOAD validates file/memory sizes, class address limits, known R/W/X flags and p_align congruence. Report backed/zero-fill intervals, overlap ambiguity, entry outside executable LOAD, W+X segments/stack and W+X page flag unions. Page-offset incongruence is a finding. Page size is a declared power of two512..65536, default4096; interval sweep avoids enumeration of huge virtual ranges. PT_INTERP is read as bounded ASCII but never opened/executed.

JSON reports go to stdout. Exit0 means the documented successful result, exit1 a valid finding/incomplete/rejected result, exit2 invalid/unsupported input, I/O or budget failure with stderr and no partial report. Ranges are half-open.

## Limits

8 MiB. Other program-header kinds are ignored, section headers/relocations/ABI-specific semantics unverified. No loader simulation, ASLR, dynamic linking, DWARF, exploitation assessment or safety certificate. Missing GNU_STACK is unknown information, not a healthy-stack claim. Page union is a declared model; actual OS loading/permissions can differ.

## Verify

```sh
python3 -m unittest -v test_behavior
python3 -m compileall -q .
python3 -m pip wheel --no-deps --wheel-dir dist .
python3 -m venv /tmp/elf-page-permissions-check
/tmp/elf-page-permissions-check/bin/python -m pip install --no-deps dist/*.whl
python3 verify_installed.py /tmp/elf-page-permissions-check/bin/python
```

[Validation](VALIDATION.md), [research](RESEARCH.md), [contributing](CONTRIBUTING.md), [support](SUPPORT.md), [security](SECURITY.md), [MIT license](LICENSE).

Original implementation, prose and invented fixtures developed with AI assistance. No measured performance-superiority or verified production-adoption claim.
