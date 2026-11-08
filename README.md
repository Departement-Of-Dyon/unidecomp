# UniDecomp

Universal binary analysis & decompilation workbench. Point it at any file —
it auto-detects the format and performs structural analysis, string
extraction, entropy profiling, and disassembly.

## Supported formats

| Format | Analysis |
|--------|----------|
| PE/COFF (.exe/.dll) | headers, sections, imports, exports, .NET detection |
| ELF | class, type, machine, section table |
| Mach-O (incl. fat/universal) | CPU, load commands |
| Java .class | constant pool, fields/methods counts, strings |
| Python .pyc | marshal → bytecode disassembly |
| Android .dex / .apk | header stats, string preview, contents |
| Lua bytecode | version, endianness, word sizes |
| WebAssembly | version detection |
| Raw firmware/binaries | entropy + strings |

Native disassembly via [Capstone](https://www.capstone-engine.org/):
x86, x86-64, ARM, ARM64, MIPS, PPC, SPARC.

## Usage

```bash
unidecomp <file>                 # full analysis report
unidecomp <file> --strings       # extract ASCII + UTF-16 strings
unidecomp <file> --disasm        # disassemble the code section
unidecomp <file> --disasm --va 0x401000 --size 0x400 --arch x86-64
unidecomp <file> --json          # machine-readable output
```

## Full decompilation (Ghidra engine)

```bash
unidecomp --install-engine          # one-time: downloads Ghidra (Apache-2.0, NSA)
unidecomp <file> --decompile        # headless analysis -> <file>.decompiled.c
unidecomp <file> --decompile -o out.c
```

`--decompile` runs Ghidra's full auto-analysis (disassembly, function
recovery, decompiler) and exports C pseudocode for every function — the
same engine used by NSA professionals. Requires **JDK 21+** (auto-detected;
install Temurin JDK 21 if missing). Ghidra is downloaded on demand to
`%LOCALAPPDATA%\UniDecomp\engines` — UniDecomp itself stays small.

## Legal notice

UniDecomp and the Ghidra engine are lawful tools. You may only analyze
binaries you own or have the legal right to examine — your own software,
open-source code, malware you're authorized to analyze defensively, or
files covered by reverse-engineering-for-interoperability exemptions in
your jurisdiction (e.g., DMCA §1201(f) in the US). Do not use it to
circumvent copy protection, DRM, or anti-tamper mechanisms, and do not
decompile proprietary software you have no rights to.

## Deeper decompilation

UniDecomp handles *analysis*; for full source-level decompilation pair it
with format-specific tools:

- **.NET** → `ilspycmd` (`dotnet tool install -g ilspycmd`) or dnSpy
- **Java** → CFR / Procyon / Fernflower
- **Python** → pycdc, decompyle3, pylingual
- **DEX/APK** → jadx, apktool
- **Lua** → unluac / luadec
- **WASM** → wasm2wat, wasm-decompile
- **Native** → Ghidra, IDA, Binary Ninja (UniDecomp gives you the map)

## Install

```bash
pip install capstone
python unidecomp.py <file>
```

Or grab the standalone `unidecomp.exe` from Releases (Windows, no Python needed).

## License

MIT
