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
