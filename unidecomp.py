#!/usr/bin/env python3
"""UniDecomp — universal binary analysis & decompilation workbench.

Auto-detects file format and performs:
  - structural analysis (headers, sections, imports/exports, metadata)
  - string extraction (ASCII + UTF-16LE)
  - entropy profiling
  - disassembly via Capstone (x86/x64/ARM/ARM64/MIPS/PPC/Sparc)
  - bytecode introspection: Python .pyc, Java .class, Lua, DEX/APK, WASM
  - .NET detection with ilspycmd/dnSpy guidance

Usage:
  unidecomp <file>                 full analysis report
  unidecomp <file> --strings       strings only
  unidecomp <file> --disasm        disassemble code sections
  unidecomp <file> --disasm --va 0x401000 --size 0x400
  unidecomp <file> --json          machine-readable output

Supported: PE/COFF (.exe/.dll, incl. .NET detection), ELF, Mach-O (incl. fat),
Java .class, Python .pyc, Android .dex/.apk, Lua bytecode, WebAssembly,
raw firmware/binaries.
"""
import argparse, json, math, os, struct, sys, zipfile
from pathlib import Path

try:
    import capstone
except ImportError:
    capstone = None

# ---------------------------------------------------------------- utilities

def entropy(data: bytes) -> float:
    if not data:
        return 0.0
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in freq if c)


def extract_strings(data: bytes, minlen=5):
    out = []
    cur = bytearray()
    for b in data:
        if 32 <= b < 127:
            cur.append(b)
        else:
            if len(cur) >= minlen:
                out.append(cur.decode("ascii"))
            cur = bytearray()
    if len(cur) >= minlen:
        out.append(cur.decode("ascii"))
    # UTF-16LE pass
    u = []
    i = 0
    while i + 1 < len(data):
        c = data[i] | (data[i + 1] << 8)
        if 32 <= c < 127 and data[i + 1] == 0:
            u.append(chr(c))
            i += 2
        else:
            if len(u) >= minlen:
                out.append("".join(u))
            u = []
            i += 2
    if len(u) >= minlen:
        out.append("".join(u))
    return out


def hexdump(data: bytes, base=0, width=16, limit=256):
    lines = []
    for off in range(0, min(len(data), limit), width):
        chunk = data[off:off + width]
        hexs = " ".join(f"{b:02x}" for b in chunk)
        asc = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"{base + off:08x}  {hexs:<{width * 3}}  {asc}")
    return "\n".join(lines)


# ---------------------------------------------------------------- PE parser

PE_MACHINES = {0x14C: "x86", 0x8664: "x86-64", 0x1C0: "ARM", 0xAA64: "ARM64",
               0x200: "IA64", 0x1C4: "ARMv7", 0x5064: "RISC-V 64"}


def parse_pe(data: bytes):
    if len(data) < 0x40 or data[:2] != b"MZ":
        return None
    try:
        e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
        if data[e_lfanew:e_lfanew + 4] != b"PE\0\0":
            return {"kind": "pe", "error": "bad PE signature"}
        coff = e_lfanew + 4
        machine, nsec, _, _, _, opt_size, chars = struct.unpack_from("<HHIIIHH", data, coff)
        opt = coff + 20
        magic = struct.unpack_from("<H", data, opt)[0]
        is64 = magic == 0x20B
        dd_base = opt + (112 if is64 else 96)
        # data directories: 0 export, 1 import, 14 CLR
        dirs = []
        for i in range(16):
            rva, sz = struct.unpack_from("<II", data, dd_base + i * 8)
            dirs.append((rva, sz))
        secs = []
        sp = opt + opt_size
        for i in range(nsec):
            o = sp + i * 40
            name = data[o:o + 8].rstrip(b"\0").decode("ascii", "replace")
            vsz, va, rsz, roff = struct.unpack_from("<IIII", data, o + 8)
            schars = struct.unpack_from("<I", data, o + 36)[0]
            secs.append({"name": name, "va": va, "vsize": vsz,
                         "raw_off": roff, "raw_size": rsz, "chars": schars,
                         "exec": bool(schars & 0x20000000)})

        def rva2off(rva):
            for s in secs:
                if s["va"] <= rva < s["va"] + max(s["vsize"], s["raw_size"]):
                    return s["raw_off"] + (rva - s["va"])
            return None

        result = {"kind": "pe", "machine": PE_MACHINES.get(machine, f"0x{machine:x}"),
                  "machine_id": machine, "sections": nsec, "is64": is64,
                  "characteristics": chars, "section_list": secs,
                  "dotnet": bool(dirs[14][0]), "imports": [], "exports": []}

        # imports
        if dirs[1][0]:
            off = rva2off(dirs[1][0])
            seen = set()
            while off and off + 20 <= len(data):
                oft, _, _, name_rva, ft = struct.unpack_from("<IIIII", data, off)
                if not (oft or name_rva or ft):
                    break
                noff = rva2off(name_rva)
                dll = data[noff:data.find(b"\0", noff)].decode("ascii", "replace") if noff else "?"
                if dll not in seen:
                    seen.add(dll)
                    result["imports"].append(dll)
                off += 20
                if len(result["imports"]) > 200:
                    break

        # exports (names only)
        if dirs[0][0]:
            off = rva2off(dirs[0][0])
            if off and off + 40 <= len(data):
                try:
                    _, _, _, _, n_names, addr_names = struct.unpack_from("<IIHHIIII", data, off)[0], None, None, None, None, None, None
                except Exception:
                    pass
                # simpler: read NumberOfNames at +24, AddressOfNames at +32
                n_names = struct.unpack_from("<I", data, off + 24)[0]
                names_rva = struct.unpack_from("<I", data, off + 32)[0]
                noff = rva2off(names_rva)
                if noff and n_names < 100000:
                    for i in range(min(n_names, 500)):
                        nrva = struct.unpack_from("<I", data, noff + i * 4)[0]
                        fo = rva2off(nrva)
                        if fo:
                            end = data.find(b"\0", fo)
                            result["exports"].append(data[fo:end].decode("ascii", "replace"))
        return result
    except Exception as e:
        return {"kind": "pe", "error": str(e)}


# ---------------------------------------------------------------- ELF parser

ELF_MACHINES = {3: "x86", 62: "x86-64", 40: "ARM", 183: "AArch64",
                8: "MIPS", 20: "PPC", 21: "PPC64", 243: "RISC-V"}
ELF_TYPES = {0: "NONE", 1: "REL", 2: "EXEC", 3: "DYN", 4: "CORE"}
SHT = {0: "NULL", 1: "PROGBITS", 2: "SYMTAB", 3: "STRTAB", 4: "RELA",
       9: "RELAS", 11: "DYNSYM", 14: "INIT_ARRAY"}


def parse_elf(data: bytes):
    if len(data) < 64 or data[:4] != b"\x7fELF":
        return None
    try:
        is64 = data[4] == 2
        le = data[5] == 1
        e = "<" if le else ">"
        if is64:
            etype, mach = struct.unpack_from(e + "HH", data, 16)
            shoff = struct.unpack_from(e + "Q", data, 40)[0]
            shentsize, shnum, shstrndx = struct.unpack_from(e + "HHH", data, 58)
        else:
            etype, mach = struct.unpack_from(e + "HH", data, 16)
            shoff = struct.unpack_from(e + "I", data, 32)[0]
            shentsize, shnum, shstrndx = struct.unpack_from(e + "HHH", data, 46)
        secs = []
        shstr_off = 0
        if shoff and shentsize and shnum < 10000:
            for i in range(shnum):
                o = shoff + i * shentsize
                if is64:
                    name, typ, _, _, off, size = struct.unpack_from(e + "IIQQQQ", data, o)
                else:
                    name, typ, _, _, off, size = struct.unpack_from(e + "IIIIII", data, o)
                secs.append({"name_off": name, "type": SHT.get(typ, str(typ)),
                             "off": off, "size": size})
            if 0 <= shstrndx < len(secs) and is64:
                shstr_off = secs[shstrndx]["off"]
            elif 0 <= shstrndx < len(secs):
                shstr_off = secs[shstrndx]["off"]
            for s in secs:
                if shstr_off and s["name_off"] < 0x100000:
                    fo = shstr_off + s["name_off"]
                    end = data.find(b"\0", fo)
                    s["name"] = data[fo:end].decode("ascii", "replace") if fo < len(data) else "?"
                else:
                    s["name"] = "?"
        return {"kind": "elf", "class": "64" if is64 else "32",
                "type": ELF_TYPES.get(etype, etype),
                "machine": ELF_MACHINES.get(mach, f"0x{mach:x}"),
                "sections": secs}
    except Exception as e:
        return {"kind": "elf", "error": str(e)}


# ---------------------------------------------------------------- Mach-O parser

MACHO_MAGICS = {0xFEEDFACE: ("32", "BE"), 0xCEFAEDFE: ("32", "LE"),
                0xFEEDFACF: ("64", "BE"), 0xCFFAEDFE: ("64", "LE"),
                0xCAFEBABE: ("fat", "BE"), 0xBEBAFECA: ("fat", "LE")}
LC_NAMES = {1: "SEGMENT", 0x19: "SEGMENT_64", 2: "SYMTAB", 0xB: "DYSYMTAB",
            0xC: "LOAD_DYLIB", 0xE: "LOAD_DYLINKER", 0x1D: "CODE_SIGNATURE",
            0x22: "DYLD_INFO", 0x2A: "SOURCE_VERSION", 0x80000022: "DYLD_INFO_ONLY"}
CPU = {7: "x86", 0x01000007: "x86-64", 12: "ARM", 0x0100000C: "ARM64"}


def parse_macho(data: bytes):
    if len(data) < 8:
        return None
    magic = struct.unpack(">I", data[:4])[0]
    if magic == 0xCAFEBABE and len(data) > 8:  # could be fat Mach-O or Java class
        nfat = struct.unpack(">I", data[4:8])[0]
        if 0 < nfat < 16:
            return {"kind": "macho", "variant": "fat", "arches": nfat,
                    "note": "universal binary — run per-arch slice"}
        return parse_class(data)  # Java class shares magic
    info = MACHO_MAGICS.get(magic)
    if not info:
        return None
    bits, endian = info
    e = ">" if endian == "BE" else "<"
    try:
        if bits == "64":
            cputype, cpusub, _, ncmds, sizeofcmds, flags = struct.unpack_from(e + "IIIIII", data, 4)
        else:
            cputype, cpusub, _, ncmds, sizeofcmds, flags = struct.unpack_from(e + "IIIIII", data, 4)
        cmds = []
        off = 32 if bits == "64" else 28
        for _ in range(min(ncmds, 200)):
            if off + 8 > len(data):
                break
            cmd, cmdsize = struct.unpack_from(e + "II", data, off)
            cmds.append(LC_NAMES.get(cmd, f"cmd_0x{cmd:x}"))
            if cmdsize < 8:
                break
            off += cmdsize
        return {"kind": "macho", "bits": bits, "endian": endian,
                "cpu": CPU.get(cputype, f"0x{cputype:x}"),
                "load_commands": cmds}
    except Exception as ex:
        return {"kind": "macho", "error": str(ex)}


# ---------------------------------------------------------------- Java class

def parse_class(data: bytes):
    if len(data) < 10 or data[:4] != b"\xca\xfe\xba\xbe":
        return None
    # distinguish fat Mach-O already handled; Java minor/major at 4..8
    try:
        minor, major = struct.unpack(">HH", data[4:8])
        if major > 100 or minor > 1000:  # not a plausible class version
            return {"kind": "unknown", "magic": "cafebabe"}
        cp_count = struct.unpack(">H", data[8:10])[0]
        # walk constant pool to find class name + counts
        off = 10
        utf8s = []
        i = 1
        while i < cp_count and off + 3 <= len(data):
            tag = data[off]
            off += 1
            if tag == 1:
                ln = struct.unpack(">H", data[off:off + 2])[0]
                off += 2
                utf8s.append(data[off:off + ln].decode("utf-8", "replace"))
                off += ln
            elif tag in (7, 8, 16, 19, 20):
                off += 2
            elif tag in (15,):
                off += 3
            elif tag in (3, 4, 9, 10, 11, 12, 17, 18):
                off += 4
            elif tag in (5, 6):
                off += 8
                i += 1
            else:
                break
            i += 1
        access = struct.unpack(">H", data[off:off + 2])[0] if off + 2 <= len(data) else 0
        this_i, super_i = struct.unpack(">HH", data[off + 2:off + 6]) if off + 6 <= len(data) else (0, 0)
        def cpstr(idx):
            # resolve CONSTANT_Class -> name_index is complex; approximate via utf8 pool order
            return utf8s[idx - 1] if 0 < idx <= len(utf8s) else f"#{idx}"
        iface_n = struct.unpack(">H", data[off + 6:off + 8])[0] if off + 8 <= len(data) else 0
        foff = off + 8 + iface_n * 2
        fields = struct.unpack(">H", data[foff:foff + 2])[0] if foff + 2 <= len(data) else 0
        moff = foff + 2
        # skip field_info entries
        for _ in range(fields):
            if moff + 8 > len(data):
                break
            ac, ni, di, ac2 = struct.unpack(">HHHH", data[moff:moff + 8])
            moff += 8
            for _ in range(ac2):
                if moff + 6 > len(data):
                    break
                moff += 6
        methods = struct.unpack(">H", data[moff:moff + 2])[0] if moff + 2 <= len(data) else 0
        return {"kind": "java-class", "version": f"{major}.{minor}",
                "cp_entries": cp_count, "access_flags": access,
                "interfaces": iface_n, "fields": fields, "methods": methods,
                "sample_strings": utf8s[:40]}
    except Exception as e:
        return {"kind": "java-class", "error": str(e)}


# ---------------------------------------------------------------- Python pyc

def parse_pyc(data: bytes):
    import importlib.util, marshal, dis, types
    magic = importlib.util.MAGIC_NUMBER
    if not data.startswith(magic):
        # try common magics
        return None
    try:
        code = marshal.loads(data[16:])
        if not isinstance(code, types.CodeType):
            return {"kind": "pyc", "error": "not a code object"}
        ins = list(dis.get_instructions(code))
        return {"kind": "pyc", "name": code.co_name,
                "filename": code.co_filename,
                "argcount": code.co_argcount, "consts": len(code.co_consts),
                "names": len(code.co_names), "instructions": len(ins),
                "first_bytes": "\n".join(f"{i.offset:4d}  {i.opname:<20} {i.argrepr}"
                                          for i in ins[:120])}
    except Exception as e:
        return {"kind": "pyc", "error": str(e)}


# ---------------------------------------------------------------- DEX / APK / misc

def parse_dex(data: bytes):
    if len(data) < 0x70 or data[:4] != b"dex\n":
        return None
    try:
        ver = data[4:7].decode("ascii", "replace")
        string_ids_size, string_ids_off = struct.unpack_from("<II", data, 0x38)
        type_ids_size = struct.unpack_from("<I", data, 0x40)[0]
        proto_ids_size = struct.unpack_from("<I", data, 0x48)[0]
        class_defs_size = struct.unpack_from("<I", data, 0x60)[0]
        strings = []
        for i in range(min(string_ids_size, 30)):
            so = string_ids_off + i * 4
            if so + 4 > len(data):
                break
            str_off = struct.unpack_from("<I", data, so)[0]
            # uleb128 len then bytes
            j = str_off
            shift = 0
            while j < len(data):
                b = data[j]; j += 1
                if not (b & 0x80):
                    break
            end = data.find(b"\0", j)
            strings.append(data[j:end].decode("utf-8", "replace")[:80])
        return {"kind": "dex", "version": ver, "strings": string_ids_size,
                "types": type_ids_size, "protos": proto_ids_size,
                "classes": class_defs_size, "sample_strings": strings}
    except Exception as e:
        return {"kind": "dex", "error": str(e)}


def parse_apk(data: bytes):
    try:
        import io
        z = zipfile.ZipFile(io.BytesIO(data))
        names = z.namelist()
        dex = [n for n in names if n.endswith(".dex")]
        return {"kind": "apk" if any(n == "AndroidManifest.xml" for n in names) else "zip",
                "entries": len(names), "dex_files": dex,
                "top": names[:40]}
    except Exception:
        return None


def parse_luac(data: bytes):
    if len(data) < 12 or data[:4] != b"\x1bLua":
        return None
    ver = data[4]
    return {"kind": "luac", "version": f"{ver >> 4}.{ver & 0xF}",
            "endian": "little" if data[6] == 1 else "big",
            "sizes": {"int": data[8], "size_t": data[9], "instruction": data[10],
                      "lua_Integer": data[11]},
            "note": "bytecode — decompile with unluac/luadec for source"}


def parse_wasm(data: bytes):
    if len(data) < 8 or data[:4] != b"\0asm":
        return None
    try:
        ver = struct.unpack("<I", data[4:8])[0]
        return {"kind": "wasm", "version": f"0x{ver:08x}",
                "note": "WebAssembly — use wasm2wat/wasm-decompile"}
    except Exception as e:
        return {"kind": "wasm", "error": str(e)}


# ---------------------------------------------------------------- disassembly

CS_ARCH = {
    "x86": (capstone.CS_ARCH_X86, capstone.CS_MODE_32) if capstone else None,
    "x86-64": (capstone.CS_ARCH_X86, capstone.CS_MODE_64) if capstone else None,
    "arm": (capstone.CS_ARCH_ARM, capstone.CS_MODE_ARM) if capstone else None,
    "arm64": (capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM) if capstone else None,
    "mips": (capstone.CS_ARCH_MIPS, capstone.CS_MODE_MIPS32) if capstone else None,
    "ppc": (capstone.CS_ARCH_PPC, capstone.CS_MODE_32) if capstone else None,
    "sparc": (capstone.CS_ARCH_SPARC, capstone.CS_MODE_BIG_ENDIAN) if capstone else None,
}


def guess_code_region(info, data):
    """Return (arch_name, offset, size, vaddr) of the best code section."""
    if info.get("kind") == "pe":
        for s in info.get("section_list", []):
            if s["exec"] and s["raw_size"] > 0:
                arch = info.get("machine", "x86-64")
                return arch, s["raw_off"], min(s["raw_size"], 0x40000), s["va"] + 0x140000000 if not info.get("is64") else s["va"]
        return "x86-64", 0, min(len(data), 0x40000), 0
    if info.get("kind") == "elf":
        for s in info.get("sections", []):
            if s.get("name") in (".text",) and s["size"] > 0:
                return info.get("machine", "x86-64"), s["off"], min(s["size"], 0x40000), 0
        return info.get("machine", "x86-64"), 0, min(len(data), 0x40000), 0
    return "x86-64", 0, min(len(data), 0x40000), 0


def disassemble(data, arch, off, size, va=0, count=400):
    if not capstone:
        return "capstone not installed — pip install capstone"
    key = arch.lower()
    if key not in CS_ARCH or not CS_ARCH[key]:
        # fuzzy match
        for k in CS_ARCH:
            if k in key or key in k:
                key = k
                break
        else:
            return f"unsupported arch {arch}"
    a, m = CS_ARCH[key]
    md = capstone.Cs(a, m)
    md.detail = False
    code = data[off:off + size]
    lines = []
    base = va or off
    for i, ins in enumerate(md.disasm(code, base)):
        if i >= count:
            lines.append("...")
            break
        lines.append(f"{ins.address:08x}  {ins.bytes.hex():<20} {ins.mnemonic} {ins.op_str}")
    return "\n".join(lines) if lines else "(no instructions decoded)"


# ---------------------------------------------------------------- top-level

def analyze(path):
    data = Path(path).read_bytes()
    info = None
    for parser in (parse_pe, parse_elf, parse_macho, parse_class, parse_pyc,
                   parse_dex, parse_apk, parse_luac, parse_wasm):
        info = parser(data)
        if info:
            break
    if info is None:
        info = {"kind": "raw", "size": len(data), "entropy": round(entropy(data[:1 << 20]), 3)}
    info["file"] = os.path.basename(path)
    info["size"] = len(data)
    return data, info


def report(data, info, strings_limit=80):
    out = []
    kind = info.get("kind", "?")
    out.append(f"=== {info.get('file')} ===")
    out.append(f"size: {info.get('size', len(data)):,} bytes   type: {kind}")
    if "error" in info:
        out.append(f"parse error: {info['error']}")
    if kind == "pe":
        out.append(f"machine: {info.get('machine')}   {'PE32+' if info.get('is64') else 'PE32'}   "
                   f"sections: {info.get('sections')}   characteristics: 0x{info.get('characteristics',0):04x}")
        if info.get("dotnet"):
            out.append(">>> .NET managed assembly — for real decompilation use "
                       "ilspycmd (dotnet tool install -g ilspycmd) or dnSpy/AvaloniaILSpy")
        if info.get("section_list"):
            out.append("sections:")
            for s in info["section_list"]:
                out.append(f"  {s['name']:<8} va=0x{s['va']:08x} vsz=0x{s['vsize']:08x} "
                           f"raw=0x{s['raw_size']:08x} exec={s['exec']}")
        if info.get("imports"):
            out.append(f"imports ({len(info['imports'])} dlls): " + ", ".join(info["imports"][:30]))
        if info.get("exports"):
            out.append(f"exports ({len(info['exports'])}): " + ", ".join(info["exports"][:40]))
    elif kind == "elf":
        out.append(f"class: {info.get('class')}-bit   type: {info.get('type')}   machine: {info.get('machine')}")
        names = [s.get("name", "?") for s in info.get("sections", [])]
        out.append("sections: " + ", ".join(names[:40]))
    elif kind == "macho":
        out.append(f"cpu: {info.get('cpu')}   bits: {info.get('bits')}   endian: {info.get('endian')}")
        out.append("load commands: " + ", ".join(info.get("load_commands", [])[:30]))
    elif kind == "java-class":
        out.append(f"class version {info.get('version')}   cp={info.get('cp_entries')} "
                   f"fields={info.get('fields')} methods={info.get('methods')}")
        if info.get("sample_strings"):
            out.append("strings: " + " | ".join(info["sample_strings"][:20]))
        out.append(">>> bytecode — full decompile: install CFR/procyon and run on the .class")
    elif kind == "pyc":
        out.append(f"code object: {info.get('name')}   file: {info.get('filename')}")
        out.append(f"args={info.get('argcount')} consts={info.get('consts')} "
                   f"names={info.get('names')} instructions={info.get('instructions')}")
        if info.get("first_bytes"):
            out.append("disassembly (first instructions):")
            out.append(info["first_bytes"])
        out.append(">>> source recovery: pycdc / decompyle3 / pylingual")
    elif kind == "dex":
        out.append(f"dex v{info.get('version')}   strings={info.get('strings')} "
                   f"types={info.get('types')} classes={info.get('classes')}")
        out.append("sample strings: " + " | ".join(info.get("sample_strings", [])[:20]))
        out.append(">>> decompile: jadx / apktool")
    elif kind == "apk" or kind == "zip":
        out.append(f"zip archive — {info.get('entries')} entries")
        if info.get("dex_files"):
            out.append("dex files: " + ", ".join(info["dex_files"]))
        out.append("contents: " + ", ".join(info.get("top", [])[:30]))
    elif kind == "luac":
        out.append(f"lua bytecode v{info.get('version')} {info.get('endian')}-endian "
                   f"int={info.get('sizes',{}).get('int')}B")
        out.append(info.get("note", ""))
    elif kind == "wasm":
        out.append(f"wasm version {info.get('version')} — {info.get('note','')}")
    elif kind == "raw":
        out.append(f"unrecognized format — entropy {info.get('entropy')} "
                   f"(8.0=encrypted/compressed, ~6-7=code, ~4-5=data)")
    # entropy of whole file sample
    if kind != "raw":
        out.append(f"file entropy: {entropy(data[:1 << 20]):.2f}")
    return "\n".join(out)


def main():
    ap = argparse.ArgumentParser(prog="unidecomp",
                                 description="Universal binary analysis & decompilation workbench")
    ap.add_argument("file", help="file to analyze")
    ap.add_argument("--strings", action="store_true", help="extract strings only")
    ap.add_argument("--disasm", action="store_true", help="disassemble code section")
    ap.add_argument("--va", type=lambda x: int(x, 0), default=None, help="virtual address override")
    ap.add_argument("--size", type=lambda x: int(x, 0), default=None, help="bytes to disassemble")
    ap.add_argument("--arch", default=None, help="force arch (x86-64, arm64, ...)")
    ap.add_argument("--count", type=int, default=400, help="max instructions")
    ap.add_argument("--minlen", type=int, default=5, help="min string length")
    ap.add_argument("--json", action="store_true", help="JSON output")
    args = ap.parse_args()

    path = args.file
    if not os.path.isfile(path):
        print(f"error: {path} not found", file=sys.stderr)
        sys.exit(1)
    data, info = analyze(path)

    if args.json:
        slim = {k: v for k, v in info.items() if k != "section_list" or True}
        print(json.dumps(slim, indent=2, default=str))
        return

    if args.strings:
        strs = extract_strings(data, args.minlen)
        for s in strs[:2000]:
            print(s)
        print(f"\n# {len(strs)} strings", file=sys.stderr)
        return

    if args.disasm:
        arch, off, size, va = guess_code_region(info, data)
        if args.size:
            size = args.size
            off = 0 if args.va is not None else off
        if args.va is not None:
            # convert VA to file offset for PE/ELF when possible
            va = args.va
        if args.arch:
            arch = args.arch
        print(f"# arch={arch} offset=0x{off:x} size=0x{size:x} va=0x{va:x}")
        print(disassemble(data, arch, off, size, va, args.count))
        return

    print(report(data, info))


if __name__ == "__main__":
    main()
