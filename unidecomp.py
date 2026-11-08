#!/usr/bin/env python3
"""UniDecomp — universal binary analysis & decompilation workbench.

Auto-detects file format and performs:
  - structural analysis (headers, sections, imports/exports, metadata)
  - PE deep-dive: version info, resources, debug/PDB path, TLS, delay-loads,
    relocations, Authenticode dir, overlay, packer/protector heuristics
  - function-level import tables, export names
  - string extraction (ASCII + UTF-16LE), per-section entropy, entropy maps
  - embedded-file carving (MZ/PE, ELF, Mach-O, Java, DEX, Lua, WASM, ZIP/APK,
    PNG/JPG/GIF/PDF)
  - disassembly via Capstone (x86/x64/ARM/ARM64/MIPS/PPC/SPARC)
  - bytecode introspection: Python .pyc, Java .class, Lua, DEX/APK, WASM
  - .NET detection with ilspycmd/dnSpy guidance
  - batch directory scanning

Usage:
  unidecomp <file>                  full analysis report
  unidecomp <file> --out report.txt write report to file
  unidecomp <file> --strings        strings only
  unidecomp <file> --disasm         disassemble code section
  unidecomp <file> --disasm --va 0x401000 --size 0x400
  unidecomp <file> --hash           hashes only
  unidecomp <file> --carve          scan for embedded files
  unidecomp <file> --batch DIR      analyze every file in a directory
  unidecomp <file> --json           machine-readable output

Supported: PE/COFF (.exe/.dll, incl. .NET), ELF, Mach-O (incl. fat),
Java .class, Python .pyc, Android .dex/.apk, Lua bytecode, WebAssembly,
raw firmware/binaries.
"""
import argparse, datetime, hashlib, io, json, math, os, struct, sys, zipfile
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


def extract_strings(data: bytes, minlen=5, utf16=True):
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
    if utf16:
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


def hashes(data: bytes):
    return {"md5": hashlib.md5(data).hexdigest(),
            "sha1": hashlib.sha1(data).hexdigest(),
            "sha256": hashlib.sha256(data).hexdigest()}


def entropy_map(data: bytes, blocks=48):
    """Sparkline of per-block entropy."""
    if len(data) < blocks:
        return ""
    step = len(data) // blocks
    vals = []
    for i in range(blocks):
        vals.append(entropy(data[i * step:(i + 1) * step]))
    lo, hi = min(vals), max(vals)
    ramp = " .:-=+*#%@"
    return "".join(ramp[min(9, int((v - lo) / (hi - lo + 1e-9) * 10))] for v in vals)


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
SUBSYS = {1: "NATIVE", 2: "WINDOWS_GUI", 3: "WINDOWS_CUI", 7: "POSIX_CUI", 9: "WINDOWS_CE"}
CHAR_NAMES = [(0x0002, "EXECUTABLE"), (0x2000, "DLL"), (0x0001, "RELOCS_STRIPPED"),
              (0x0020, "LARGE_ADDRESS"), (0x0080, "BYTES_REVERSED"),
              (0x0100, "32BIT"), (0x2000, "DLL"), (0x4000, "UP_SYSTEM_ONLY"),
              (0x8000, "BYTES_REVERSED_LO")]
PACKER_SECTIONS = ("upx", ".vmp", ".themida", ".enigma", ".packed", ".aspack",
                   ".nsp", ".petite", ".fsg", ".mpress", ".byfron", ".boot",
                   "bitarts", ".winlice", ".sforce", ".y0da", ".kkrunchy")


def parse_pe(data: bytes):
    if len(data) < 0x40 or data[:2] != b"MZ":
        return None
    try:
        e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
        if e_lfanew + 0x108 > len(data) or data[e_lfanew:e_lfanew + 4] != b"PE\0\0":
            return {"kind": "pe", "error": "bad PE signature"}
        coff = e_lfanew + 4
        (machine, nsec, timestamp, _, _, opt_size, chars) = struct.unpack_from(
            "<HHIIIHH", data, coff)
        opt = coff + 20
        magic = struct.unpack_from("<H", data, opt)[0]
        is64 = magic == 0x20B
        ep_rva = struct.unpack_from("<I", data, opt + 16)[0]
        image_base = struct.unpack_from("<Q" if is64 else "<I",
                                        data, opt + (24 if is64 else 28))[0]
        subsystem = struct.unpack_from("<H", data, opt + 68)[0]
        dll_chars = struct.unpack_from("<H", data, opt + 70)[0]
        dd_base = opt + (112 if is64 else 96)
        dirs = [struct.unpack_from("<II", data, dd_base + i * 8) for i in range(16)]
        secs = []
        sp = opt + opt_size
        for i in range(nsec):
            o = sp + i * 40
            name = data[o:o + 8].rstrip(b"\0").decode("ascii", "replace")
            vsz, va, rsz, roff = struct.unpack_from("<IIII", data, o + 8)
            schars = struct.unpack_from("<I", data, o + 36)[0]
            secs.append({"name": name, "va": va, "vsize": vsz, "raw_off": roff,
                         "raw_size": rsz, "chars": schars,
                         "exec": bool(schars & 0x20000000)})

        def rva2off(rva):
            for s in secs:
                if s["va"] <= rva < s["va"] + max(s["vsize"], s["raw_size"]):
                    return s["raw_off"] + (rva - s["va"])
            return None

        result = {"kind": "pe", "machine": PE_MACHINES.get(machine, f"0x{machine:x}"),
                  "machine_id": machine, "sections": nsec, "is64": is64,
                  "characteristics": chars, "section_list": secs,
                  "dotnet": bool(dirs[14][0]),
                  "entry_rva": ep_rva, "image_base": image_base,
                  "subsystem": SUBSYS.get(subsystem, subsystem),
                  "dll_chars": dll_chars,
                  "timestamp": timestamp,
                  "compile_time": (datetime.datetime.fromtimestamp(timestamp, datetime.UTC)
                                   .strftime("%Y-%m-%d %H:%M:%S UTC")
                                   if 0 < timestamp < 0xFFFFFFFF - 1 else "n/a"),
                  "imports": [], "import_funcs": {}, "exports": [],
                  "tls": bool(dirs[9][0]), "relocs": bool(dirs[5][0]),
                  "debug_dir": bool(dirs[6][0]), "delay_imports": bool(dirs[13][0]),
                  "signature_dir": dirs[4], "overlay": None,
                  "resources": [], "pdb": None, "packers": []}

        # overlay: bytes past the last raw section end
        last_end = max((s["raw_off"] + s["raw_size"] for s in secs), default=0)
        if last_end and last_end < len(data):
            result["overlay"] = {"offset": last_end, "size": len(data) - last_end,
                                 "entropy": round(entropy(data[last_end:last_end + 65536]), 2)}

        # packer heuristics
        low_names = [s["name"].lower() for s in secs]
        for pat in PACKER_SECTIONS:
            if any(pat in n for n in low_names):
                result["packers"].append(pat)
        exec_secs = [s for s in secs if s["exec"] and s["raw_size"] > 0]
        if exec_secs:
            ent = entropy(data[exec_secs[0]["raw_off"]:exec_secs[0]["raw_off"] + min(exec_secs[0]["raw_size"], 1 << 20)])
            if ent > 7.2:
                result["packers"].append(f"high-entropy code section ({ent:.2f})")
        if len(result["imports"]) == 0 and dirs[1][0] == 0:
            pass

        # imports (dll + function names)
        if dirs[1][0]:
            off = rva2off(dirs[1][0])
            seen = set()
            while off and off + 20 <= len(data) and len(seen) < 300:
                oft, _, _, name_rva, ft = struct.unpack_from("<IIIII", data, off)
                if not (oft or name_rva or ft):
                    break
                noff = rva2off(name_rva)
                dll = data[noff:data.find(b"\0", noff)].decode("ascii", "replace") if noff else "?"
                if dll not in seen:
                    seen.add(dll)
                    result["imports"].append(dll)
                    funcs = []
                    thunk_rva = oft or ft
                    toff = rva2off(thunk_rva)
                    thunk_sz = 8 if is64 else 4
                    tfmt = "<Q" if is64 else "<I"
                    ordinal_flag = 1 << ((64 if is64 else 32) - 1)
                    for _ in range(500):
                        if not toff or toff + thunk_sz > len(data):
                            break
                        val = struct.unpack_from(tfmt, data, toff)[0]
                        toff += thunk_sz
                        if val == 0:
                            break
                        if val & ordinal_flag:
                            funcs.append(f"#{val & 0xFFFF}")
                            continue
                        hoff = rva2off(val & 0x7FFFFFFF)
                        if hoff and hoff + 2 <= len(data):
                            end = data.find(b"\0", hoff + 2)
                            funcs.append(data[hoff + 2:end].decode("ascii", "replace"))
                    if funcs:
                        result["import_funcs"][dll] = funcs[:200]
                off += 20

        # delay-load imports
        if dirs[13][0]:
            doff = rva2off(dirs[13][0])
            if doff and doff + 32 <= len(data):
                attrs = struct.unpack_from("<I", data, doff)[0]
                # version 2: name at +4? layout: attrs, name, modulehandle, iat, int, boundiat, unloadiat, timestamp
                n_rva = struct.unpack_from("<I", data, doff + 4)[0]
                noff = rva2off(n_rva)
                if noff:
                    dll = data[noff:data.find(b"\0", noff)].decode("ascii", "replace")
                    result["delay_imports"] = dll

        # exports (names)
        if dirs[0][0]:
            off = rva2off(dirs[0][0])
            if off and off + 40 <= len(data):
                n_names = struct.unpack_from("<I", data, off + 24)[0]
                names_rva = struct.unpack_from("<I", data, off + 32)[0]
                noff = rva2off(names_rva)
                if noff and 0 < n_names < 100000:
                    for i in range(min(n_names, 500)):
                        nrva = struct.unpack_from("<I", data, noff + i * 4)[0]
                        fo = rva2off(nrva)
                        if fo:
                            end = data.find(b"\0", fo)
                            result["exports"].append(data[fo:end].decode("ascii", "replace"))

        # resources (type level)
        if dirs[2][0]:
            roff = rva2off(dirs[2][0])
            if roff and roff + 16 <= len(data):
                RT = {1: "CURSOR", 2: "BITMAP", 3: "ICON", 4: "MENU", 5: "DIALOG",
                      6: "STRING", 9: "ACCELERATOR", 10: "RCDATA", 11: "MESSAGETABLE",
                      12: "GROUP_CURSOR", 14: "GROUP_ICON", 16: "VERSION", 24: "MANIFEST"}
                n_named, n_id = struct.unpack_from("<HH", data, roff + 12)
                entry_off = roff + 16
                for i in range(min(n_named + n_id, 40)):
                    if entry_off + 8 > len(data):
                        break
                    name_e, off_e = struct.unpack_from("<II", data, entry_off)
                    is_dir = off_e & 0x80000000
                    rid = name_e & 0xFFFF if not (name_e & 0x80000000) else name_e & 0x7FFFFFFF
                    if is_dir:
                        sub = rva2off(dirs[2][0] + (off_e & 0x7FFFFFFF))
                        if sub and sub + 16 <= len(data):
                            sn, si = struct.unpack_from("<HH", data, sub + 12)
                            for j in range(min(sn + si, 20)):
                                se = sub + 16 + j * 8
                                if se + 8 > len(data):
                                    break
                                _, oe2 = struct.unpack_from("<II", data, se)
                                if oe2 & 0x80000000:
                                    lang_off = rva2off(dirs[2][0] + (oe2 & 0x7FFFFFFF))
                                    if lang_off and lang_off + 16 <= len(data):
                                        ln, li = struct.unpack_from("<HH", data, lang_off + 12)
                                        for k in range(min(ln + li, 10)):
                                            le = lang_off + 16 + k * 8
                                            if le + 8 > len(data):
                                                break
                                            _, de = struct.unpack_from("<II", data, le)
                                            if not (de & 0x80000000):
                                                doff = rva2off(dirs[2][0] + de)
                                                if doff and doff + 16 <= len(data):
                                                    d_rva, d_sz = struct.unpack_from("<II", data, doff)
                                                    result["resources"].append(
                                                        f"{RT.get(rid, 'TYPE'+str(rid))} #{i} size={d_sz}")
                    entry_off += 8
                result["resources"] = result["resources"][:60]

        # debug directory -> PDB path
        if dirs[6][0]:
            doff = rva2off(dirs[6][0])
            if doff and doff + 28 <= len(data):
                n_entries = dirs[6][1] // 28
                for i in range(min(n_entries, 20)):
                    eoff = doff + i * 28
                    dtype = struct.unpack_from("<I", data, eoff + 12)[0]
                    dsize, dptr_rva = struct.unpack_from("<II", data, eoff + 16)
                    if dtype == 2:  # CodeView
                        poff = rva2off(dptr_rva)
                        if poff and data[poff:poff + 4] == b"RSDS":
                            end = data.find(b"\0", poff + 24)
                            result["pdb"] = data[poff + 24:end].decode("ascii", "replace")

        return result
    except Exception as e:
        return {"kind": "pe", "error": str(e)}


# ---------------------------------------------------------------- ELF parser

ELF_MACHINES = {3: "x86", 62: "x86-64", 40: "ARM", 183: "AArch64",
                8: "MIPS", 20: "PPC", 21: "PPC64", 243: "RISC-V"}
ELF_TYPES = {0: "NONE", 1: "REL", 2: "EXEC", 3: "DYN", 4: "CORE"}
SHT = {0: "NULL", 1: "PROGBITS", 2: "SYMTAB", 3: "STRTAB", 4: "RELA",
       9: "RELAS", 11: "DYNSYM", 14: "INIT_ARRAY"}
PT = {0: "NULL", 1: "LOAD", 2: "DYNAMIC", 3: "INTERP", 4: "NOTE",
      6: "PHDR", 7: "TLS", 0x6474E550: "GNU_EH_FRAME", 0x6474E551: "GNU_STACK",
      0x6474E552: "GNU_RELRO"}


def parse_elf(data: bytes):
    if len(data) < 64 or data[:4] != b"\x7fELF":
        return None
    try:
        is64 = data[4] == 2
        e = "<" if data[5] == 1 else ">"
        if is64:
            etype, mach = struct.unpack_from(e + "HH", data, 16)
            entry = struct.unpack_from(e + "Q", data, 24)[0]
            phoff = struct.unpack_from(e + "Q", data, 32)[0]
            shoff = struct.unpack_from(e + "Q", data, 40)[0]
            phentsize, phnum = struct.unpack_from(e + "HH", data, 54)
            shentsize, shnum, shstrndx = struct.unpack_from(e + "HHH", data, 58)
        else:
            etype, mach = struct.unpack_from(e + "HH", data, 16)
            entry = struct.unpack_from(e + "I", data, 24)[0]
            phoff = struct.unpack_from(e + "I", data, 28)[0]
            shoff = struct.unpack_from(e + "I", data, 32)[0]
            phentsize, phnum = struct.unpack_from(e + "HH", data, 42)
            shentsize, shnum, shstrndx = struct.unpack_from(e + "HHH", data, 46)
        secs = []
        if shoff and shentsize and shnum < 10000:
            for i in range(shnum):
                o = shoff + i * shentsize
                if is64:
                    name, typ, _, _, off, size = struct.unpack_from(e + "IIQQQQ", data, o)
                else:
                    name, typ, _, _, off, size = struct.unpack_from(e + "IIIIII", data, o)
                secs.append({"name_off": name, "type": SHT.get(typ, str(typ)),
                             "off": off, "size": size})
            shstr_off = secs[shstrndx]["off"] if 0 <= shstrndx < len(secs) else 0
            for s in secs:
                if shstr_off and s["name_off"] < 0x100000:
                    fo = shstr_off + s["name_off"]
                    end = data.find(b"\0", fo)
                    s["name"] = data[fo:end].decode("ascii", "replace") if fo < len(data) else "?"
                else:
                    s["name"] = "?"
        # program headers -> interpreter
        interp = None
        phdrs = []
        if phoff and phentsize and phnum < 1000:
            for i in range(phnum):
                o = phoff + i * phentsize
                if is64:
                    ptype = struct.unpack_from(e + "I", data, o)[0]
                    poff, pfilesz = struct.unpack_from(e + "QQ", data, o + 8)[1], struct.unpack_from(e + "Q", data, o + 32)[0]
                    # p_offset at +8, p_filesz at +32 for ELF64
                    poff = struct.unpack_from(e + "Q", data, o + 8)[0]
                    pfilesz = struct.unpack_from(e + "Q", data, o + 32)[0]
                else:
                    ptype = struct.unpack_from(e + "I", data, o)[0]
                    poff = struct.unpack_from(e + "I", data, o + 4)[0]
                    pfilesz = struct.unpack_from(e + "I", data, o + 16)[0]
                phdrs.append(PT.get(ptype, f"PT_{ptype}"))
                if ptype == 3 and poff + pfilesz <= len(data):  # PT_INTERP
                    interp = data[poff:poff + pfilesz].rstrip(b"\0").decode("utf-8", "replace")
        return {"kind": "elf", "class": "64" if is64 else "32",
                "type": ELF_TYPES.get(etype, etype),
                "machine": ELF_MACHINES.get(mach, f"0x{mach:x}"),
                "entry": hex(entry), "interpreter": interp,
                "program_headers": phdrs, "sections": secs}
    except Exception as ex:
        return {"kind": "elf", "error": str(ex)}


# ---------------------------------------------------------------- Mach-O parser

MACHO_MAGICS = {0xFEEDFACE: ("32", "BE"), 0xCEFAEDFE: ("32", "LE"),
                0xFEEDFACF: ("64", "BE"), 0xCFFAEDFE: ("64", "LE")}
LC_NAMES = {1: "SEGMENT", 0x19: "SEGMENT_64", 2: "SYMTAB", 0xB: "DYSYMTAB",
            0xC: "LOAD_DYLIB", 0xD: "ID_DYLIB", 0xE: "LOAD_DYLINKER", 0x1D: "CODE_SIGNATURE",
            0x22: "DYLD_INFO", 0x2A: "SOURCE_VERSION", 0x80000022: "DYLD_INFO_ONLY",
            0x24: "VERSION_MIN", 0x25: "FUNCTION_STARTS", 0x26: "DYLD_ENVIRONMENT"}
CPU = {7: "x86", 0x01000007: "x86-64", 12: "ARM", 0x0100000C: "ARM64"}


def parse_macho(data: bytes):
    if len(data) < 8:
        return None
    magic_be = struct.unpack(">I", data[:4])[0]
    if magic_be == 0xCAFEBABE:
        nfat = struct.unpack(">I", data[4:8])[0]
        if 0 < nfat < 16:
            archs = []
            for i in range(min(nfat, 8)):
                o = 8 + i * 20
                if o + 20 > len(data):
                    break
                cputype, cpusub, offset, size, align = struct.unpack(">IIIII", data, o)
                archs.append({"cpu": CPU.get(cputype, f"0x{cputype:x}"),
                              "offset": offset, "size": size})
            return {"kind": "macho", "variant": "fat", "archs": archs}
        return parse_class(data)
    info = MACHO_MAGICS.get(magic_be) or MACHO_MAGICS.get(struct.unpack("<I", data[:4])[0])
    if not info:
        return None
    bits, endian = info
    e = ">" if endian == "BE" else "<"
    try:
        cputype, cpusub, filetype, ncmds, sizeofcmds, flags, reserved = (
            struct.unpack_from(e + "IIIIIIII", data, 4) if bits == "64"
            else struct.unpack_from(e + "IIIIII", data, 4) + (0,))
        cmds = []
        segs = []
        off = 32 if bits == "64" else 28
        for _ in range(min(ncmds, 200)):
            if off + 8 > len(data):
                break
            cmd, cmdsize = struct.unpack_from(e + "II", data, off)
            name = LC_NAMES.get(cmd, f"cmd_0x{cmd:x}")
            cmds.append(name)
            if cmd in (1, 0x19) and cmdsize >= 16:  # segment carries a name
                segname = data[off + 8:off + 24].rstrip(b"\0").decode("ascii", "replace")
                segs.append(segname)
            if cmdsize < 8:
                break
            off += cmdsize
        return {"kind": "macho", "bits": bits, "endian": endian,
                "cpu": CPU.get(cputype, f"0x{cputype:x}"),
                "filetype": filetype, "segments": segs,
                "load_commands": cmds}
    except Exception as ex:
        return {"kind": "macho", "error": str(ex)}


# ---------------------------------------------------------------- Java class

def parse_class(data: bytes):
    if len(data) < 10 or data[:4] != b"\xca\xfe\xba\xbe":
        return None
    try:
        minor, major = struct.unpack(">HH", data[4:8])
        if major > 100 or minor > 1000:
            return {"kind": "unknown", "magic": "cafebabe"}
        cp_count = struct.unpack(">H", data[8:10])[0]
        cp = [None] * cp_count
        utf8s = []
        off = 10
        i = 1
        while i < cp_count and off + 3 <= len(data):
            tag = data[off]
            off += 1
            if tag == 1:
                ln = struct.unpack(">H", data[off:off + 2])[0]
                off += 2
                s = data[off:off + ln].decode("utf-8", "replace")
                off += ln
                cp[i] = ("Utf8", s)
                utf8s.append(s)
            elif tag in (7, 8, 16, 19, 20):
                cp[i] = ("ref", struct.unpack(">H", data[off:off + 2])[0]); off += 2
            elif tag == 15:
                cp[i] = ("mh", data[off], struct.unpack(">H", data[off + 1:off + 3])[0]); off += 3
            elif tag in (3, 4, 9, 10, 11, 12, 17, 18):
                cp[i] = ("pair", struct.unpack(">HH", data[off:off + 4])); off += 4
            elif tag in (5, 6):
                cp[i] = ("long", struct.unpack(">II", data[off:off + 8])); off += 8
                i += 1
            else:
                break
            i += 1
        access = struct.unpack(">H", data[off:off + 2])[0] if off + 2 <= len(data) else 0
        iface_n = struct.unpack(">H", data[off + 6:off + 8])[0] if off + 8 <= len(data) else 0
        foff = off + 8 + iface_n * 2
        fields = struct.unpack(">H", data[foff:foff + 2])[0] if foff + 2 <= len(data) else 0
        moff = foff + 2
        field_names = []
        for _ in range(fields):
            if moff + 8 > len(data):
                break
            ac, ni, di, ac2 = struct.unpack(">HHHH", data[moff:moff + 8])
            if 0 < ni < len(cp) and cp[ni] and cp[ni][0] == "Utf8":
                field_names.append(cp[ni][1])
            moff += 8
            for _ in range(ac2):
                if moff + 6 > len(data):
                    break
                moff += 6
        methods = struct.unpack(">H", data[moff:moff + 2])[0] if moff + 2 <= len(data) else 0
        moff += 2
        method_names = []
        for _ in range(methods):
            if moff + 8 > len(data):
                break
            ac, ni, di, ac2 = struct.unpack(">HHHH", data[moff:moff + 8])
            if 0 < ni < len(cp) and cp[ni] and cp[ni][0] == "Utf8":
                method_names.append(cp[ni][1])
            moff += 8
            for _ in range(ac2):
                if moff + 6 > len(data):
                    break
                moff += 6
        ident = [s for s in utf8s if re_ident(s)]
        return {"kind": "java-class", "version": f"{major}.{minor}",
                "cp_entries": cp_count, "access_flags": access,
                "interfaces": iface_n, "fields": fields, "methods": methods,
                "method_names": method_names[:80], "field_names": field_names[:40],
                "identifiers": ident[:80]}
    except Exception as e:
        return {"kind": "java-class", "error": str(e)}


def re_ident(s):
    return 0 < len(s) < 60 and s[0].isalpha() and all(c.isalnum() or c in "_$<>[]()" for c in s)


# ---------------------------------------------------------------- Python pyc

def parse_pyc(data: bytes):
    import importlib.util, marshal, dis, types
    magic = importlib.util.MAGIC_NUMBER
    if not data.startswith(magic):
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
                "co_names": list(code.co_names)[:60],
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
        for i in range(min(string_ids_size, 40)):
            so = string_ids_off + i * 4
            if so + 4 > len(data):
                break
            str_off = struct.unpack_from("<I", data, so)[0]
            j = str_off
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
        z = zipfile.ZipFile(io.BytesIO(data))
        names = z.namelist()
        dex = [n for n in names if n.endswith(".dex")]
        return {"kind": "apk" if any(n == "AndroidManifest.xml" for n in names) else "zip",
                "entries": len(names), "dex_files": dex,
                "has_manifest": "AndroidManifest.xml" in names,
                "has_resources": "resources.arsc" in names,
                "top": names[:50]}
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
        # walk sections: id(1) size(leb128)
        sections = []
        off = 8
        while off + 2 < len(data) and len(sections) < 30:
            sid = data[off]
            off += 1
            shift = 0
            size = 0
            while off < len(data):
                b = data[off]; off += 1
                size |= (b & 0x7F) << shift
                if not (b & 0x80):
                    break
                shift += 7
            SN = {0: "custom", 1: "type", 2: "import", 3: "function", 4: "table",
                  5: "memory", 6: "global", 7: "export", 8: "start", 9: "elem",
                  10: "code", 11: "data", 12: "datacount"}
            sections.append(f"{SN.get(sid, 'sec'+str(sid))}({size})")
            off += size
        return {"kind": "wasm", "version": f"0x{ver:08x}",
                "sections": sections,
                "note": "WebAssembly — use wasm2wat/wasm-decompile"}
    except Exception as e:
        return {"kind": "wasm", "error": str(e)}


# ---------------------------------------------------------------- carving

CARVE_SIGS = [
    (b"MZ", "PE/executable"), (b"\x7fELF", "ELF"), (b"\xca\xfe\xba\xbe", "Mach-O/Java"),
    (b"dex\n", "DEX"), (b"\x1bLua", "Lua bytecode"), (b"\0asm", "WASM"),
    (b"PK\x03\x04", "ZIP/APK/JAR"), (b"\x89PNG\r\n\x1a\n", "PNG"),
    (b"\xff\xd8\xff", "JPEG"), (b"GIF87a", "GIF"), (b"GIF89a", "GIF"),
    (b"%PDF", "PDF"), (b"SQLite format 3\0", "SQLite"),
    (b"Rar!\x1a\x07", "RAR"), (b"7z\xbc\xaf\x27\x1c", "7z"),
    (b"\x1f\x8b\x08", "GZIP"),
]


def carve(data: bytes, min_size=256):
    hits = []
    for sig, name in CARVE_SIGS:
        start = 0
        while True:
            i = data.find(sig, start)
            if i < 0:
                break
            # for MZ require e_lfanew sanity
            if sig == b"MZ":
                if i + 0x40 > len(data) or struct.unpack_from("<I", data, i + 0x3C)[0] > len(data):
                    start = i + 1
                    continue
            hits.append((i, name))
            start = i + 1
    return hits


# ---------------------------------------------------------------- disassembly

CS_ARCH = {
    "x86": (capstone.CS_ARCH_X86, capstone.CS_MODE_32) if capstone else None,
    "x86-64": (capstone.CS_ARCH_X86, capstone.CS_MODE_64) if capstone else None,
    "arm": (capstone.CS_ARCH_ARM, capstone.CS_MODE_ARM) if capstone else None,
    "arm64": (capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM) if capstone else None,
    "mips": (capstone.CS_ARCH_MIPS, capstone.CS_MODE_MIPS32) if capstone else None,
    "mips64": (capstone.CS_ARCH_MIPS, capstone.CS_MODE_MIPS64) if capstone else None,
    "ppc": (capstone.CS_ARCH_PPC, capstone.CS_MODE_32) if capstone else None,
    "sparc": (capstone.CS_ARCH_SPARC, capstone.CS_MODE_BIG_ENDIAN) if capstone else None,
}


def guess_code_region(info, data):
    if info.get("kind") == "pe":
        for s in info.get("section_list", []):
            if s["exec"] and s["raw_size"] > 0:
                base = info.get("image_base", 0)
                return info.get("machine", "x86-64"), s["raw_off"], min(s["raw_size"], 0x80000), s["va"] + base
        return info.get("machine", "x86-64"), 0, min(len(data), 0x80000), info.get("image_base", 0)
    if info.get("kind") == "elf":
        for s in info.get("sections", []):
            if s.get("name") in (".text",) and s["size"] > 0:
                return info.get("machine", "x86-64"), s["off"], min(s["size"], 0x80000), 0
        return info.get("machine", "x86-64"), 0, min(len(data), 0x80000), 0
    return "x86-64", 0, min(len(data), 0x80000), 0


def disassemble(data, arch, off, size, va=0, count=400):
    if not capstone:
        return "capstone not installed — pip install capstone"
    key = (arch or "").lower()
    if key not in CS_ARCH or not CS_ARCH[key]:
        for k in CS_ARCH:
            if k in key or key in k:
                key = k
                break
        else:
            return f"unsupported arch {arch}"
    a, m = CS_ARCH[key]
    md = capstone.Cs(a, m)
    code = data[off:off + size]
    lines = []
    base = va or off
    for i, ins in enumerate(md.disasm(code, base)):
        if i >= count:
            lines.append("...")
            break
        lines.append(f"{ins.address:016x}  {ins.bytes.hex():<24} {ins.mnemonic} {ins.op_str}")
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


def report(data, info):
    out = []
    kind = info.get("kind", "?")
    out.append(f"=== {info.get('file')} ===")
    out.append(f"size: {info.get('size', len(data)):,} bytes   type: {kind}")
    h = hashes(data)
    out.append(f"md5:    {h['md5']}")
    out.append(f"sha1:   {h['sha1']}")
    out.append(f"sha256: {h['sha256']}")
    out.append(f"entropy: {entropy(data[:1 << 20]):.2f}   map: {entropy_map(data)}")
    if "error" in info:
        out.append(f"parse error: {info['error']}")

    if kind == "pe":
        out.append(f"machine: {info.get('machine')}   {'PE32+' if info.get('is64') else 'PE32'}   "
                   f"subsystem: {info.get('subsystem')}   entry: RVA 0x{info.get('entry_rva',0):x}")
        out.append(f"image base: 0x{info.get('image_base',0):x}   compiled: {info.get('compile_time')}   "
                   f"timestamp: 0x{info.get('timestamp',0):08x}")
        flags = []
        if info.get("dotnet"): flags.append(".NET")
        if info.get("tls"): flags.append("TLS")
        if info.get("relocs"): flags.append("RELOCS")
        if info.get("delay_imports"): flags.append(f"DELAY({info['delay_imports']})")
        if info.get("signature_dir", (0,0))[1]: flags.append(f"SIGNED(dir size {info['signature_dir'][1]})")
        if info.get("pdb"): flags.append(f"PDB: {info['pdb']}")
        if info.get("packers"): flags.append("PACKER?: " + ", ".join(info["packers"]))
        if flags:
            out.append("flags: " + " | ".join(flags))
        if info.get("overlay"):
            ov = info["overlay"]
            out.append(f"overlay: {ov['size']:,} bytes @ 0x{ov['offset']:x} (entropy {ov['entropy']})")
        if info.get("section_list"):
            out.append("sections:")
            for s in info["section_list"]:
                raw = data[s["raw_off"]:s["raw_off"] + min(s["raw_size"], 1 << 20)] if s["raw_size"] else b""
                ent = f"{entropy(raw):.2f}" if raw else "-"
                out.append(f"  {s['name']:<8} va=0x{s['va']:08x} vsz=0x{s['vsize']:08x} "
                           f"raw=0x{s['raw_size']:08x} exec={s['exec']} ent={ent}")
        if info.get("imports"):
            out.append(f"imports ({len(info['imports'])} dlls): " + ", ".join(info["imports"][:30]))
            for dll, funcs in list(info.get("import_funcs", {}).items())[:12]:
                out.append(f"  {dll}: {', '.join(funcs[:15])}{' ...' if len(funcs) > 15 else ''}")
        if info.get("exports"):
            out.append(f"exports ({len(info['exports'])}): " + ", ".join(info["exports"][:40]))
        if info.get("resources"):
            out.append("resources: " + "; ".join(info["resources"][:30]))
        if info.get("dotnet"):
            out.append(">>> .NET managed assembly — for real decompilation use "
                       "ilspycmd (dotnet tool install -g ilspycmd) or dnSpy/AvaloniaILSpy")
    elif kind == "elf":
        out.append(f"class: {info.get('class')}-bit   type: {info.get('type')}   machine: {info.get('machine')}   "
                   f"entry: {info.get('entry')}   interp: {info.get('interpreter') or '-'}")
        out.append("program headers: " + ", ".join(info.get("program_headers", [])[:20]))
        names = [s.get("name", "?") for s in info.get("sections", [])]
        out.append("sections: " + ", ".join(names[:40]))
    elif kind == "macho":
        if info.get("variant") == "fat":
            out.append("universal binary:")
            for a in info.get("archs", []):
                out.append(f"  {a['cpu']} @ 0x{a['offset']:x} size=0x{a['size']:x}")
        else:
            out.append(f"cpu: {info.get('cpu')}   bits: {info.get('bits')}   endian: {info.get('endian')}   "
                       f"filetype: {info.get('filetype')}")
            if info.get("segments"):
                out.append("segments: " + ", ".join(info["segments"][:20]))
            out.append("load commands: " + ", ".join(info.get("load_commands", [])[:30]))
    elif kind == "java-class":
        out.append(f"class version {info.get('version')}   cp={info.get('cp_entries')} "
                   f"fields={info.get('fields')} methods={info.get('methods')}")
        if info.get("method_names"):
            out.append("methods: " + ", ".join(info["method_names"][:40]))
        if info.get("field_names"):
            out.append("fields: " + ", ".join(info["field_names"][:30]))
        if info.get("identifiers"):
            out.append("identifiers: " + " | ".join(info["identifiers"][:30]))
        out.append(">>> bytecode — full decompile: install CFR/procyon and run on the .class")
    elif kind == "pyc":
        out.append(f"code object: {info.get('name')}   file: {info.get('filename')}")
        out.append(f"args={info.get('argcount')} consts={info.get('consts')} "
                   f"names={info.get('names')} instructions={info.get('instructions')}")
        if info.get("co_names"):
            out.append("names: " + ", ".join(info["co_names"][:40]))
        if info.get("first_bytes"):
            out.append("disassembly (first instructions):")
            out.append(info["first_bytes"])
        out.append(">>> source recovery: pycdc / decompyle3 / pylingual")
    elif kind == "dex":
        out.append(f"dex v{info.get('version')}   strings={info.get('strings')} "
                   f"types={info.get('types')} classes={info.get('classes')}")
        out.append("sample strings: " + " | ".join(info.get("sample_strings", [])[:20]))
        out.append(">>> decompile: jadx / apktool")
    elif kind in ("apk", "zip"):
        out.append(f"zip archive — {info.get('entries')} entries")
        if info.get("dex_files"):
            out.append("dex files: " + ", ".join(info["dex_files"]))
        out.append(f"manifest: {info.get('has_manifest')}   resources.arsc: {info.get('has_resources')}")
        out.append("contents: " + ", ".join(info.get("top", [])[:30]))
    elif kind == "luac":
        out.append(f"lua bytecode v{info.get('version')} {info.get('endian')}-endian "
                   f"int={info.get('sizes',{}).get('int')}B")
        out.append(info.get("note", ""))
    elif kind == "wasm":
        out.append(f"wasm version {info.get('version')} — {info.get('note','')}")
        if info.get("sections"):
            out.append("sections: " + ", ".join(info["sections"]))
    elif kind == "raw":
        out.append(f"unrecognized format — entropy {info.get('entropy')} "
                   f"(8.0=encrypted/compressed, ~6-7=code, ~4-5=data)")
    return "\n".join(out)


def batch_scan(directory):
    rows = []
    for p in sorted(Path(directory).rglob("*")):
        if not p.is_file():
            continue
        try:
            data, info = analyze(str(p))
            rows.append((str(p), info.get("kind", "?"), info.get("size", 0),
                         round(entropy(data[:1 << 16]), 2)))
        except Exception as e:
            rows.append((str(p), f"error:{e}", 0, 0))
    w = max(len(r[0]) for r in rows) if rows else 10
    print(f"{'FILE':<{w}}  {'TYPE':<12} {'SIZE':>12}  ENT")
    for f, k, s, e in rows:
        print(f"{f:<{w}}  {k:<12} {s:>12,}  {e}")
    print(f"\n{len(rows)} files")


def main():
    ap = argparse.ArgumentParser(prog="unidecomp",
                                 description="Universal binary analysis & decompilation workbench")
    ap.add_argument("file", help="file to analyze (or directory with --batch)")
    ap.add_argument("--strings", action="store_true", help="extract strings only")
    ap.add_argument("--disasm", action="store_true", help="disassemble code section")
    ap.add_argument("--va", type=lambda x: int(x, 0), default=None, help="virtual address override")
    ap.add_argument("--size", type=lambda x: int(x, 0), default=None, help="bytes to disassemble")
    ap.add_argument("--arch", default=None, help="force arch (x86-64, arm64, ...)")
    ap.add_argument("--count", type=int, default=400, help="max instructions")
    ap.add_argument("--minlen", type=int, default=5, help="min string length")
    ap.add_argument("--no-utf16", action="store_true", help="skip UTF-16 string pass")
    ap.add_argument("--hash", action="store_true", help="hashes only")
    ap.add_argument("--carve", action="store_true", help="scan for embedded files")
    ap.add_argument("--batch", action="store_true", help="scan a directory recursively")
    ap.add_argument("--out", "-o", default=None, help="write report to file")
    ap.add_argument("--json", action="store_true", help="JSON output")
    args = ap.parse_args()

    if args.batch:
        if not os.path.isdir(args.file):
            print(f"error: {args.file} is not a directory", file=sys.stderr)
            sys.exit(1)
        batch_scan(args.file)
        return

    if not os.path.isfile(args.file):
        print(f"error: {args.file} not found", file=sys.stderr)
        sys.exit(1)
    data, info = analyze(args.file)

    if args.json:
        print(json.dumps(info, indent=2, default=str))
        return

    if args.hash:
        for k, v in hashes(data).items():
            print(f"{k}: {v}")
        return

    if args.strings:
        strs = extract_strings(data, args.minlen, not args.no_utf16)
        for s in strs[:5000]:
            print(s)
        print(f"\n# {len(strs)} strings", file=sys.stderr)
        return

    if args.carve:
        hits = carve(data)
        seen = {}
        for off, name in hits:
            seen.setdefault((name, off // 0x1000), []).append(off)
        for (name, _), offs in sorted(seen.items()):
            print(f"0x{offs[0]:08x}  {name}  ({len(offs)} hit{'s' if len(offs)>1 else ''})")
        if not hits:
            print("no embedded signatures found")
        return

    if args.disasm:
        arch, off, size, va = guess_code_region(info, data)
        if args.size:
            size = args.size
        if args.arch:
            arch = args.arch
        hdr = f"# arch={arch} offset=0x{off:x} size=0x{size:x} va=0x{va:x}"
        body = disassemble(data, arch, off, size, args.va if args.va is not None else va, args.count)
        text = hdr + "\n" + body + "\n"
        if args.out:
            Path(args.out).write_text(text)
            print(f"wrote {args.out}")
        else:
            print(text)
        return

    text = report(data, info) + "\n"
    if args.out:
        Path(args.out).write_text(text)
        print(f"wrote {args.out} ({len(text):,} chars)")
    else:
        print(text)


if __name__ == "__main__":
    main()
