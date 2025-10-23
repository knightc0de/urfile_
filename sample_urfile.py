from argparse import ArgumentParser
from pathlib import Path
import lief
import zipfile
import magic
import struct
import re

results = { 
    "file_type": "Unknown",
    "architecture": "Unknown",
    "executable": "False",
    "encoding": "Unknown",
    "language": "Unknown",
}

class Urfile_:
    def __init__(self, path):
        self.path = path
        self.results = results.copy()

    def file_type(self):
        try:
            m = magic.Magic(mime=False)
            ftype = m.from_file(self.path)
            ftype = ftype.split(",")[0].strip()
            self.results["file_type"] = ftype
            ext = Path(self.path).suffix.lower()
            file_map = {
                ".py": "Python Script",
                ".c": "C Source File",
                ".cpp": "C++ Source File",
                ".cc": "C++ Source File",
                ".cxx": "C++ Source File",
                ".sh": "Shell Script",
                ".bash": "Shell Script",
                ".zsh": "Shell Script",
                ".html": "HTML Document",
                ".htm": "HTML Document",
                ".php": "PHP Script",
                ".js": "JavaScript File",
                ".java": "Java Source File",
            }
            if ext in file_map:
                self.results["file_type"] = file_map[ext]
        except Exception:
            self.results["file_type"] = "Unknown (magic unavailable)"

    def detecting_binary(self):
        with open(self.path, "rb") as f:
            header = f.read(64)

        # Windows PE
        if header[:2] == b"MZ":
            self.results["file_type"] = "Windows PE"
            self.results["executable"] = True
            try:
                with open(self.path, "rb") as f:
                    data = f.read()
                    offset = struct.unpack("<I", data[0x3C:0x40])[0]
                    if data[offset:offset+4] == b"PE\0\0":
                        machine = struct.unpack("<H", data[offset+4:offset+6])[0]
                        if machine == 0x14c:
                            self.results["architecture"] = "32-bit (x86)"
                        elif machine == 0x8664:
                            self.results["architecture"] = "64-bit (x64)"
                        else:
                            self.results["architecture"] = f"Unknown (machine={hex(machine)})"
            except Exception:
                pass

        # ELF
        elif header[:4] == b"\x7fELF":
            self.results["file_type"] = "Linux ELF Executable"
            self.results["executable"] = True
            bit_format = header[4]
            self.results["architecture"] = "32-bit" if bit_format == 1 else "64-bit"

        # APK / ZIP
        elif zipfile.is_zipfile(self.path):
            try:
                with zipfile.ZipFile(self.path, "r") as z:
                    if "AndroidManifest.xml" in z.namelist():
                        self.results["file_type"] = "Android APK"
                        self.results["language"] = "Android Package"
            except Exception:
                pass

        return self.results


# ---------------------------
# Fallback helpers (byte-based)
# ---------------------------
PACKER_SIGNATURES = {
    "UPX": [b"UPX0", b"UPX1", b"UPX2", b"UPX!"],
    "Themida": [b"Themida", b"WIN32_Themida"],
    "VMProtect": [b"VMProtect", b"VMProtectSDK"],
    "ASPack": [b"ASPack", b"ASPACK"],
    "MPRESS": [b"MPRESS"],
    "PECompact": [b"PEC2", b"PECompact"],
}

COMMON_PE_DLLS = [b"KERNEL32", b"MSVCRT", b"WS2_32", b"ADVAPI32", b"USER32", b"GDI32"]
ELF_DYNAMIC_HINTS = [b"DT_NEEDED", b"libc.so", b"ld-linux", b".so."]

def read_all_bytes(path):
    with open(path, "rb") as f:
        return f.read()

def detect_packer_from_bytes(data):
    upper = data.upper()
    for name, sigs in PACKER_SIGNATURES.items():
        for sig in sigs:
            if sig.upper() in upper:
                return True, name
    if b"UPX" in upper:
        return True, "UPX"
    if b"PACKED" in upper:
        return True, "Packed/Unknown"
    return False, None

def fallback_linking_and_stripped(path, data, ftype_hint):
    linking = None
    stripped = None
    upper = data.upper()

    if ftype_hint and "PE" in ftype_hint.upper():
        if any(dll in upper for dll in COMMON_PE_DLLS):
            linking = "Dynamic"
        else:
            linking = "Static"
        if b"RSDS" in data or b".PDB" in upper or b".DEBUG_" in upper:
            stripped = "Non-Stripped"
        else:
            stripped = "Stripped"

    elif ftype_hint and "ELF" in ftype_hint.upper():
        if any(tok in upper for tok in ELF_DYNAMIC_HINTS):
            linking = "Dynamic"
        else:
            linking = "Static"
        if b".debug_info" in data or b".symtab" in data or b".debug_str" in data:
            stripped = "Non-Stripped"
        else:
            stripped = "Stripped"

    else:
        if any(dll in upper for dll in COMMON_PE_DLLS) or any(tok in upper for tok in ELF_DYNAMIC_HINTS):
            linking = "Dynamic"
        else:
            linking = "Unknown"
        if any(x in upper for x in [b"RSDS", b".PDB", b".DEBUG_INFO", b".SYMTAB"]):
            stripped = "Non-Stripped"
        else:
            stripped = "Unknown"

    return linking, stripped


# ---------------------------
# Main protection detection
# ---------------------------
def detect_protection(file, use_lief=True):
    protections = {
        "pie": False,
        "nx": None,
        "relro": "None",
        "canary": False,
        "aslr": False,
        "packed": False,
        "packer_name": None,
        "stripped": None,
        "linking": None,
    }

    raw_bytes = b""

    # Step 1: LIEF parsing
    if use_lief:
        try:
            binary = lief.parse(file)
            if binary:
                ftype = binary.format.name

                if ftype == "ELF":
                    protections["pie"] = binary.is_pie
                    protections["aslr"] = binary.is_pie
                    protections["nx"] = binary.has_nx
                    protections["canary"] = "__stack_chk_fail" in [s.name for s in binary.symbols]
                    protections["relro"] = (
                        "Full" if binary.has_full_relro else
                        "Partial" if binary.has_partial_relro else
                        "None"
                    )
                    symtab = binary.get_section(".symtab")
                    protections["stripped"] = "Non-Stripped" if symtab and len(binary.symbols) > 0 else "Stripped"
                    protections["linking"] = "Dynamic" if binary.libraries else "Static"

                elif ftype == "PE":
                    dllchars = binary.optional_header.dll_characteristics_lists
                    protections["pie"] = "DYNAMIC_BASE" in dllchars
                    protections["aslr"] = protections["pie"]
                    protections["nx"] = "NX_COMPAT" in dllchars
                    try:
                        names = [imp.name for lib in binary.imports for imp in lib.entries if imp.name]
                    except Exception:
                        names = []
                    protections["canary"] = any("__security_cookie" in (n or "").lower() or "__stack_chk_fail" in (n or "").lower() for n in names)
                    protections["linking"] = "Dynamic" if binary.imports else "Static"
                    protections["stripped"] = "Non-Stripped" if getattr(binary, "has_debug", False) else "Stripped"

                # Check for UPX sections
                try:
                    section_names = [sec.name.lower() for sec in binary.sections]
                    if any("upx" in name for name in section_names):
                        protections["packed"] = True
                        protections["packer_name"] = "UPX"
                except Exception:
                    pass

        except Exception as e:
            protections["lief_error"] = str(e)

    # Step 2: Raw byte analysis
    try:
        raw_bytes = read_all_bytes(file)
    except Exception:
        raw_bytes = b""

    upper = raw_bytes.upper()

    # Step 3: Packer detection
    try:
        is_packed, packer = detect_packer_from_bytes(raw_bytes)
        if is_packed:
            protections["packed"] = True
            protections["packer_name"] = packer
    except Exception:
        pass

    # Step 4: Fallback linking/stripped
    try:
        if not protections.get("linking") or protections["linking"] == "Unknown":
            linking, stripped = fallback_linking_and_stripped(file, raw_bytes, results.get("file_type"))
            protections["linking"] = linking or protections.get("linking", "Unknown")
            protections["stripped"] = stripped or protections.get("stripped", "Unknown")
    except Exception:
        protections["linking"] = "Unknown"
        protections["stripped"] = "Unknown"

    return protections


# ---------------------------
# CLI Driver
# ---------------------------
def main():
    parser = ArgumentParser(description="File Analyzer with Binary Protection Detection")
    parser.add_argument("file", type=Path, help="Path to file")
    parser.add_argument("--protections", action="store_true", help="Show only binary protection info")
    parser.add_argument("--no-lief", action="store_true", help="Skip LIEF parsing (fast mode)")
    args = parser.parse_args()

    if not args.file.exists():
        print(f"Error: File '{args.file}' not found.")
        return

    uf = Urfile_(str(args.file))
    uf.file_type()
    results = uf.detecting_binary()

    protections = detect_protection(str(args.file), use_lief=not args.no_lief)
    results["protections"] = protections

    # If --protections only
    if args.protections:
        print(f"\n[+] Protection Report: {args.file}\n")
        labels = [
            ("pie", "PIE"),
            ("nx", "NX"),
            ("relro", "RELRO"),
            ("canary", "Canary"),
            ("aslr", "ASLR"),
            ("packed", "Packed"),
            ("packer_name", "Packer"),
            ("stripped", "Stripped"),
            ("linking", "Linking Type"),
        ]
        for key, label in labels:
            val = protections.get(key)
            if isinstance(val, bool):
                val = "Yes" if val else "No"
            elif val is None:
                val = "Unknown"
            print(f"  {label:<14}: {val}")
        print("\nAnalysis Complete ✅")
        return

    # Full report
    print(f"\n[+] File Report for: {args.file}\n")
    print(f"File Type     : {results.get('file_type')}")
    print(f"Architecture  : {results.get('architecture')}")
    print(f"Executable    : {results.get('executable')}")
    print(f"Encoding      : {results.get('encoding')}")
    print(f"Language      : {results.get('language')}\n")

    print("[+] Binary Protections\n")
    for key, label in [
        ("pie", "PIE"), ("nx", "NX"), ("relro", "RELRO"), ("canary", "Canary"),
        ("aslr", "ASLR"), ("packed", "Packed"), ("packer_name", "Packer"),
        ("stripped", "Stripped"), ("linking", "Linking Type")
    ]:
        val = protections.get(key)
        if isinstance(val, bool):
            val = "Yes" if val else "No"
        elif val is None:
            val = "Unknown"
        print(f"   {label:<14}: {val}")

    if "lief_error" in protections:
        print("\n[!] Note: LIEF parser failed while reading this binary.")
        print(f"    Reason: {protections['lief_error']}")
        print("    This may indicate the file is packed or corrupted.\n")

if __name__ == "__main__":
    main()
