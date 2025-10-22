from  argparse import ArgumentParser
from pathlib import Path 
import lief 
import re
import zipfile
import magic 
import struct 

results = {
           "file_type" : "Unknown",
           "architecture" : "Unknown", 
           "executable"   : "False",
           "encoding"     :  "Unknown",
           "language"     : "Unknown",
}

class Urfile_():
      def __init__(self,Path):
          self.path = Path 
          self.results = results.copy()
      
      def file_type(self):
          try:
               m = magic.Magic(mime=False)
               ftype = m.from_file(self.path)
               ftype = ftype.split(",")[0].strip()
               self.results["file_type"] = ftype
               ext = Path(self.path).suffix.lower()
               if ext == ".py":
                      self.results["file_type"] = "Python Script"
               elif ext == ".c":
                      self.results["file_type"] = "C Source File"
               elif ext in [".cpp", ".cc", ".cxx"]:
                      self.results["file_type"] = "C++ Source File"
               elif ext in [".sh",".bash",".zsh"]:
                      self.results["file_type"] = "Shell Script"
               elif ext == ".html" or ext == ".htm":
                      self.results["file_type"] = "HTML Document"
               elif ext == ".php":
                      self.results["file_type"] = "PHP Script"
               elif ext == ".js":
                     self.results["file_type"] = "JavaScript File"
               elif ext == ".java":
                     self.results["file_type"] = "Java Source File"
             
          except Exception:
              self.results["file type"] = "Unknown (magic unavailable)"

      def detecting_binary(self):
          with open(self.path,"rb")as f :
               header  = f.read(64)

 # ;; Windows EXE ;;
          if header[:2] == b"MZ":
             self.results["file_type"] = "Windows PE" 
             self.results["executable"] = True 
             with open(self.path,"rb") as f :
                  data = f.read()
                  offset = struct.unpack("<I",data[0x3C:0x40])[0]
                  if data[offset:offset+4] == b"PE\0\0":
                       machine = struct.unpack("<H", data[offset+4:offset+6])[0]
                       if machine == 0x14c:
                          self.results["architecture"] = "32-bit (x86)"
                       elif machine == 0x8664:
                            self.results["architecture"] = "64-bit (x64)"
                       else:
                          self.results["architecture"] = f"Unknown (machine={hex(machine)})"
# ;; Linux ELF ;; 
          elif header[:4] == b"\x7fELF":
               self.results["file_type"]  = "Linux ElF Executable"
               self.results["executable"] = True 
               bit_format = header[4]
               self.results["architecture"] = "32-bit" if bit_format  == 1 else "64=bit"
# ;; MacOS ;; 
          elif header[:4] in [
               b"\xFE\xED\xFA\xCE" , b"\xCE\xFA\xED\xFE",
               b"\xFE\xED\xFA\xCF" , b"\xCF\xFA\xED\xFE"
          ]:
               self.results["file_type"] = "macOs Mach-O Exceutable"
               self.results["exceutable"]  = True 
               self.results["architecture"] = "64-bit" if header[:4] in [b"\xFE\xED\xFA\xCF", b"\xCF\xFA\xED\xFE"] else "32-bit"


 # ;; Android APK  ;;
          elif zipfile.is_zipfile(self.path):
            try:
                with zipfile.ZipFile(self.path, "r") as z:
                    if "AndroidManifest.xml" in z.namelist():
                        self.results["file_type"] = "Android APK"
                        self.results["executable"] = False
                        self.results["language"] = "Android Package"
            except Exception:
                pass

           
# ;; Linux Shared Object (.so) ;;
          elif self.path.lower().endswith(".so"):
             if header[:4] == b"\x7fELF":
                self.results["file_type"] = "Linux Shared Object (.so)"
                self.results["executable"] = True
                bit_format = header[4]
                self.results["architecture"] = "32-bit" if bit_format == 1 else "64-bit"
# ;; zip (file);; 
          elif  header.startswith(b"PK\x03\x04"):
               self.results["file_type"] = "ZIP Archive"
               self.results["executable"] = False

# ;; 7-Zip ;;
          elif header.startswith(b"7z\xBC\xAF\x27\x1C"):
               self.results["file_type"] = "7z Archive"
               self.results["executable"] = False

# ;; RAR ;;
          elif header.startswith(b"Rar!\x1A\x07\x00"):
               self.results["file_type"] = "RAR Archive"
               self.results["executable"] = False

# ;; GZIP ;; 
          elif header.startswith(b"\x1F\x8B\x08"):
               self.results["file_type"] = "GZIP Archive (.gz)"
               self.results["executable"] = False


# ;; BZIP2 ;;
          elif header.startswith(b"BZh"):
               self.results["file_type"] = "BZIP2 Archive (.bz2)"
               self.results["executable"] = False
# ;; TAR ;;
          elif self.path.lower().endswith(".tar"):
             with open(self.path, "rb") as f:
                  data = f.read(512)
                  if b"ustar" in data:
                     self.results["file_type"] = "TAR Archive"
                     self.results["executable"] = False    


# ;; HTML ;; 
          else:
              try:
                  with open(self.path,"r",encoding="utf-8",error="ignore") as f :
                       content = f.read(2048).lower() 
                       if "<html" in content or "<!doctype html" in content:
                           self.results["file_type"] = "HTML Document"
                           self.results["encoding"] = "UTF-8"
                           self.results["language"] = "HTML"
                           self.results["exceutable"] = False 
              except Exception:
                   pass 
              
      

# ;; Text / Encoding Detection ;; 
          if self.results["encoding"].startswith("Unknown"):
             try:
                 with open(self.path,"rb") as f:
                     data = f.read(2048)   
                 if all(32 <= b < 127 or b in (9,10,13) for b in data):
                    self.results["encoding"]  = "ASCII"
                 elif b'\x00' not in data:
                     try:
                         data.decode("utf-8")                      
                         if self.results["file_type"] == "Unknown":
                            self.results["file_type"] = "UTF-8 Text File"
                         self.results["encoding"] = "UTF-8"
                     except UnicodeDecodeError:
                          pass 
             except Exception:
                 pass 

          p = Path(self.path)  
# file content
          try:
               with open(p, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read(2048)
                    if "def " in content and "import " in content:
                        self.results["language"] = "Python"
                    elif "#include" in content and "int main" in content:
                        self.results["language"] = "C/C++"
                    elif "function " in content and "console.log" in content:
                        self.results["language"] = "JavaScript"
                    elif "<?php" in content:
                         self.results["language"] = "PHP"
                    elif "class " in content and "public static void main" in content:
                         self.results["language"] = "Java"
          except Exception:
                 pass

       
# ;; Executable fallback ;; 
          if any(word in self.results["file_type"].lower() for word in ["executable", "pe", "elf", "mach-o"]):
             self.results["executable"] = True
          
          return self.results
      
 

PACKER_SIGNATURES = { "UPX": [b"UPX0", b"UPX1", b"UPX2", b"UPX!"],
    "Themida": [b"Themida", b"WIN32_Themida"],
    "VMProtect": [b"VMProtect", b"VMProtectSDK"],
    "ASPack": [b"ASPack", b"ASPACK"],
    "MPRESS": [b"MPRESS"],
    "PECompact": [b"PEC2", b"PECompact"],}

pe_dllds = [b"KERNEL32", b"MSVCRT", b"WS2_32", b"ADVAPI32", b"USER32", b"GDI32"]
elf_dynamic_ =  [b"DT_NEEDED", b"libc.so", b"ld-linux", b".so."]

def read_bytes(path):
    with open(path,"rb") as f:
        return f.read()
    

def detect_packer_(data):
    upper = data.upper()
    for name,sings in PACKER_SIGNATURES.items():
        for sig in sings:
            if sig.upper() in upper:
                return True,name 
    if b"UPX" in upper:
        return True,"UPX"
    if b"PACKED" in upper:
       return True,"Packed/Unkown"
    return False,None

def linking_and_stripped(path,data,ftype_):
    linking = None
    stripped = None
    upper = data.upper()

    if ftype_ and "PE" in ftype_.upper():
        if any(dll in upper for dll in pe_dllds):
            linking = "Dynamic"
        else:
            linking = "Static"
        if b"RSDS" in data or b".PDB"  in upper or b".DEBUG_" in upper:
            stripped = "Non-stripped"
        else:
            stripped = "Stripped"
    elif ftype_ and "ELF" in ftype_.upper():
         if any(tok in upper for tok in elf_dynamic_):
             linking = "Dynamic"
         else: 
             linking = "Static"  
         if  b".debug_info" in data or b".symtab" in data or    b".debug_str" in data:
             stripped = "Non_Stripped"
         else:
             stripped = "Stripped"
    
    else:
         if any (dll in upper for dll in pe_dllds):
             linking = "Dynamic"
         else:
             linking = "Unknown"
         if any(sym in upper for sym in [b"RSDS", b".PDB",b".DEBUG_INFO",b".SYMTAB"]):
            stripped = "Non-Stripped"
         else:
             stripped = "Unknown"

    return linking,stripped
         
def detect_protection(file,_lief=True):
      protections = {
          "pie": False,
          "nx": None,
          "relro": "None",
          "canary": False,
          "aslr": False,
          "packed": False,
          "stripped": None,
          "linking": None,
           }
   
      raw_bytes = b""
    # _lief  parsing 
      if _lief:
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
                     protections["stripped"] = "Non-stripped" if symtab and len(binary.symbols) > 0 else "Stripped" 
                     protections["linking"] = "Dynamic" if binary.libraries else "Static"

                  elif ftype == "PE":
                       dllchar = binary.optional_header.dll_characteristics_lists
                       protections["pie"] = "Dynamic_BASE" in dllchar
                       protections["aslr"] = protections["pie"]
                       protections["nx"]  = "NX_COMPAT" in dllchar
                       try:
                          names = [imp.name for lib in binary.imports for  imp in lib.entries if imp.name]
                       except Exception:
                          names = [] 
                       protections["canary"] = any("__security_cookie" in (n or "").lower() or "__stack_chk_fail" in (n or "").lower() for n in names)
                       protections["linking"] = "Dynamic" if binary.imports else "Static"
                       protections["stripped"] = "Non-Stripped" if getattr(binary, "has_debug", False) else "Stripped"
        
#  UPX sections
                  try:
                      section_names = [sec.name.lower() for sec in binary.sections]
                      if any("upx" in name for name in section_names):
                         protections["packed"] = True
                         protections["packer_name"] = "UPX"
                  except Exception:
                        pass   
         except Exception as e :
             protections["lief_error"] = str(e) 
        
 # RAw bytes analysis            
      try:
          raw_bytes = read_bytes()
      except Exception:
          raw_bytes = b""
 
      upper = raw_bytes()
      
      try:
          is_packed,packer = detect_packer_(file)
          if is_packed:
              protections["packed"] = True
              protections["packer_name"] = packer
      except Exception:
          pass

 # linking_stripped      
      try:
          if not protections.get("linking") or protections["linking"] ==  "Unknown":
              linking,stripped = linking_and_stripped(file,raw_bytes,results.get("file_type"))
              protections["linking"] = linking or protections.get("linking","Unknown")
              protections["stripped"] = stripped or protections.get("stripped","Unknown")
      except Exception:
          protections["linking"] = "Unkown"
          protections["stripped"] = "Unkown"
      
      return  protections 
 
 
 def main():
  parser = ArgumentParser(description="File Analyzer")
  parser.add_argument("file",type=Path,help="Path of your file ")
  parser.add_argument("--protections",action="store_true",help="Show only binary protection information")

  args = parser.parse_args() 
  if not args.file.exists():
      print(f"Error: File '{args.file}' not found.")
      return
 
  file = Urfile_(str(args.file))
  file.file_type() 
  results = file.detecting_binary() 
  protections = detect_protection(str(args.file))
  if protections:
        results["protections"] = protections
  
  print("\n[+] File Report ")
  print(f"File Path     : {args.file}")
  print(f"File Type     : {results.get('file_type', 'Unknown')}")
  print(f"Architecture  : {results.get('architecture', 'Unknown')}")
  print(f"Executable    : {results.get('executable', 'False')}")
  print(f"Encoding      : {results.get('encoding', 'Unknown')}")
  print(f"Language      : {results.get('language', 'Unknown')}\n")

#;; Output ;;

  if args.protections:
   print("\n[+] Binary Protections")
   prot = results.get("protections", {})
   labels = {
         "pie": "PIE",
         "nx": "NX",
         "relro": "RELRO",
         "canary": "Canary",
          "aslr": "ASLR",
         "packed": "Packed",
         "stripped": "Stripped",
         "linking": "Linking Type",
     }

   for key, label in labels.items():
         val = prot.get(key, None)
         if val is True:
             val = "Enabled"
         elif val is False:
             val = "Disabled"
         elif val is None:
             val = "Unknown"
         elif isinstance(val, str):
             # capitalize nice labels like "Full", "Static", etc.
             val = val.replace("_", " ").title()
         print(f"   {label:<14}: {val}")

   

if __name__ == "__main__":
   main()
