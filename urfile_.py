from  argparse import ArgumentParser
from pathlib import Path 
import lief 
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
      
#;; protection & linking analysis ;; 

def detect_protection(file):
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

      try:
          binary = lief.parse(file)
          if not binary:
           return protections

          ftype = binary.format.name  

# ;; Linux Elf ;; 
          if ftype == "ELF":
               elf = binary
               protections["pie"] = elf.is_pie
               protections["aslr"] = elf.is_pie
               protections["nx"] = elf.has_nx
               protections["canary"] = "__stack_chk_fail" in [s.name for s in elf.symbols]
               protections["relro"] = (
                "Full" if elf.has_full_relro else
                "Partial" if elf.has_partial_relro else
                "None"
            )
            # stripped 
               symtab = elf.get_section(".symtab")
               results["stripped"] = (
                "Non-Stripped" if symtab and len(elf.symbols) > 0 else "Stripped"
            )
            # linking 
               results["linking"] = "Dynamic" if elf.libraries else "Static"
 


def main():
  parser = ArgumentParser(description="File Analyzer")
  parser.add_argument("file",type=Path,help="Path of your file ")
  args =  parser.parse_args()
  if not args.file.exists():
        print(f"Error: File '{args.file}' not found.")
        return
 
  file = Urfile_(str(args.file))
  file.file_type() 
  results = file.detecting_binary() 

  for k, v in results.items():
    print(f"{k:15}: {v}")



if __name__ == "__main__":
   main()
