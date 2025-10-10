from  argparse import ArgumentParser,FileType
from pathlib import Path 
import sys 
import magic 
import os 
import struct 

results = {
           "file_type" : "Unknown",
           "architecture" : "Unknown", 
           "executable"   : "False",
           "encoding"     :  "Unknown",
           "language"     : "Unknown"
}

class Urfile_():
      def __init__(self,Path):
          self.path = Path 
          self.results = results.copy()
      
      def file_type(self):
          try:
               m = magic.Magic(mime=False)
               ftype = m.from_file(self.path)
               self.results["file_type"] = ftype
          
          except Exception:
              self.results["file type"] = "Unknown (magic unavailable)"

      def detecting_binary(self.path):
          with open(self.path,"rb")as f :
               header  = f.read(64)
 # ;; Windows EXE ;;
          if header[:2] == b"MZ":
             self.results["file_type"] = "Windows PE" 
             self.results["exceutable"] = True 
             with open(self.path,"rb") as f :
                  data = f.read()
                  offset = struct.unpack("<I",data[0x3C:0x40])[0]
                  if data[offset:offset+4] == b"PE\0\0":
                       machine = struct.unpack("<H", data[offset+4:offset+6])[0]
                       if machine == 0x14c:
                          self.result["architecture"] = "32-bit (x86)"
                       elif machine == 0x8664:
                            self.result["architecture"] = "64-bit (x64)"
                       else:
                          self.result["architecture"] = f"Unknown (machine={hex(machine)})"
# ;; Linux ELF ;; 
          elif header[:4] == b"\x7fELF":
               self.results["file_type"]  = "Linux ElF Executable"
               self.results["exceutable"] = True 
               bit_format = header[4]
               self.results("architecture") = "32-bit" if bit_format  == 1 else "64=bit"
# ;; MacOS ;; 
          elif header[:4] in [
               b"\xFE\xED\xFA\xCE" , b"\xCE\xFA\xED\xFE",
               b"\xFE\xED\xFA\xCF" , b"\xCF\xFA\xED\xFE"
          ]:
               self.results["file_type"] = "macOs Mach-O Exceutable"
               self.results["exceutable"]  = True 
               self.results["architecture"] = "64-bit" if header[:4] in [b"\xFE\xED\xFA\xCF", b"\xCF\xFA\xED\xFE"] else "32-bit"
# ;; HTML ;; 
          else:
              try:
                  with 