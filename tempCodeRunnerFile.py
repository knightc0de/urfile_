    
      def file_type(self):
          try:
               m = magic.Magic(mime=False)
               ftype = m.from_file(self.path)
               if self.path.endswith(".py"):
                  self.results["file_type"] = "Python Script"
               ftype = ftype.split(",")[0].strip()
               self.results["file_type"] = ftype