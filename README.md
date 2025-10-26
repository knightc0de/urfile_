# 🧠 Urfile_ is a command line file Analyzer tool for windows.

## Features

- Detects file types — Supports PE, ELF, Mach-O, APK, archives, text formats, and scripts

- Architecture detection — Identifies 32-bit or 64-bit executables (Windows, Linux, macOS)

- Encoding detection — Detects ASCII, UTF-8, and binary formats

- Language detection — Recognizes Python, C/C++, JavaScript, Java, PHP, Shell, and HTML

- Archive recognition — Supports ZIP, 7z, RAR, TAR, GZIP, BZIP2

- Magic-based inspection — Uses the python-magic library for precise MIME and content inspection

### Requirements 
```bash
   pip install python-magic
```

## Usage
> Run directly from the command line:
``` bash  
python urfile_.py <path_to_file>
```
### Supported Formats
- Category	Types Detected
- Executables	Windows PE, Linux ELF, macOS Mach-O
- Mobile	Android APK
- Archives	ZIP, RAR, 7z, TAR, GZIP, BZIP2
- Source Code	Python, C/C++, Java, JavaScript, PHP, Shell
- Web	HTML, PHP
- Other	Text, Binary
