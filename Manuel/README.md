Manuel

Alphanumeric shellcode encoder made and used during my CTP/OSCE preperation. Written in Python (3?).

```
root@kali:~# python3 manuel.py -h
usage: manuel.py [-h] [-d] [-s SHELLCODE] [-sf SHELLFILE] [-f FORMAT]

optional arguments:
  -h, --help            show this help message and exit
  -d, --debug           Print debug information at runtime
  -s SHELLCODE, --shellcode SHELLCODE
                        Raw shellcode to encode (wrap in " ")
  -sf SHELLFILE, --shellfile SHELLFILE
                        Path to file holding raw shellcode
  -f FORMAT, --format FORMAT
                        Format: py = python
```

Example usage clips:
Standard usage
[![asciicast](https://asciinema.org/a/wctxFuqCnkM6gyPNn4KC3XFqo.svg)](https://asciinema.org/a/wctxFuqCnkM6gyPNn4KC3XFqo)


Usage with debug output
[![asciicast](https://asciinema.org/a/7VhMrAVPTm1W6V5P0afuxdUCt.svg)](https://asciinema.org/a/7VhMrAVPTm1W6V5P0afuxdUCt)

Usage with python ready output
[![asciicast](https://asciinema.org/a/sphDgkkyCrEuUonM3xNIEPuOd.svg)](https://asciinema.org/a/sphDgkkyCrEuUonM3xNIEPuOd)


Shellcode used in example clip, taken from: http://shell-storm.org/shellcode/files/shellcode-827.php

```
\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80
```
