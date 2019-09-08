#!/usr/bin/env python
from pwn import *

sh_shellcode = """
        mov eax, 11
        push 0
        push 0x68732f6e
        push 0x69622f2f
        mov ebx, esp
        mov ecx, 0
        mov edx, 0
        int 0x80
"""

e = ELF.from_assembly(sh_shellcode, vma=0x400000)

with open('test_shell', 'wb') as f:
    f.write(e.get_data())
