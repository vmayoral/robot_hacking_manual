#!/usr/bin/env python
from pwn import *
import os

# # Compile the binary of narnia1
# os.system('gcc narnia1.c -g -m32 -o narnia1_local -fno-stack-protector -z execstack')

binary = ELF('narnia1_local', checksec=False)
main_addr=binary.symbols['main']
log.info("Main at "+ hex(main_addr))

# dissasemble the code
log.info("Disassembling the code")
log.info(disasm(binary.read(main_addr, 64), arch='x86'))

# log.info("Disassembling the code")
# log.info(disasm(hex(main_addr), 8))

# print(binary.read(binary.address+1, 3))
# # log.info("Main at: " + hex(main_addr))
# # hex(binary.plt['read'])
# print binary.disasm(binary.plt.read, 16)

# bash = ELF(which('bash'))
# # hex(bash.symbols['read'])
# # hex(bash.plt['read'])
# # u32(bash.read(bash.got['read'], 4))
# print bash.disasm(bash.plt.read, 64)
