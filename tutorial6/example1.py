#!/usr/bin/env python
from pwn import *

leaky_elf = ELF('leaky')
main_addr = leaky_elf.symbols['main']

# Print address of main
log.info("Main at: " + hex(main_addr))

# Disassemble the first 14 bytes of main
log.info(disasm(leaky_elf.read(main_addr, 14), arch='x86'))
