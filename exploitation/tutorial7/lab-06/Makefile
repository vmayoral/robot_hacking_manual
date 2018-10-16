all: vuln vuln2 test_shellcode shell.bin shellcode

vuln: vuln.asm
	nasm $< -f elf32
	gcc -m32 -fno-stack-protector -z execstack vuln.o -o $@

vuln2: vuln2.asm
	nasm $< -f elf32
	gcc -m32 -fno-stack-protector -z execstack vuln2.o -o $@

shell.bin: shellcode_exit.S
	nasm $< -o $@

shellcode: shell.bin
	xxd -i $< > $@

test_shellcode: test_shellcode.c shellcode
	gcc -m32 -o $@ $<

clean:
	rm -rf vuln vuln.o vuln2 vuln2.o shell.bin test_shellcode shellcode
