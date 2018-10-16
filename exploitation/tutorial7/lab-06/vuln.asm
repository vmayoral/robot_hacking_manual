extern gets
extern printf

section .data
formatstr: db "Enjoy your leak: %p",0xa,0

section .text
global main
main:
	push ebp
	mov ebp, esp
	sub esp, 64
	lea ebx, [ebp - 64]
	push ebx
	push formatstr
	call printf
	push ebx
	call gets
	add esp, 4
	leave
	ret
