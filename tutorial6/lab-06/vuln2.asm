extern printf, strcpy

section .data
fmstr: db "Here's your leek: %p",0xa,0
section .text
global main
main:
	push ebp
	mov ebp, esp
	sub esp, 64
	lea edi, [ebp - 64]         ; buf
	push edi
	push fmstr
	call printf
	mov eax, [ebp + 8]          ; argc
	cmp eax, 2
	jne away
	mov ebx, dword [ebp + 12]   ; argv
	mov ebx, dword [ebx + 4]    ; argv[1]
	push ebx
	push edi
	call strcpy
	leave
	ret
away:
	mov eax, 1
	mov ebx, -1
	int 0x80
