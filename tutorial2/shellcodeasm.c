void main() {
__asm__(" \
          xor     %eax,       %eax; \
          xor     %edx,       %edx; \
          movb    $11,        %al; \
          push    %edx; \
          push    $0x68732f6e; \
          push    $0x69622f2f; \
          mov     %esp,       %ebx; \
          push    %edx; \
          push    %ebx; \
          mov     %esp,       %ecx; \
          int     $0x80; \
          movl   $0x1, %eax; \
          movl   $0x0, %ebx;  \
          int    $0x80;");
}
