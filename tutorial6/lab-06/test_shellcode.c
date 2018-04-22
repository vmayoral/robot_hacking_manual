#include <string.h>
#include <stdio.h>
#include <sys/mman.h>

#include "shellcode"

int main()
{
        void (*f)(void);

        f = mmap(NULL, 4096, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        memcpy(f, shell_bin, shell_bin_len);
        f();
        return 0;
}
