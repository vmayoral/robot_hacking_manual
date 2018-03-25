# Buffer overflows

The objective of this tutorial is to show how buffer overflows can affect the behavior of a program. The typical memory layout of a program is as follows:
```
                              /------------------\  higher
                              |                  |  memory
                              |                  |  addresses
                              |------------------|
                              |                  |
                            | |       Stack      |
                    growth  | |                  |
                  direction v |-.-.-.-.-.-.-.-.-.|
                              |                  |
                              |                  |
                              |                  |
                              |                  |
                              |                  |
                              |-.-.-.-.-.-.-.-.-.|
                            ^ |                  |
                    growth  | |       Heap       |
                  direction | |                  |
                              |------------------|
                              |   Uninitialized  |
                              |        Data      |
                              |       (bss)      |
                              |------------------|
                              |    Initialized   |
                              |        Data      |
                              |------------------|
                              |                  |  
                              |       Text       |  lower
                              |                  |  memory
                             \------------------/   addresses
```

As described at http://insecure.org/stf/smashstack.html, a stack is an abstract data type frequently used in computer science to represent (likely) the most important technique for structuring programs, functions (or procedures). From one point of view, a function call alters the flow of control just as the `jump` instruction does, but unlike a jump, when finished performing its task, a function returns control to the  statement or instruction following the call. This high-level abstraction is implemented with the help of the stack.

In this tutorial, we'll be *overflowing* (aka, writing more than we should) a buffer in the stack to alter the behavior of a program. This will picture in a very simplistic way one of the main and most relevant problems in cybersecurity. Besides the use of the stack, the following registers are also of relevance:

- **(E)SP**: the stack pointer, points to the last address on the stack (or  to the next free available address after the stack in some implementations)
- **(E)BP**, the frame pointer, facilitates access to local variables.

The code we will be using to picture the overflow is below:
```C
0: void function(int a, int b, int c) {
1:    char buffer1[5];
2:    char buffer2[10];
3:    int *ret;
4:
5:    ret = buffer1 + 26;
6:    (*ret) += 8;
7: }
8:
9: void main() {
a:   int x;
b:
c:   x = 0;
d:   function(1,2,3);
e:   x = 1;
f:   printf("%d\n",x);
10: }
```

To facilitate reproducing this hack, a docker container has been built. The `Dockerfile` is available within this tutorial and can be built as follows:

**Note**: *docker containers match the architecture of the host machine. For simplicity, the container will be built using a 32 bit architecture.*

```bash
docker build -t basic_cybersecurity1:latest .
```

Now, run it:
```bash
docker run --privileged -it basic_cybersecurity1:latest
root@3c9eab7fde0b:~# ./overflow
0
```

Interestingly, the code jumps over line `e`:
```
e:   x = 1;
```
And simply dumps in the standard output the initial and unmodified value of the `x` variable.

Let's analyze the memory to understand why this is happening.

### Analyzing the memory
The docker container has fetched a `.gdbinit` file which provides a nice environment wherein one can study the internals of the memory. Let's see the state of the memory and registers at line `5`:
- esp: `0xffffd7c0`
- ebp: `0xffffd7e8`

```
0xffffd7c0 ff ff ff ff ee d7 ff ff 34 0c e3 f7 f3 72 e5 f7 ........4 ...r..
0xffffd7d0 00 00 00 00 00 00 c3 00 01 00 00 00 01 83 04 08 ................
0xffffd7e0 b8 d9 ff ff 2f 00 00 00 18 d8 ff ff d4 84 04 08 ..../...........
0xffffd7f0 01 00 00 00 02 00 00 00 03 00 00 00 ad 74 e5 f7 .............t..
```

The first observation is that the `base pointer` is at `0xffffd7e8` which means that the *return* address (from `function`) is 4 bytes after, in other words at `0xffffd7ec` with a value of `d4 84 04 08` according to the memory displayed above which transforms into `0x080484d4` with the right endianness.

From literature, the memory diagram of the stack is expected to be as follows:
```
bottom of                                                                             top of
memory                                                                                memory
                ret      buffer2      buffer1   ebp     return      a      b      c
<-----      [        ][            ][        ][     ][0x080484d4][     ][     ][     ]
(growth)

top of                                                                               bottom of
stack                                                                                   stack
```
However it's not like this. Newer compilers (gcc), play tricks on the memory layout to prevent overflows and malicious attacks. In particular, the local variables have the following locations:
```
>>> p &buffer1
$1 = (char (*)[5]) 0xffffd7d2
>>> p &buffer2
$2 = (char (*)[10]) 0xffffd7d2
>>> p &ret
$3 = (int **) 0xffffd7cc
```

It's interesting to note that both, `buffer1` and `buffer2` point to the same address. Likely, due to the fact that both variables aren't used within the code.

Lines of code `5` and `6` aim to modify a value in the stack:
```
5:    ret = buffer1 + 26;
6:    (*ret) += 8;
```
Knowing that `buffer1 = 0xffffd7d2` then `ret` will be:
```
>>> p 0xffffd7d2 + 26
$5 = 4294957036
```
Which in hexadecimal is `0xffffd7ec`. Not surprisingly, **this address is exactly the same as the one of the return address**. Line `6` of code adds `8` to the *value* of the return address which results in a memory layout as follows (the change has been [highlighted]):
```
0xffffd7c0 ff ff ff ff ee d7 ff ff 34 0c e3 f7 ec d7 ff ff ........4 ......
0xffffd7d0 00 00 00 00 00 00 c3 00 01 00 00 00 00 8d 5a f7 ..............Z.
0xffffd7e0 b8 d9 ff ff 2f 00 00 00 18 d8 ff ff [dc 84 04 08] ..../...........
0xffffd7f0 01 00 00 00 02 00 00 00 03 00 00 00 ad 74 e5 f7 .............t..
```

To understand the rationale behind this, let's look at the assembly code of the `main` function:
```
>>> disassemble main
Dump of assembler code for function main:
   0x080484a7 <+0>:	push   %ebp
   0x080484a8 <+1>:	mov    %esp,%ebp
   0x080484aa <+3>:	and    $0xfffffff0,%esp
   0x080484ad <+6>:	sub    $0x20,%esp
   0x080484b0 <+9>:	movl   $0x0,0x1c(%esp)
   0x080484b8 <+17>:	movl   $0x3,0x8(%esp)
   0x080484c0 <+25>:	movl   $0x2,0x4(%esp)
   0x080484c8 <+33>:	movl   $0x1,(%esp)
   0x080484cf <+40>:	call   0x804846d <function>
   0x080484d4 <+45>:	movl   $0x1,0x1c(%esp)
   0x080484dc <+53>:	mov    0x1c(%esp),%eax
   0x080484e0 <+57>:	mov    %eax,0x4(%esp)
   0x080484e4 <+61>:	movl   $0x8048590,(%esp)
   0x080484eb <+68>:	call   0x8048330 <printf@plt>
   0x080484f0 <+73>:	leave  
   0x080484f1 <+74>:	ret    
End of assembler dump.
```

Note that in address `0x080484cf <+40>` a call to `function` is produced and the return address `0x080484d4` (the address of the next assembly instruction) is pushed into the stack.

Putting all together, the `overflow.c` program is modifying the *return address* and adding 8 bytes pointing to `0x080484dc` so that the instruction at `0x080484d4` (`movl   $0x1,0x1c(%esp)`) is skipped which results in the program printing the initial value of variable `x`.
