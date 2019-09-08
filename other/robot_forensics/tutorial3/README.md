### Capturing memory in Linux-based robots

This tutorial will explore how to capture memory in Linux-based robots.

#### No developers' tools required
##### Using `/dev/mem`
```bash
sudo dd if=/dev/mem of=/home/vagrant/robot.dd bs=1MB count=10
```
then test it:
```bash
vol.py --profile LinuxUbuntu14045x64 -f robot.dd linux_pslist
Volatility Foundation Volatility Framework 2.6
Offset             Name                 Pid             PPid            Uid             Gid    DTB                Start Time
------------------ -------------------- --------------- --------------- --------------- ------ ------------------ ----------
No suitable address space mapping found
Tried to open image as:
 MachOAddressSpace: mac: need base
 LimeAddressSpace: lime: need base
...
```

Not able to perform captures this way. Probably related to the fact that this interface was disabled in most Linux distributions for security concerns.

**Failed to do something useful with this in modern kernels**.

#### Some developers' tools required
##### Using ptrace

```bash
git clone https://github.com/citypw/lcamtuf-memfetch
cd lcamtuf-memfetch/
make
```

This generated a binary called memfetch. `ptrace` is used in the following manner:
```bash
vagrant@vagrant-ubuntu-trusty-64:~/lcamtuf-memfetch$ grep -r ptrace .
./README:     a ptrace-based debugger like strace, ltrace or gdb.
./README:  6) Because ptrace() interface stinks, you cannot use -s in conjunction
Binary file ./memfetch matches
./memfetch.c:#include <sys/ptrace.h>
./memfetch.c:	if (tracepid>0) ptrace(PTRACE_DETACH,tracepid,NULL,(void*)lastsig); \
./memfetch.c:		ptrace(PTRACE_CONT,tracepid,0,(void*)lastsig);
./memfetch.c:				writeptr[j]=ptrace(PTRACE_PEEKDATA, tracepid, (void*)(offset+i*page_size+j*4), 0);
./memfetch.c:	if (ptrace(PTRACE_ATTACH,tracepid,0,0))
./memfetch.c:				ptrace(PTRACE_PEEKDATA, tracepid, (void*)i, 0);
./memfetch.c:	ptrace(PTRACE_DETACH,tracepid,0,(void*)lastsig);
```

then use it with `sudo memfetch <process-PID>`. It will generate results similar to the use of the `linux_dump_map` volatility plugin.


#### Kernel modules
##### Using `/dev/fmem`
Install it:
```bash
git clone https://github.com/NateBrune/fmem
cd fmem && make
sudo ./run.sh
```
then capture memory:
```bash
sudo dd if=/dev/fmem of=memory.dump bs=1MB count=1000
```
and test it:
```bash
vagrant@vagrant-ubuntu-trusty-64:~$ vol.py --profile LinuxUbuntu14045x64 -f memory.dump linux_pslist
Volatility Foundation Volatility Framework 2.6
Offset             Name                 Pid             PPid            Uid             Gid    DTB                Start Time
------------------ -------------------- --------------- --------------- --------------- ------ ------------------ ----------
0xffff88001dc38000 init                 1               0               0               0      0x000000001dfb4000 2018-11-04 10:12:09 UTC+0000
0xffff88001dc39800 kthreadd             2               0               0               0      ------------------ 2018-11-04 10:12:09 UTC+0000
0xffff88001dc3b000 ksoftirqd/0          3               2               0               0      ------------------ 2018-11-04 10:12:09 UTC+0000
0xffff88001dc3c800 kworker/0:0          4               2               0               0      ------------------ 2018-11-04 10:12:09 UTC+0000
0xffff88001dc3e000 kworker/0:0H         5               2               0               0      ------------------ 2018-11-04 10:12:09 UTC+0000
0xffff88001dcd1800 rcu_sched            7               2               0               0      ------------------ 2018-11-04 10:12:09 UTC+0000
...
```


##### Using LiME `/dev/mem`

LiME can be installed as follows:
```bash
cd $HOME && git clone https://github.com/504ensicsLabs/LiME
cd $HOME/LiME/src && make
cd $HOME/LiME/src && cp lime-*.ko lime.ko
cd $HOME/LiME/src && sudo mv lime.ko /lib/modules/
```
and it can be used to capture memory in the following manner:
```bash
sudo insmod /lib/modules/lime.ko "path=/home/vagrant/robot.lime format=lime"
# to remove module:
sudo rmmod /lib/modules/lime.ko
```
then test it:
```bash
vol.py --profile LinuxUbuntu14045x64 -f robot.lime linux_pslist
```


### Resources
- [1] Mendia, G. O., Juan, L. U. S., Bascaran, X. P., Calvo, A. B., Cordero, A. H., Ugarte, I. Z., ... & Vilches, V. M. (2018). Robotics CTF (RCTF), a playground for robot hacking. arXiv preprint arXiv:1810.02690.
- [2] How to dump memory image from linux system? Retrieved from https://unix.stackexchange.com/questions/119762/how-to-dump-memory-image-from-linux-system
- [3] volatility. Retrieved from https://github.com/volatilityfoundation/volatility.
