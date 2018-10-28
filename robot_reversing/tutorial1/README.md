### Basic robot forensics, an unauthenticated unregistration in ROS

This tutorial will explore forensics tools to obtain details about an unregistered node in ROS exploiting a vulnerability in the ROS Master API due to a lack of authentication. The content here builds from https://github.com/vmayoral/basic_robot_cybersecurity/tree/master/robot_exploitation/tutorial11. Review this tutorial first to figure out how to exploit the vulnerability.

As a side note and due to the use of memory acquisition techniques that require access to the kernel, docker can't be used. Instead a VM with vagrant will be set up. The first part of this tutorial will provide a walkthrough on the setup process.


#### Auxilary Docker image
An auxiliary docker image was created for development purposes

----

```bash
docker build -t basic_robot_cybersecurity_reversing1:latest .
```
and run with:
```bash
docker run -it basic_robot_cybersecurity_reversing1:latest
```

Unfortunately, docker does not provide all necessary utilities to perform the forensic analysis (lack of kernel, no memory dumps, etc.)

#### Setup process with vagrant
The pre-requisites are:
- Vagrant
- VirtualBox

Once this is installed, let's create the VM box. I've provided a `Vagrantfile` with provisioning to simplify the whole setup. Simply get into this tutorial's directory and do:
```bash
vagrant up --provision
```

This will get us a VM. We can ssh into it with `vagrant ssh`.


#### Forensic analysis

For the forensics, we'll use volatility project [7]. The first thing with volatility is to determine the profile. The docker container already has copied one within the source of volatility. We can verify this by doing:

```bash
root@eb955d625120:/# vol.py --info | grep Linux
Volatility Foundation Volatility Framework 2.6
LinuxUbuntu16045x64   - A Profile for Linux Ubuntu16045 x64
...
```

Ideally we should be using the `LinuxUbuntu14045x64` profile however sometimes it will simply not work and we'll need to create it manually. The following process describes how to do so:
```bash
cd ~/volatility/tools/linux
vagrant@vagrant-ubuntu-trusty-64:~/volatility/tools/linux$ make
make -C //lib/modules/3.13.0-161-generic/build CONFIG_DEBUG_INFO=y M="/home/vagrant/volatility/tools/linux" modules
make[1]: Entering directory `/usr/src/linux-headers-3.13.0-161-generic'
  CC [M]  /home/vagrant/volatility/tools/linux/module.o
/home/vagrant/volatility/tools/linux/module.c:193:0: warning: "RADIX_TREE_MAX_TAGS" redefined [enabled by default]
 #define RADIX_TREE_MAX_TAGS     2
 ^
In file included from include/linux/fs.h:15:0,
                 from /home/vagrant/volatility/tools/linux/module.c:10:
include/linux/radix-tree.h:61:0: note: this is the location of the previous definition
 #define RADIX_TREE_MAX_TAGS 3
 ^
  Building modules, stage 2.
  MODPOST 1 modules
  CC      /home/vagrant/volatility/tools/linux/module.mod.o
  LD [M]  /home/vagrant/volatility/tools/linux/module.ko
make[1]: Leaving directory `/usr/src/linux-headers-3.13.0-161-generic'
dwarfdump -di module.ko > module.dwarf
make -C //lib/modules/3.13.0-161-generic/build M="/home/vagrant/volatility/tools/linux" clean
make[1]: Entering directory `/usr/src/linux-headers-3.13.0-161-generic'
  CLEAN   /home/vagrant/volatility/tools/linux/.tmp_versions
  CLEAN   /home/vagrant/volatility/tools/linux/Module.symvers
make[1]: Leaving directory `/usr/src/linux-headers-3.13.0-161-generic'

vagrant@vagrant-ubuntu-trusty-64:~/volatility/tools/linux$ mkdir ~/profile
vagrant@vagrant-ubuntu-trusty-64:~/volatility/tools/linux$ cp module.dwarf ~/profile
vagrant@vagrant-ubuntu-trusty-64:~/volatility/tools/linux$ sudo cp /boot/System.map-3.13.0-161-generic ~/profile
vagrant@vagrant-ubuntu-trusty-64:~/volatility/tools/linux$ zip Ubuntu14045.zip profile/System.map profile/module.dwarf
vagrant@vagrant-ubuntu-trusty-64:~/volatility/tools/linux$ sudo mv Ubuntu14045.zip /usr/local/lib/python2.7/dist-packages/volatility-2.6-py2.7.egg/volatility/plugins/overlays/linux/
```

Then:
```bash
vagrant@vagrant-ubuntu-trusty-64:~$ vol.py --info|grep Linux
Volatility Foundation Volatility Framework 2.6
LinuxUbuntu14045x64   - A Profile for Linux Ubuntu14045 x64
LinuxAMD64PagedMemory          - Linux-specific AMD 64-bit address space.
linux_aslr_shift           - Automatically detect the Linux ASLR shift
linux_banner               - Prints the Linux banner information
linux_yarascan             - A shell in the Linux memory image
```

There it is: `LinuxUbuntu14045x64`.

Next thing we need is to acquire memory. To do so, we'll use `LiME` which has been shipped with the Vagrantfile. Let's make a memory capture prior to the hack:
```bash
roscore &
rosrun scenario1 talker &
rosrun scenario1 listener > /tmp/listener.txt &
sudo insmod /lib/modules/lime.ko "path=/home/vagrant/robot.lime format=lime"
# to remove module:
sudo rmmod /lib/modules/lime.ko
```
This will generate a `robot.lime` file.

Let's now disturb the robot simulation by exploiting the vulnerability reported at the top and record another memory dump:
```bash
roschaos master unregister node --node_name /publisher
sudo insmod /lib/modules/lime.ko "path=/home/vagrant/robot_hacked.lime format=lime"
sudo rmmod /lib/modules/lime.ko
```

Next is to use the memory dump and analyze it with `volatity`. Let's start enumerating the processes:
```bash
vol.py --profile LinuxUbuntu14045x64 -f robot.lime linux_pslist
vagrant@vagrant-ubuntu-trusty-64:~$ vol.py --profile LinuxUbuntu14045x64 -f robot.lime linux_pslist
Volatility Foundation Volatility Framework 2.6
Offset             Name                 Pid             PPid            Uid             Gid    DTB                Start Time
------------------ -------------------- --------------- --------------- --------------- ------ ------------------ ----------
0xffff88001dc38000 init                 1               0               0               0      0x000000001dfae000 2018-10-28 07:45:11 UTC+0000
0xffff88001dc39800 kthreadd             2               0               0               0      ------------------ 2018-10-28 07:45:11 UTC+0000
0xffff88001dc3b000 ksoftirqd/0          3               2               0               0      ------------------ 2018-10-28 07:45:11 UTC+0000
0xffff88001dc3c800 kworker/0:0          4               2               0               0      ------------------ 2018-10-28 07:45:11 UTC+0000
0xffff88001dc3e000 kworker/0:0H         5               2               0               0      ------------------ 2018-10-28 07:45:11 UTC+0000
0xffff88001dcd1800 rcu_sched            7               2               0               0      ------------------ 2018-10-28 07:45:11 UTC+0000
0xffff88001dcd3000 rcuos/0              8               2               0               0      ------------------ 2018-10-28 07:45:11 UTC+0000
0xffff88001dcd4800 rcu_bh               9               2               0               0      ------------------ 2018-10-28 07:45:11 UTC+0000
0xffff88001dcd6000 rcuob/0              10              2               0               0      ------------------ 2018-10-28 07:45:11 UTC+0000
0xffff88001dd00000 migration/0          11              2               0               0      ------------------ 2018-10-28 07:45:11 UTC+0000
0xffff88001dd01800 watchdog/0           12              2               0               0      ------------------ 2018-10-28 07:45:11 UTC+0000
0xffff88001dd03000 khelper              13              2               0               0      ------------------ 2018-10-28 07:45:11 UTC+0000
0xffff88001dd04800 kdevtmpfs            14              2               0               0      ------------------ 2018-10-28 07:45:11 UTC+0000
0xffff88001dd06000 netns                15              2               0               0      ------------------ 2018-10-28 07:45:11 UTC+0000
0xffff88001dd68000 writeback            16              2               0               0      ------------------ 2018-10-28 07:45:11 UTC+0000
0xffff88001dd69800 kintegrityd          17              2               0               0      ------------------ 2018-10-28 07:45:11 UTC+0000
0xffff88001dd6b000 bioset               18              2               0               0      ------------------ 2018-10-28 07:45:11 UTC+0000
0xffff88001dd6c800 kworker/u3:0         19              2               0               0      ------------------ 2018-10-28 07:45:11 UTC+0000
0xffff88001dd6e000 kblockd              20              2               0               0      ------------------ 2018-10-28 07:45:11 UTC+0000
0xffff88001de10000 ata_sff              21              2               0               0      ------------------ 2018-10-28 07:45:11 UTC+0000
0xffff88001de11800 khubd                22              2               0               0      ------------------ 2018-10-28 07:45:11 UTC+0000
0xffff88001de13000 md                   23              2               0               0      ------------------ 2018-10-28 07:45:11 UTC+0000
0xffff88001de14800 devfreq_wq           24              2               0               0      ------------------ 2018-10-28 07:45:11 UTC+0000
0xffff88001de16000 kworker/0:1          25              2               0               0      ------------------ 2018-10-28 07:45:11 UTC+0000
0xffff88001c6a9800 khungtaskd           27              2               0               0      ------------------ 2018-10-28 07:45:11 UTC+0000
0xffff88001c6ab000 kswapd0              28              2               0               0      ------------------ 2018-10-28 07:45:11 UTC+0000
0xffff88001c6ac800 vmstat               29              2               0               0      ------------------ 2018-10-28 07:45:11 UTC+0000
0xffff88001c6ae000 ksmd                 30              2               0               0      ------------------ 2018-10-28 07:45:11 UTC+0000
0xffff88001c700000 fsnotify_mark        31              2               0               0      ------------------ 2018-10-28 07:45:11 UTC+0000
0xffff88001c701800 ecryptfs-kthrea      32              2               0               0      ------------------ 2018-10-28 07:45:11 UTC+0000
0xffff88001c703000 crypto               33              2               0               0      ------------------ 2018-10-28 07:45:11 UTC+0000
0xffff88001c74e000 kthrotld             45              2               0               0      ------------------ 2018-10-28 07:45:11 UTC+0000
0xffff88001f093000 deferwq              65              2               0               0      ------------------ 2018-10-28 07:45:11 UTC+0000
0xffff88001f094800 charger_manager      66              2               0               0      ------------------ 2018-10-28 07:45:11 UTC+0000
0xffff88001f090000 kpsmoused            108             2               0               0      ------------------ 2018-10-28 07:45:11 UTC+0000
0xffff88001f080000 scsi_eh_0            125             2               0               0      ------------------ 2018-10-28 07:45:11 UTC+0000
0xffff88001f43c800 jbd2/sda1-8          174             2               0               0      ------------------ 2018-10-28 07:45:13 UTC+0000
0xffff88001f43e000 ext4-rsv-conver      175             2               0               0      ------------------ 2018-10-28 07:45:13 UTC+0000
0xffff88001f091800 upstart-udev-br      377             1               0               0      0x000000001d54c000 2018-10-28 07:45:14 UTC+0000
0xffff88001f439800 systemd-udevd        382             1               0               0      0x000000001d6a2000 2018-10-28 07:45:14 UTC+0000
0xffff88001f081800 iprt                 410             2               0               0      ------------------ 2018-10-28 07:45:15 UTC+0000
0xffff88001d694800 kworker/u3:1         416             2               0               0      ------------------ 2018-10-28 07:45:15 UTC+0000
0xffff88001d3ae000 rpcbind              556             1               0               0      0x000000001d3d8000 2018-10-28 07:45:16 UTC+0000
0xffff88001d3ac800 dhclient             567             1               0               0      0x000000001d452000 2018-10-28 07:45:16 UTC+0000
0xffff88001d4ee000 rpc.statd            602             1               107             65534  0x000000001cebc000 2018-10-28 07:45:16 UTC+0000
0xffff88001d44e000 upstart-socket-      632             1               0               0      0x000000001d764000 2018-10-28 07:45:16 UTC+0000
0xffff88001cec8000 kauditd              815             2               0               0      ------------------ 2018-10-28 07:45:18 UTC+0000
0xffff88001d394800 rpciod               850             2               0               0      ------------------ 2018-10-28 07:45:18 UTC+0000
0xffff88001f45e000 nfsiod               858             2               0               0      ------------------ 2018-10-28 07:45:18 UTC+0000
0xffff88001f0e6000 dbus-daemon          888             1               102             106    0x000000001d76a000 2018-10-28 07:45:18 UTC+0000
0xffff88001c74b000 rpc.idmapd           910             1               0               0      0x000000001f484000 2018-10-28 07:45:18 UTC+0000
0xffff88001f0e3000 systemd-logind       933             1               0               0      0x000000001d3ec000 2018-10-28 07:45:18 UTC+0000
0xffff88001d396000 rsyslogd             952             1               101             104    0x000000001c618000 2018-10-28 07:45:19 UTC+0000
0xffff88001d4e9800 upstart-file-br      972             1               0               0      0x000000001f098000 2018-10-28 07:45:19 UTC+0000
0xffff88001f096000 getty                1055            1               0               0      0x000000001f4ee000 2018-10-28 07:45:19 UTC+0000
0xffff88001d4eb000 getty                1058            1               0               0      0x000000001d768000 2018-10-28 07:45:19 UTC+0000
0xffff88001d696000 getty                1062            1               0               0      0x000000001ce44000 2018-10-28 07:45:19 UTC+0000
0xffff88001d693000 getty                1063            1               0               0      0x000000001ce66000 2018-10-28 07:45:19 UTC+0000
0xffff88001d449800 getty                1065            1               0               0      0x000000001ce6e000 2018-10-28 07:45:19 UTC+0000
0xffff88001cfa9800 acpid                1109            1               0               0      0x000000001cf10000 2018-10-28 07:45:19 UTC+0000
0xffff88001cfa8000 cron                 1111            1               0               0      0x000000001cf04000 2018-10-28 07:45:19 UTC+0000
0xffff88001cf3e000 atd                  1112            1               0               0      0x0000000000078000 2018-10-28 07:45:19 UTC+0000
0xffff88001d4ec800 VBoxService          1161            1               0               0      0x000000001ce64000 2018-10-28 07:45:20 UTC+0000
0xffff88001d690000 sshd                 1246            1               0               0      0x000000001cf5e000 2018-10-28 07:45:20 UTC+0000
0xffff88001f520000 puppet               1288            1               0               0      0x000000001d5e2000 2018-10-28 07:45:21 UTC+0000
0xffff88001f526000 ruby                 1318            1               0               0      0x000000001d50e000 2018-10-28 07:45:22 UTC+0000
0xffff88001c749800 getty                1345            1               0               0      0x0000000000052000 2018-10-28 07:45:22 UTC+0000
0xffff88001d448000 kworker/u2:1         12200           2               0               0      ------------------ 2018-10-28 08:53:16 UTC+0000
0xffff88001f45b000 kworker/u2:2         28347           2               0               0      ------------------ 2018-10-28 09:03:02 UTC+0000
0xffff88001f086000 sshd                 10964           1246            0               0      0x000000001f5de000 2018-10-28 09:24:03 UTC+0000
0xffff88001d4e8000 sshd                 11034           10964           1000            1000   0x000000001d458000 2018-10-28 09:24:03 UTC+0000
0xffff88001d44b000 bash                 11035           11034           1000            1000   0x000000001f574000 2018-10-28 09:24:03 UTC+0000
0xffff88001d53c800 roscore              11410           11035           1000            1000   0x000000001f576000 2018-10-28 09:46:14 UTC+0000
0xffff88001dcd0000 rosmaster            11422           11410           1000            1000   0x00000000145b0000 2018-10-28 09:46:14 UTC+0000
0xffff88001f459800 rosout               11435           11410           1000            1000   0x000000001d620000 2018-10-28 09:46:14 UTC+0000
0xffff88001c6a8000 talker               11452           11035           1000            1000   0x000000001f3b8000 2018-10-28 09:46:19 UTC+0000
0xffff88001cf38000 listener             11586           11035           1000            1000   0x000000001d25c000 2018-10-28 09:46:23 UTC+0000
0xffff88001c734800 sudo                 11610           11035           0               1000   0x000000001f3d6000 2018-10-28 09:46:30 UTC+0000
0xffff88001c736000 insmod               11611           11610           0               0      0x000000001f558000 2018-10-28 09:46:30 UTC+0000
0xffff88001d390000 systemd-udevd        11612           382             0               0      0x000000001d7e6000 2018-10-28 09:46:30 UTC+0000
```

Seems to be working. Let's compare the two memory dumps:
```bash
vagrant@vagrant-ubuntu-trusty-64:~$ vol.py --profile LinuxUbuntu14045x64 -f robot linux_pslist > robot.txt
robot_hacked.lime  robot.lime         robot.txt
vagrant@vagrant-ubuntu-trusty-64:~$ vol.py --profile LinuxUbuntu14045x64 -f robot_hacked.lime linux_pslist > robot_hacked.txt
Volatility Foundation Volatility Framework 2.6
vagrant@vagrant-ubuntu-trusty-64:~$ diff robot.txt robot_hacked.txt
80,82c80,82
< 0xffff88001c734800 sudo                 11610           11035           0               1000   0x000000001f3d6000 2018-10-28 09:46:30 UTC+0000
< 0xffff88001c736000 insmod               11611           11610           0               0      0x000000001f558000 2018-10-28 09:46:30 UTC+0000
< 0xffff88001d390000 systemd-udevd        11612           382             0               0      0x000000001d7e6000 2018-10-28 09:46:30 UTC+0000
---
> 0xffff88001f438000 sudo                 11629           11035           0               1000   0x0000000000d10000 2018-10-28 09:46:51 UTC+0000
> 0xffff88001f43b000 insmod               11630           11629           0               0      0x000000001f240000 2018-10-28 09:46:51 UTC+0000
> 0xffff88001d390000 systemd-udevd        11631           382             0               0      0x000000001dfbc000 2018-10-28 09:46:51 UTC+0000
```

No changes in the relevant ROS-related processes. As expected. Let's try some other plugins and to do so, let's make use of the following script named as `voltest.sh`:
```bash
#!/usr/bin/env bash

vol.py --profile LinuxUbuntu14045x64 -f robot.lime $1 > /tmp/robot.txt

vol.py --profile LinuxUbuntu14045x64 -f robot_hacked.lime $1 > /tmp/robot_hacked.txt

diff /tmp/robot.txt /tmp/robot_hacked.txt
```

Let's for example use the `linux_lsof` plugin which walks a process file descriptor table and prints the file descriptor number and path for each entry:

```bash
vagrant@vagrant-ubuntu-trusty-64:~$ ./voltest.sh "linux_lsof -p 11452"
Volatility Foundation Volatility Framework 2.6
Volatility Foundation Volatility Framework 2.6
14d13
< 0xffff88001c6a8000 talker                            11452       12 socket:[106140]
```
This means that `robot.lime`'s talker has an additional file descriptor. In particular FD number `12` with inode number `106140`. Let's analyze the processes' network connections using the `linux_netstat` plugin:
```bash
vagrant@vagrant-ubuntu-trusty-64:~$ ./voltest.sh "linux_netstat -p 11452"
Volatility Foundation Volatility Framework 2.6
Volatility Foundation Volatility Framework 2.6
5,6c5
< TCP      10.0.2.15       :47785 10.0.2.15       :54442 ESTABLISHED                talker/11452
< TCP      10.0.2.15       :47785 10.0.2.15       :54457 ESTABLISHED                talker/11452
---
> TCP      10.0.2.15       :47785 10.0.2.15       :54442 CLOSE_WAIT                 talker/11452
```


#### Summary of forensics
Summary of forensics analysis on a ROS system under an `Unauthenticated unregistration attack`.

| Memory file |  `linux_pslist` | `linux_proc_maps`| `linux_psaux` | `linux_lsof` |
|-------------|-----------------| -----------------| ------|----|
| *The memory acquired and being analyzed.*  | *A volatility plugin to enumerate processes* | *Enumerating process mappings, useful to see injections.* | *Analyzing command line arguments.* | *walks a process file descriptor table and prints the file descriptor number and path for each entry* |
| robot.lime  | - | - | - | `11452       12 socket:[106140]` |
| robot_hacked.lime | -  | - | - | Does not include the 12th fd. |

### Bibliography
- [1] Mendia, G. O., Juan, L. U. S., Bascaran, X. P., Calvo, A. B., Cordero, A. H., Ugarte, I. Z., ... & Vilches, V. M. (2018). Robotics CTF (RCTF), a playground for robot hacking. arXiv preprint arXiv:1810.02690.
- [2] Scenarios of the Robotics CTF (RCTF), a playground to challenge robot security. Retrieved from https://github.com/aliasrobotics/RCTF
- [3] Dieber, B., Breiling, B., Taurer, S., Kacianka, S., Rass, S., & Schartner, P. (2017). Security for the Robot Operating System. Robotics and Autonomous Systems, 98, 192-203.
- [4] SROS2 Tutorial, IROS 2018. Retrieved from https://ruffsl.github.io/IROS2018_SROS2_Tutorial/.
- [5] roschaos. Retrieved from https://github.com/ruffsl/roschaos.
- [6] ROSPenTo. Retrieved from https://github.com/jr-robotics/ROSPenTo.
- [7] volatility. Retrieved from https://github.com/volatilityfoundation/volatility.
