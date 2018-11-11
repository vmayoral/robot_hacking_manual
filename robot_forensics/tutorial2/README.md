### Locating ROS logs in memory

This tutorial will explore forensics tools to obtain the ROS Master logs from memory.

The tutorial will build on top of the [tutorial1 resources](../tutorial1).

#### Listing files and directories
Let's start enumerating the files and directories found within the different files sytems in memory:
```bash
vagrant@vagrant-ubuntu-trusty-64:~$ vol.py --plugins=/vagrant/ros_volatility --profile LinuxUbuntu14045x64 -f robot_hacked.lime linux_enumerate_files
Volatility Foundation Volatility Framework 2.6
     Inode Address Inode Number              Path
------------------ ------------------------- ----
0xffff88001d9a8488                         2 /
0xffff88001467f7c0                   2359297 /vagrant
0xffff88001c8433e8                      8196 /home
0xffff8800146377c0                    131077 /home/vagrant
0xffff88001c83b7c0                    141385 /home/vagrant/robot_hacked.lime
               0x0 ------------------------- /home/vagrant/libnss_files.so.2
               0x0 ------------------------- /home/vagrant/liblz4.so.1
               0x0 ------------------------- /home/vagrant/libbz2.so.1.0
0xffff88001da117c0                     64195 /swapfile
0xffff88001d9f60b0                      8208 /tmp
0xffff8800001aec38                     62234 /tmp/listener.txt
0xffff88001d9a9b98                     57345 /var
...
```

This will show every file found in memory however none of these files corresponded to the log files which by default are stored at `/home/vagrant/.ros/log/`. In particular, the file we're interested in is `/home/vagrant/.ros/log/*/.master.log` since that's the file that registers the changes in the ROS network. Doesn't seem like we'll be able to get much in this direction. Let's try a different one.

#### Reviewing the information about the ROS Master
Let's start by dumping the processes in memory:
```bash
vagrant@vagrant-ubuntu-trusty-64:~$ vol.py --plugins=/vagrant/ros_volatility --profile LinuxUbuntu14045x64 -f robot_hacked.lime linux_pslist
Volatility Foundation Volatility Framework 2.6
Offset             Name                 Pid             PPid            Uid             Gid    DTB                Start Time
------------------ -------------------- --------------- --------------- --------------- ------ ------------------ ----------
0xffff88001dc38000 init                 1               0               0               0      0x000000001dfb4000 2018-11-01 15:51:57 UTC+0000
0xffff88001dc39800 kthreadd             2               0               0               0      ------------------ 2018-11-01 15:51:57 UTC+0000
...
0xffff88001f420000 sshd                 1512            1013            0               0      0x0000000000072000 2018-11-01 15:54:52 UTC+0000
0xffff88001c704800 bash                 1583            1582            1000            1000   0x000000001f4f2000 2018-11-01 15:54:53 UTC+0000
0xffff88001dcd0000 roscore              2360            1583            1000            1000   0x000000001df26000 2018-11-01 17:58:17 UTC+0000
0xffff88001f06e000 rosmaster            2372            2360            1000            1000   0x000000001dfec000 2018-11-01 17:58:17 UTC+0000
0xffff88001d65b000 rosout               2385            2360            1000            1000   0x000000001f4ee000 2018-11-01 17:58:17 UTC+0000
0xffff88001c68b000 talker               2402            1583            1000            1000   0x000000001cfd8000 2018-11-01 17:58:27 UTC+0000
0xffff88001f4d4800 listener             2420            1583            1000            1000   0x000000001d366000 2018-11-01 17:58:31 UTC+0000
0xffff88001d330000 sudo                 2481            1583            0               1000   0x000000001f570000 2018-11-01 18:09:49 UTC+0000
0xffff88001d334800 insmod               2482            2481            0               0      0x00000000001da000 2018-11-01 18:09:49 UTC+0000
0xffff88001d336000 systemd-udevd        2483            394             0               0      0x000000000e1de000 2018-11-01 18:09:49 UTC+0000
```
Let's stick with the following three processes:
- roscore: `2360`
- rosmaster: `2372`
- rosout: `2385`

To figure out which process is writing in `/home/vagrant/.ros/log/*/.master.log`, we check the open file descriptor each process has:

```
vagrant@vagrant-ubuntu-trusty-64:~$ vol.py --plugins=/vagrant/ros_volatility --profile LinuxUbuntu14045x64 -f robot_hacked.lime linux_lsof -p 2360
Volatility Foundation Volatility Framework 2.6
Offset             Name                           Pid      FD       Path
------------------ ------------------------------ -------- -------- ----
0xffff88001dcd0000 roscore                            2360        0 /dev/pts/0
0xffff88001dcd0000 roscore                            2360        1 /dev/pts/0
0xffff88001dcd0000 roscore                            2360        2 /dev/pts/0
0xffff88001dcd0000 roscore                            2360        3 /dev/urandom
0xffff88001dcd0000 roscore                            2360        4 /home/vagrant/.ros/log/b66d4092-ddff-11e8-8938-080027d0c4ba/roslaunch-vagrant-ubuntu-trusty-64-2360.log
0xffff88001dcd0000 roscore                            2360        5 socket:[14544]
vagrant@vagrant-ubuntu-trusty-64:~$ vol.py --plugins=/vagrant/ros_volatility --profile LinuxUbuntu14045x64 -f robot_hacked.lime linux_lsof -p 2372
Volatility Foundation Volatility Framework 2.6
Offset             Name                           Pid      FD       Path
------------------ ------------------------------ -------- -------- ----
0xffff88001f06e000 rosmaster                          2372        0 /dev/pts/0
0xffff88001f06e000 rosmaster                          2372        1 /dev/pts/0
0xffff88001f06e000 rosmaster                          2372        2 /dev/pts/0
0xffff88001f06e000 rosmaster                          2372        3 /home/vagrant/.ros/log/b66d4092-ddff-11e8-8938-080027d0c4ba/master.log
0xffff88001f06e000 rosmaster                          2372        4 socket:[14563]
0xffff88001f06e000 rosmaster                          2372        5 socket:[14693]
0xffff88001f06e000 rosmaster                          2372        6 socket:[15025]
vagrant@vagrant-ubuntu-trusty-64:~$ vol.py --plugins=/vagrant/ros_volatility --profile LinuxUbuntu14045x64 -f robot_hacked.lime linux_lsof -p 2385
Volatility Foundation Volatility Framework 2.6
Offset             Name                           Pid      FD       Path
------------------ ------------------------------ -------- -------- ----
0xffff88001d65b000 rosout                             2385        0 /dev/pts/0
0xffff88001d65b000 rosout                             2385        1 /home/vagrant/.ros/log/b66d4092-ddff-11e8-8938-080027d0c4ba/rosout-1-stdout.log
0xffff88001d65b000 rosout                             2385        2 /dev/pts/0
0xffff88001d65b000 rosout                             2385        3 socket:[14649]
0xffff88001d65b000 rosout                             2385        4 anon_inode:[5259]
0xffff88001d65b000 rosout                             2385        5 pipe:[14605]
0xffff88001d65b000 rosout                             2385        6 pipe:[14605]
0xffff88001d65b000 rosout                             2385        7 socket:[14608]
0xffff88001d65b000 rosout                             2385        8 socket:[14611]
0xffff88001d65b000 rosout                             2385        9 socket:[14612]
0xffff88001d65b000 rosout                             2385       10 /home/vagrant/.ros/log/b66d4092-ddff-11e8-8938-080027d0c4ba/rosout.log
0xffff88001d65b000 rosout                             2385       11 socket:[14694]
0xffff88001d65b000 rosout                             2385       14 socket:[14760]
```

The process we're interested in is the `rosmaster` with PID `2372`. In particular, we're interested in FD 3 of this process.


There's a useful list of volatility commands at https://github.com/volatilityfoundation/volatility/wiki/Linux-Command-Reference.

From it, let's try to find the Inode of the file we're trying to look for:

```bash
vagrant@vagrant-ubuntu-trusty-64:~$ vol.py --plugins=/vagrant/ros_volatility --profile LinuxUbuntu14045x64 -f robot_hacked.lime linux_find_file -F "/home/vagrant/.ros/log/b66d4092-ddff-11e8-8938-080027d0c4ba/master.log"
Volatility Foundation Volatility Framework 2.6
```

No result. This path's not going to lead to any interesting result either.
Let's dig a bit more in the prints the memory of the process then. The following command will provide a list of allocated and memory-resident (non-swapped) pages in the process:

```bash
vagrant@vagrant-ubuntu-trusty-64:~$ vol.py --plugins=/home/vagrant/volatility-plugins/linux --profile LinuxUbuntu14045x64 -f robot_hacked.lime linux_memmap -p 2372
Volatility Foundation Volatility Framework 2.6
Task             Pid      Virtual            Physical                         Size
---------------- -------- ------------------ ------------------ ------------------
rosmaster            2372 0x0000000000416000 0x000000001c268000             0x1000
rosmaster            2372 0x0000000000417000 0x000000001c3ed000             0x1000
rosmaster            2372 0x0000000000418000 0x000000001c34b000             0x1000
rosmaster            2372 0x0000000000470000 0x000000001bd4e000             0x1000
rosmaster            2372 0x0000000000480000 0x000000001bfcf000             0x1000
...
```

There seems to be quite a few pages:
```bash
vagrant@vagrant-ubuntu-trusty-64:~$ vol.py --plugins=/home/vagrant/volatility-plugins/linux --profile LinuxUbuntu14045x64 -f robot_hacked.lime linux_memmap -p 2372| wc -l
Volatility Foundation Volatility Framework 2.6
80212
```

Instead of that, let's gather the process memory maps:
```bash
vagrant@vagrant-ubuntu-trusty-64:~$ vol.py --plugins=/home/vagrant/volatility-plugins/linux --profile LinuxUbuntu14045x64 -f robot_hacked.lime linux_proc_maps -p 2372
Volatility Foundation Volatility Framework 2.6
Offset             Pid      Name                 Start              End                Flags               Pgoff Major  Minor  Inode      File Path
------------------ -------- -------------------- ------------------ ------------------ ------ ------------------ ------ ------ ---------- ---------
0xffff88001f06e000     2372 rosmaster            0x0000000000400000 0x00000000006bb000 r-x                   0x0      8      1      47941 /usr/bin/python2.7
0xffff88001f06e000     2372 rosmaster            0x00000000008ba000 0x00000000008bb000 r--              0x2ba000      8      1      47941 /usr/bin/python2.7
0xffff88001f06e000     2372 rosmaster            0x00000000008bb000 0x0000000000930000 rw-              0x2bb000      8      1      47941 /usr/bin/python2.7
0xffff88001f06e000     2372 rosmaster            0x0000000000930000 0x0000000000942000 rw-                   0x0      0      0          0
0xffff88001f06e000     2372 rosmaster            0x00000000011d7000 0x000000000177a000 rw-                   0x0      0      0          0 [heap]
0xffff88001f06e000     2372 rosmaster            0x00007f4f58000000 0x00007f4f58021000 rw-                   0x0      0      0          0
0xffff88001f06e000     2372 rosmaster            0x00007f4f58021000 0x00007f4f5c000000 ---                   0x0      0      0          0
0xffff88001f06e000     2372 rosmaster            0x00007f4f60000000 0x00007f4f60021000 rw-                   0x0      0      0          0
...
```

Unfortunately, there's nothing about the file we're trying to get :(.

Let's try reviewing the information about the `rosmaster` process using the `linux_volshell` volatility plugin:
```
vagrant@vagrant-ubuntu-trusty-64:~$ vol.py --plugins=/vagrant/ros_volatility --profile LinuxUbuntu14045x64 -f robot_hacked.lime linux_volshell
Volatility Foundation Volatility Framework 2.6
Current context: process init, pid=1 DTB=0x1dfb4000
Welcome to volshell! Current memory image is:
file:///home/vagrant/robot_hacked.lime
To get help, type 'hh()'
>>> ps()
Name             PID    Offset
init             1      0xffff88001dc38000
kthreadd         2      0xffff88001dc39800
ksoftirqd/0      3      0xffff88001dc3b000
kworker/0:0      4      0xffff88001dc3c800
kworker/0:0H     5      0xffff88001dc3e000
rcu_sched        7      0xffff88001dcd1800
rcuos/0          8      0xffff88001dcd3000
rcu_bh           9      0xffff88001dcd4800
rcuob/0          10     0xffff88001dcd6000
migration/0      11     0xffff88001dd00000
watchdog/0       12     0xffff88001dd01800
khelper          13     0xffff88001dd03000
kdevtmpfs        14     0xffff88001dd04800
netns            15     0xffff88001dd06000
writeback        16     0xffff88001dd68000
kintegrityd      17     0xffff88001dd69800
bioset           18     0xffff88001dd6b000
kworker/u3:0     19     0xffff88001dd6c800
kblockd          20     0xffff88001dd6e000
ata_sff          21     0xffff88001de10000
khubd            22     0xffff88001de11800
md               23     0xffff88001de13000
devfreq_wq       24     0xffff88001de14800
kworker/0:1      25     0xffff88001de16000
khungtaskd       27     0xffff88001c6a9800
kswapd0          28     0xffff88001c6ab000
vmstat           29     0xffff88001c6ac800
ksmd             30     0xffff88001c6ae000
fsnotify_mark    31     0xffff88001c700000
ecryptfs-kthrea  32     0xffff88001c701800
crypto           33     0xffff88001c703000
kthrotld         45     0xffff88001c74e000
deferwq          65     0xffff88001f083000
charger_manager  66     0xffff88001f084800
scsi_eh_0        108    0xffff88001c734800
kpsmoused        109    0xffff88001c730000
kworker/u2:2     111    0xffff88001f068000
kworker/u2:3     127    0xffff88001f424800
jbd2/sda1-8      173    0xffff88001c733000
ext4-rsv-conver  174    0xffff88001c6a8000
upstart-udev-br  386    0xffff88001dfa9800
systemd-udevd    394    0xffff88001c749800
iprt             436    0xffff88001c706000
dhclient         514    0xffff88001f0c9800
kworker/u3:1     619    0xffff88001f4d3000
rpcbind          625    0xffff88001d429800
rpc.statd        677    0xffff88001c629800
upstart-socket-  680    0xffff88001c62c800
rpciod           752    0xffff88001dfac800
dbus-daemon      762    0xffff88001f0c8000
nfsiod           766    0xffff88001f06b000
rpc.idmapd       810    0xffff88001c62e000
systemd-logind   836    0xffff88001cf36000
rsyslogd         865    0xffff88001c628000
upstart-file-br  887    0xffff88001c688000
getty            961    0xffff88001d65c800
getty            964    0xffff88001f4d1800
getty            968    0xffff88001cf34800
getty            969    0xffff88001cf30000
getty            971    0xffff88001c748000
sshd             1013   0xffff88001cfac800
atd              1015   0xffff88001cfae000
cron             1016   0xffff88001cfa9800
acpid            1017   0xffff88001cfa8000
VBoxService      1059   0xffff88001f0cc800
puppet           1106   0xffff88001f0cb000
ruby             1136   0xffff88001cff4800
getty            1163   0xffff88001d65e000
kauditd          1185   0xffff88001cff3000
sshd             1512   0xffff88001f420000
sshd             1582   0xffff88001f06c800
bash             1583   0xffff88001c704800
roscore          2360   0xffff88001dcd0000
rosmaster        2372   0xffff88001f06e000
rosout           2385   0xffff88001d65b000
talker           2402   0xffff88001c68b000
listener         2420   0xffff88001f4d4800
sudo             2481   0xffff88001d330000
insmod           2482   0xffff88001d334800
systemd-udevd    2483   0xffff88001d336000
```

let's change the context to the process we're interested in:
```
>>> cc(0xffff88001f06e000)
Current context: process rosmaster, pid=2372 DTB=0x1dfec000
```
(or also `cc(pid=2372)`)


**No clear result has been achieved from the available memory capture**.

### Resources
- [1] Mendia, G. O., Juan, L. U. S., Bascaran, X. P., Calvo, A. B., Cordero, A. H., Ugarte, I. Z., ... & Vilches, V. M. (2018). Robotics CTF (RCTF), a playground for robot hacking. arXiv preprint arXiv:1810.02690.
- [2] Scenarios of the Robotics CTF (RCTF), a playground to challenge robot security. Retrieved from https://github.com/aliasrobotics/RCTF
- [3] Dieber, B., Breiling, B., Taurer, S., Kacianka, S., Rass, S., & Schartner, P. (2017). Security for the Robot Operating System. Robotics and Autonomous Systems, 98, 192-203.
- [4] SROS2 Tutorial, IROS 2018. Retrieved from https://ruffsl.github.io/IROS2018_SROS2_Tutorial/.
- [5] roschaos. Retrieved from https://github.com/ruffsl/roschaos.
- [6] ROSPenTo. Retrieved from https://github.com/jr-robotics/ROSPenTo.
- [7] volatility. Retrieved from https://github.com/volatilityfoundation/volatility.
