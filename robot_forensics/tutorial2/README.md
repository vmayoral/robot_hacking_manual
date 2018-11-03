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

**Unfinished**


### Resources
- [1] Mendia, G. O., Juan, L. U. S., Bascaran, X. P., Calvo, A. B., Cordero, A. H., Ugarte, I. Z., ... & Vilches, V. M. (2018). Robotics CTF (RCTF), a playground for robot hacking. arXiv preprint arXiv:1810.02690.
- [2] Scenarios of the Robotics CTF (RCTF), a playground to challenge robot security. Retrieved from https://github.com/aliasrobotics/RCTF
- [3] Dieber, B., Breiling, B., Taurer, S., Kacianka, S., Rass, S., & Schartner, P. (2017). Security for the Robot Operating System. Robotics and Autonomous Systems, 98, 192-203.
- [4] SROS2 Tutorial, IROS 2018. Retrieved from https://ruffsl.github.io/IROS2018_SROS2_Tutorial/.
- [5] roschaos. Retrieved from https://github.com/ruffsl/roschaos.
- [6] ROSPenTo. Retrieved from https://github.com/jr-robotics/ROSPenTo.
- [7] volatility. Retrieved from https://github.com/volatilityfoundation/volatility.
