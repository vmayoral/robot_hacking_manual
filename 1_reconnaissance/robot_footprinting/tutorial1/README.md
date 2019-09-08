# Footprinting ROS systems

Footprinting, (also known as *reconnaissance*) is the technique used for gathering information about digital systems and the entities they belong to. To get this information, a security analyst might use various tools and technologies. This information is very useful when performing a series attacks over an specific system.

ROS is the de facto standard for robot application development. This tutorial will show how to localize ROS systems and obtain additional information about them using the `aztarna` security tool. `aztarna` means "footprint" in *basque*.


----

**Note**: as in previous tutorials, there's a docker container that facilitates reproducing the work of this tutorial. The container can be built with:
```bash
docker build -t basic_cybersecurity_footprinting1:latest .
```
and runned with:
```bash
docker run --privileged -it basic_cybersecurity_footprinting1:latest
```

----

### ROS footprinting basics

The first thing we do to test the capabilities of `aztarna` is to get a container with the right dependencies and the tool installed:
~~~smallcontent
```bash
# from this directory:
docker build -t basic_cybersecurity_footprinting1:latest .
...
```
~~~

Let's launch an instance of ROS in the default port and see how `aztarna` can detect it:

~~~smallcontent
```bash
docker run --privileged -it basic_cybersecurity_footprinting1:latest
root@3c22d4bbf4e1:/# roscore -p 11311 &
root@3c22d4bbf4e1:/# roscore -p 11317 &
root@3c22d4bbf4e1:/# aztarna -t ROS -p 11311 -a 127.0.0.1
[+] ROS Host found at 127.0.0.1:11311


root@3c22d4bbf4e1:/# aztarna -t ROS -p 11311-11320 -a 127.0.0.1
root@432b0c5f61cc:~/aztarna# aztarna -t ROS -p 11311-11320 -a 127.0.0.1
[-] Error connecting to host Address: 127.0.0.1: Cannot connect to host 127.0.0.1:11315 ssl:None [Connection refused]
	Not a ROS host
[-] Error connecting to host Address: 127.0.0.1: Cannot connect to host 127.0.0.1:11312 ssl:None [Connection refused]
	Not a ROS host
[-] Error connecting to host Address: 127.0.0.1: Cannot connect to host 127.0.0.1:11316 ssl:None [Connection refused]
	Not a ROS host
[-] Error connecting to host Address: 127.0.0.1: Cannot connect to host 127.0.0.1:11313 ssl:None [Connection refused]
	Not a ROS host
[-] Error connecting to host Address: 127.0.0.1: Cannot connect to host 127.0.0.1:11314 ssl:None [Connection refused]
	Not a ROS host
[-] Error connecting to host Address: 127.0.0.1: Cannot connect to host 127.0.0.1:11318 ssl:None [Connection refused]
	Not a ROS host
[-] Error connecting to host Address: 127.0.0.1: Cannot connect to host 127.0.0.1:11319 ssl:None [Connection refused]
	Not a ROS host
[+] ROS Host found at 127.0.0.1:11317
[+] ROS Host found at 127.0.0.1:11311

```
~~~

Launches and scans reasonably fast:

~~~smallcontent
```bash
root@3c22d4bbf4e1:/# time aztarna -t ROS -p 11311-11320 -a 127.0.0.1
...
real	0m0.687s
user	0m0.620s
sys	0m0.040s
```
~~~

More information about a particular ROS Host can be obtained with the `-e` flag:

~~~smallcontent
```bash
root@aa6b6d7f9bd3:/# aztarna -t ROS -p 11311 -a 127.0.0.1 -e
[+] ROS Host found at 127.0.0.1:11311

Node: /rosout XMLRPCUri: http://aa6b6d7f9bd3:39719

	 Published topics:
		 * /rosout_agg(Type: rosgraph_msgs/Log)

	 Subscribed topics:
		 * /rosout(Type: rosgraph_msgs/Log)

	 Services:
		 * /rosout/set_logger_level
		 * /rosout/get_loggers

	 CommunicationROS 0:
		 - Publishers:
		 - Topic: /rosout(Type: rosgraph_msgs/Log)
		 - Subscribers:
			/rosout XMLRPCUri: http://aa6b6d7f9bd3:39719

	 CommunicationROS 1:
		 - Publishers:
			/rosout XMLRPCUri: http://aa6b6d7f9bd3:39719
		 - Topic: /rosout_agg(Type: rosgraph_msgs/Log)
		 - Subscribers:
```
~~~

### Checking for all ROS instances in a machine
A simple way to check for ROS within a particular machine is to chain the `aztarna` tool with other common bash utilities:

~~~smallcontent
```bash
root@bc6af321d62e:/# nmap -p 1-65535 127.0.0.1 | grep open | awk '{print $1}' | sed "s*/tcp**" | sed "s/^/aztarna -t ROS -p /" | sed "s/$/ -a 127.0.0.1/" | bash
[+] ROS Host found at 127.0.0.1:11311



[+] ROS Host found at 127.0.0.1:11317



[-] Error connecting to host 127.0.0.1:38069 -> Unknown error
	Not a ROS host
[-] Error connecting to host 127.0.0.1:38793 -> Unknown error
	Not a ROS host
[-] Error connecting to host 127.0.0.1:45665 -> <type 'exceptions.Exception'>:method "getSystemState" is not supported
	Not a ROS host
[-] Error connecting to host 127.0.0.1:46499 -> <type 'exceptions.Exception'>:method "getSystemState" is not supported
	Not a ROS host
[ERROR] [1543085503.685199009]: a header of over a gigabyte was predicted in tcpros. that seems highly unlikely, so I'll assume protocol synchronization is lost.
[-] Error connecting to host 127.0.0.1:55905 -> None
	Not a ROS host
[ERROR] [1543085504.415197656]: a header of over a gigabyte was predicted in tcpros. that seems highly unlikely, so I'll assume protocol synchronization is lost.
[-] Error connecting to host 127.0.0.1:59939 -> None
	Not a ROS host

```
~~~

### Resources
- [1] aztarna. Retrieved from https://github.com/aliasrobotics/aztarna.
- [2] Docker of ROS. Retrieved from https://hub.docker.com/_/ros/.
