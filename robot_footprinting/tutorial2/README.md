# Footprinting Secure ROS systems

Following from the previous tutorial, in this one we'll analyze secure ROS setups using the SROS package.

----

**Note**: as in previous tutorials, there's a docker container that facilitates reproducing the work of this tutorial. The container can be built with:
```bash
docker build -t basic_cybersecurity_footprinting2:latest .
```
and runned with:
```bash
docker run --privileged -it basic_cybersecurity_footprinting2:latest
```

----

### Understanding SROS
According to [5], SROS has three levels of concepts: the Transport Security level, the Access Control level, and the Process Profile level. These levels and concepts are summarized below and later sections go into each of these in greater detail.

[4] provides some additional intuition about each one of these levels.

### Footprinting SROS systems

```bash
# Launching Keyserver
sroskeyserver &
# Launching the secure ROS Master
sroscore &
# Launch aztarna with the right options
aztarna -t SROS -a 127.0.0.1
Connecting to 127.0.0.1:11311
[+] SROS host found!!!

```


### Resources
- [1] aztarna. Retrieved from https://github.com/aliasrobotics/aztarna.
- [2] Docker of ROS. Retrieved from https://hub.docker.com/_/ros/.
- [3] SROS documentation. Retrieved from  http://wiki.ros.org/SROS.
- [4] SROS tutorials. Retrieved from http://wiki.ros.org/SROS/Tutorials
- [4] SROS concepts. Retrieved from http://wiki.ros.org/SROS/Concepts
