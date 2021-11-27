\newpage

## TurtleBot 3 (TB3)

Building on top of the previous [ROS 2 case study](../2_ros2), this piece aims to demonstrate how ROS 2 vulnerabilities can be translated directly into complete robots and how attackers could exploit them.

### Dockerized environment
Like in previous cases, when possible, we'll facilitate a Docker-based environment so that you can try things out yourself! Here's this one:


```bash
# Build
docker build -t hacking_tb3:foxy --build-arg DISTRO=foxy .

# Run headless
docker run -it hacking_tb3:foxy -c "/bin/bash"

# Run headless with byobu config using both Fast-DDS and RTI's Connext
docker run -it hacking_tb3:foxy -c "/usr/bin/byobu -f /opt/configs/pocs_headless_connext.conf attach"

# Run headless sharing host's network
docker run -it --privileged --net=host hacking_tb3:foxy -c "/usr/bin/byobu -f /opt/configs/pocs_headless.conf attach"

# Run headless sharing host's network, and with some nodes launched using OpenDDS
docker run -it --privileged --net=host hacking_tb3:foxy -c "/usr/bin/byobu -f /opt/configs/pocs_headless_opendds.conf attach"


# Run, using X11
xhost + # (careful with this)
docker run -it --privileged --net=host -v /tmp/.X11-unix:/tmp/.X11-unix -e DISPLAY=$DISPLAY -v $HOME/.Xauthority:/home/xilinx/.Xauthority hacking_tb3:foxy -c "/usr/bin/byobu -f /opt/configs/pocs.conf attach"

```

### Searching for TB3s around (reconnaissance)

```bash
python3 exploits/footprint.py 2> /dev/null
```

It'll find the CycloneDDS node `teleop_keyboard`, which respond to the crafted package and identify the corresponding endpoint.


### Messing up with TB3's traffic

![](../../images/2021/tb3_reflection.gif)

```bash
python3 exploits/reflection.py 2> /dev/null
```


### Crashing TB3s running DDS's "best in the world"

![](../../images/2021/rti_connext.png)


<!-- Elaborate on this -->

Vulnerability Title

Segmentation Fault while receiving malformed packet in RTI Connext DDS
High-level overview of the vulnerability and the possible effect of using it

Serializer in RTI would segmentation fault while receiving a malformed form of packet. This would cause runtimes to exit immediately and causing an denial of service.
Detailed description of the vulnerability

RTICdrStream_skipStringAndGetLength does not check for any type of malformed packet, thus while using results from RTICdrStream_align, it will commit a segmentation fault.
How did you find this vulnerability?

afl-unicorn
Can you identify exploitability?

DoS
Can you identify root cause?

RTICdrStream_skipStringAndGetLength does not check for any type of malformed packet, thus while using results from RTICdrStream_align, it will commit a segmentation fault. We compiled test programs in static mode, gcc5.4, Linux 3, C. Both publisher and subscriber is affected.
