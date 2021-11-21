\newpage

## TurtleBot 3 (TB3)

Building on top of the previous [ROS 2 case study](../2_ros2), this piece aims to demonstrate how ROS 2 vulnerabilities can be translated directly into complete robots and how attackers could exploit them.


### Dockerized environment
Like in previous cases, when possible, we'll facilitate a Docker-based environment so that you can try things out yourself! Here's this one:


```bash
# Build
docker build -t hacking_tb3:foxy --build-arg DISTRO=foxy .

# Run headless
docker run -it hacking_tb3:foxy /bin/bash
# (inside of the container)
byobu -f configs/pocs_headless.conf attach

# Run, using X11
xhost + # (careful with this)
docker run -it -v /tmp/.X11-unix:/tmp/.X11-unix -e DISPLAY=$DISPLAY -v $HOME/.Xauthority:/home/xilinx/.Xauthority hacking_tb3:foxy
# (inside of the container)
byobu -f configs/poc.conf attach
```

### Searching for TB3s around (reconnaissance)

```bash
## From another terminal
python3 exploits/footprint.py 2> /dev/null
```
