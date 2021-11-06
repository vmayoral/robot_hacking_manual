# tb3nav2_demo

TurtleBot 3 `navigation2` demonstration.

## Build from source and run

```bash
# Build
docker build -t tb3nav2_demo .

# Run, using X11
xhost + # (careful with this)
docker run -it -v /tmp/.X11-unix:/tmp/.X11-unix -e DISPLAY=$DISPLAY -v $HOME/.Xauthority:/home/xilinx/.Xauthority tb3nav2_demo:latest

# Run setup (inside container)
byobu -f configs/poc.conf attach
```

## Use pre-built containers

### `galactic`
```bash
docker pull registry.gitlab.com/xilinxrobotics/tb3nav2_demo:galactic
xhost + # (careful with this)
docker run -it -v /tmp/.X11-unix:/tmp/.X11-unix -e DISPLAY=$DISPLAY -v $HOME/.Xauthority:/home/xilinx/.Xauthority registry.gitlab.com/xilinxrobotics/tb3nav2_demo:galactic

# Run setup (inside container)
byobu -f configs/poc.conf attach
```

### `foxy`
```bash
docker pull registry.gitlab.com/xilinxrobotics/tb3nav2_demo:foxy
xhost + # (careful with this)
docker run -it -v /tmp/.X11-unix:/tmp/.X11-unix -e DISPLAY=$DISPLAY -v $HOME/.Xauthority:/home/xilinx/.Xauthority registry.gitlab.com/xilinxrobotics/tb3nav2_demo:foxy

# Run setup (inside container)
byobu -f configs/poc.conf attach
```
