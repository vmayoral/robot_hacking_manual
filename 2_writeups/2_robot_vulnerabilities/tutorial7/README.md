\newpage

## WIP: Tutorial 7: Analyzing Turtlebot 3

This tutorial will research the Turtlebot 3 or TB3 for short. A quick search shows that most of the official content of this robot is for ROS. ROS is completely vulnerable and it makes little sense to try and exploit it since prior research has already shown its vulnerability status. This work will instead focus on a ROS2-specific-TB3.

### Background on SROS 2
- Note https://ruffsl.github.io/IROS2018_SROS2_Tutorial/
- SROS2 basics https://ruffsl.github.io/IROS2018_SROS2_Tutorial/content/slides/SROS2_Basics.pdf
- https://github.com/ros2/sros2/blob/master/SROS2_Linux.md

### Resources and exploring ROS 2 setup for TB3

The official manual [^1] provides an entry point. More interesting that the overall manual is [^2] which is the ROS2 specific section. A few things of relevance:
- Packages for the TB3 seem to be available at [^3]
- Repos are available but don't seem too filled:
  - https://github.com/ROBOTIS-GIT/turtlebot3/blob/ros2/turtlebot3.repos
  - https://github.com/ROBOTIS-GIT/turtlebot3/blob/ros2/turtlebot3_ci.repos

Searched for docker containers https://hub.docker.com/search?q=turtlebot3&type=image:
- https://github.com/TheLurps/turtlebot3_docker seems not updated and ROS1 based
- Found Ruffin's work at https://github.com/ros-swg/turtlebot3_demo, this seems the best spot from where to start. It even has some security aspects configured which will help further investigate it.

Settling on https://github.com/ros-swg/turtlebot3_demo.
It seems that this depends clearly on cartographer which is likely, another component for robots.

#### First steps, exploring turtlebot3_demo 

Let's start by cloning the repo and building it locally
```bash
git clone https://github.com/vmayoral/turtlebot3_demo
cd turtlebot3_demo
docker build . -t rosswg/turtlebot3_demo
```

then launch it in a Linux machine:
```bash
rocker --x11 rosswg/turtlebot3_demo:roscon19 "byobu -f configs/secure.conf attach"
```

Got myself familiar with the navigation of the environment https://github.com/vmayoral/turtlebot3_demo#running-the-demo. To scroll up/down one can use `F7` + the arrow lines and then `Enter` to exit this environment.

Tried exploring the setup launching `aztarna`. Found that takes about 4 minutes. Let's dive a bit more into reconnaissance.

#### Reconnaissance

*Moved to [Tutorial 3: Footprinting ROS 2 and DDS systems](../../1_reconnaissance/robot_footprinting/tutorial3/README.md)*.


### Resources
- [^1]: Official e-manual of TB3 http://emanual.robotis.com/docs/en/platform/turtlebot3/overview/
- [^2]: ROS 2 specific section in TB3 e-manual http://emanual.robotis.com/docs/en/platform/turtlebot3/ros2/
- [^3]: TB3 ROS 2 packages https://github.com/ROBOTIS-GIT/turtlebot3/tree/ros2