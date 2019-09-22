\newpage

## WIP: Tutorial 6: Analyzing Turtlebot 3

This tutorial will research the Turtlebot 3 or TB3 for short. A quick search shows that most of the official content of this robot is for ROS. ROS is completely vulnerable and it makes little sense to try and exploit it since prior research has already shown its vulnerability status. This work will instead focus on a ROS2-specific-TB3.

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

### Resources
- [^1]: Official e-manual of TB3 http://emanual.robotis.com/docs/en/platform/turtlebot3/overview/
- [^2]: ROS 2 specific section in TB3 e-manual http://emanual.robotis.com/docs/en/platform/turtlebot3/ros2/
- [^3]: TB3 ROS 2 packages https://github.com/ROBOTIS-GIT/turtlebot3/tree/ros2