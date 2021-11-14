#!/bin/bash

source /opt/ros/kinetic/setup.bash

roscore &
sleep 4
rosrun scenario1 talker &
rosrun scenario1 listener > /tmp/listener.txt &

# Get a prompt
bash
