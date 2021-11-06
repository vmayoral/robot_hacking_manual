#!/usr/bin/env bash

ros2 action send_goal /NavigateToPose nav2_msgs/action/NavigateToPose "
pose:
  pose:
    position:
      x: 1.0
      y: 1.1
      z: 0.0
    orientation:
      x: 0.0
      y: 0.0
      z: -1.0
      w: 0.0"