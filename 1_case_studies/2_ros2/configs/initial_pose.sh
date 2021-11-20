#!/usr/bin/env bash

ros2 topic pub --once /initialpose geometry_msgs/msg/PoseWithCovarianceStamped "
header:
  frame_id: map
pose:
  pose:
    position:
      x: -2.7
      y: 0.4
      z: 0.0
    orientation:
      x: 0.0
      y: 0.0
      z: 0.0
      w: 1.0"