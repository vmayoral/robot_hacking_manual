#!/bin/bash
set -e

# setup ros environment
# source "/root/sros_catkin_ws/install_isolated/setup.bash"
source "/root/sros_catkin_ws/install/setup.bash"
exec "$@"
