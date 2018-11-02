FROM ros:jade-ros-core-trusty
MAINTAINER Víctor Mayoral Vilches<victor@aliasrobotics.com>

# install ros packages
RUN apt-get update && apt-get install -y \
    ros-jade-ros-base=1.2.1-0* \
    && rm -rf /var/lib/apt/lists/*

# RUN apt-get update && apt-get install -y \
#     ros-kinetic-robot=1.3.2-0* \
#     && rm -rf /var/lib/apt/lists/*

# Install a few additional dependencies

RUN apt-get update && apt-get install -y git build-essential

# Get a simple talker/listener into the scenario, get roschaos
COPY pubsub_example /root/ros_catkin_ws/src/pubsub_example
RUN cd /root/ros_catkin_ws/src && git clone https://github.com/ruffsl/roschaos
# Get roscpp tutorials
RUN cd /root/ros_catkin_ws/src && git clone https://github.com/ros/ros_tutorials
RUN cd /root/ros_catkin_ws/src && touch ros_tutorials/ros_tutorials/CATKIN_IGNORE
RUN cd /root/ros_catkin_ws/src && touch ros_tutorials/rospy_tutorials/CATKIN_IGNORE
RUN cd /root/ros_catkin_ws/src && touch ros_tutorials/turtlesim/CATKIN_IGNORE
RUN /bin/bash -c "cd /root/ros_catkin_ws \
  && source /opt/ros/jade/setup.bash \
  && catkin_make_isolated --install --install-space /opt/ros/jade \
  && cd && rm -r /root/ros_catkin_ws"

# # Install ROSPenTo
# RUN cd /root && git clone https://github.com/jr-robotics/ROSPenTo
# RUN cd /root/ROSPenTo && nuget restore && msbuild

#Copy SSH banner
RUN rm -rf /etc/update-motd.d/* && rm -rf /etc/legal && \
  sed -i 's/\#force_color_prompt=yes/force_color_prompt=yes/' /root/.bashrc
# Create an alias for ROSPenTo and rospento
RUN echo 'alias ROSPenTo="mono /root/ROSPenTo/RosPenToConsole/bin/Debug/RosPenToConsole.exe"' >> /root/.bashrc
RUN echo 'alias rospento="mono /root/ROSPenTo/RosPenToConsole/bin/Debug/RosPenToConsole.exe"' >> /root/.bashrc

RUN apt-get install -y lsof net-tools psmisc
RUN echo 'source /opt/ros/jade/setup.bash' >> /root/.bashrc

COPY launch_script.bash /root/
ENTRYPOINT ["/root/launch_script.bash"]
