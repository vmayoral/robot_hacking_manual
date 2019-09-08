FROM ubuntu:precise
MAINTAINER Víctor Mayoral Vilches<victor@aliasrobotics.com>

# setup source.list to old-releases
RUN sed -i -e 's/archive/old-releases/g' /etc/apt/sources.list

# setup keys
RUN apt-key adv --keyserver hkp://keyserver.ubuntu.com:80 --recv-keys 421C365BD9FF1F717815A3895523BAEEB01FA116

# setup sources.list
RUN echo "deb http://packages.ros.org/ros/ubuntu precise main" > /etc/apt/sources.list.d/ros-latest.list

# setup environment
RUN locale-gen en_US.UTF-8
ENV LANG en_US.UTF-8

# install ros packages
ENV ROS_DISTRO hydro
RUN apt-get update && apt-get install -y \
    ros-hydro-ros \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir /var/lib/apt/lists/partial

# Install a few additional dependencies
RUN apt-get update
RUN apt-get install -y git build-essential

# Get a simple talker/listener into the scenario, get roschaos
COPY pubsub_example /root/ros_catkin_ws/src/pubsub_example
RUN cd /root/ros_catkin_ws/src && git clone https://github.com/ruffsl/roschaos
RUN cd /root/ros_catkin_ws/src && git clone https://github.com/ros/rosconsole
# Get roscpp tutorials
RUN cd /root/ros_catkin_ws/src && git clone https://github.com/ros/ros_tutorials
RUN cd /root/ros_catkin_ws/src && touch ros_tutorials/ros_tutorials/CATKIN_IGNORE
RUN cd /root/ros_catkin_ws/src && touch ros_tutorials/rospy_tutorials/CATKIN_IGNORE
RUN cd /root/ros_catkin_ws/src && touch ros_tutorials/turtlesim/CATKIN_IGNORE
RUN /bin/bash -c "cd /root/ros_catkin_ws \
  && source /opt/ros/hydro/setup.bash \
  && catkin_make_isolated --install --install-space /opt/ros/hydro \
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
RUN echo 'source /opt/ros/hydro/setup.bash' >> /root/.bashrc

COPY launch_script.bash /root/
ENTRYPOINT ["/root/launch_script.bash"]
