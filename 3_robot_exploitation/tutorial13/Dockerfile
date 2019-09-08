FROM ros:kinetic-ros-base-xenial
MAINTAINER Víctor Mayoral Vilches<victor@aliasrobotics.com>

RUN apt-get update && apt-get install -y \
    ros-kinetic-robot=1.3.2-0* \
    && rm -rf /var/lib/apt/lists/*

# Install mono
RUN apt-key adv --keyserver hkp://keyserver.ubuntu.com:80 --recv-keys 3FA7E0328081BFF6A14DA29AA6A19B38D3D831EF
RUN apt-get update && apt-get install apt-transport-https
RUN echo "deb https://download.mono-project.com/repo/ubuntu stable-xenial main" | tee /etc/apt/sources.list.d/mono-official-stable.list
RUN apt-get update && apt-get -y install mono-devel
# RUN certmgr -ssl -m https://go.microsoft.com
# RUN certmgr -ssl -m https://nugetgallery.blob.core.windows.net
# RUN certmgr -ssl -m https://nuget.org
# RUN mozroots --import --sync

# Install a few additional dependencies
RUN apt-get install -y nuget git

# Get a simple talker/listener into the scenario, get roschaos
COPY pubsub_example /root/ros_catkin_ws/src/pubsub_example
RUN cd /root/ros_catkin_ws/src && git clone https://github.com/ruffsl/roschaos
# Get roscpp tutorials
RUN cd /root/ros_catkin_ws/src && git clone https://github.com/ros/ros_tutorials
RUN cd /root/ros_catkin_ws/src && touch ros_tutorials/ros_tutorials/AMENT_IGNORE
RUN cd /root/ros_catkin_ws/src && touch ros_tutorials/rospy_tutorials/AMENT_IGNORE
RUN cd /root/ros_catkin_ws/src && touch ros_tutorials/turtlesim/AMENT_IGNORE
RUN /bin/bash -c "cd /root/ros_catkin_ws \
  && source /opt/ros/kinetic/setup.bash \
  && catkin_make_isolated --install --install-space /opt/ros/kinetic \
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

COPY launch_script.bash /root/
ENTRYPOINT ["/root/launch_script.bash"]
