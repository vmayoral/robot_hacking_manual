FROM ros:melodic-ros-core-bionic
# FROM ros:kinetic-ros-base-xenial
MAINTAINER Víctor Mayoral Vilches<victor@aliasrobotics.com>

# install ros packages
RUN apt-get update && apt-get install -y \
    ros-melodic-ros-base=1.4.1-0* \
    && rm -rf /var/lib/apt/lists/*

# RUN apt-get update && apt-get install -y \
#     ros-kinetic-robot=1.3.2-0* \
#     && rm -rf /var/lib/apt/lists/*

RUN apt-get -qq update && apt-get -qqy upgrade
# install aztarna build dependencies
RUN apt-get -qqy install build-essential cmake libgmp3-dev gengetopt libpcap-dev flex byacc libjson-c-dev pkg-config libunistring-dev wget unzip git
# RUN apt-get install software-properties-common -y
# RUN add-apt-repository ppa:deadsnakes/ppa
# RUN apt-get update
# RUN apt-get -qqy install python3.6 python3-dev python3-pip
RUN apt-get -qqy install python3 python3-dev python3-pip
RUN apt-get -qqy install libxml2-dev libxslt1-dev
RUN apt-get -qqy install zlib1g-dev
RUN apt-get -qqy install libffi-dev
RUN apt-get -qqy install libssl-dev


######################
# Install SROS
######################
# setup environment
ENV LANG C.UTF-8
ENV LC_ALL C.UTF-8

# set environment and workspace
ENV ROS_DISTRO melodic
ENV CATKIN_WS=/root/sros_catkin_ws
RUN mkdir -p $CATKIN_WS/src
WORKDIR $CATKIN_WS/src

RUN pip3 install rosinstall-generator
RUN apt-get install -y python-openssl apparmor-utils python-apparmor python-pip

# download sourcecode for sros
RUN rosinstall_generator \
      ros_comm \
      rospy_tutorials \
      --rosdistro ${ROS_DISTRO} \
      --deps \
      --tar > ${ROS_DISTRO}-ros_comm-wet.rosinstall && \
    wstool init -j8 . ${ROS_DISTRO}-ros_comm-wet.rosinstall && \
    rm -rf ros_comm && \
    git clone -b sros https://github.com/ros/ros_comm && \
    git clone -b sros https://github.com/ros-infrastructure/rospkg ../rospkg && \
    pip install --upgrade ../rospkg/

# # install dependencies
# RUN apt-get update && \
#     rosdep init && \
#     rosdep update && \
#     rosdep install -y \
#       --from-paths . \
#       --ignore-src \
#       --rosdistro ${ROS_DISTRO} \
#       --as-root=apt:false && \
#     pip install --upgrade ../rospkg/ && \
#     rm -rf /var/lib/apt/lists/*

# build repo
WORKDIR $CATKIN_WS
ENV TERM xterm
ENV PYTHONIOENCODING UTF-8
RUN touch src/rosconsole/CATKIN_IGNORE
RUN touch src/ros_comm/tools/rosbag/CATKIN_IGNORE
RUN touch src/ros_comm/tools/rosbag_storage/CATKIN_IGNORE
# RUN touch src/ros_comm/test/CAKTIN_IGNORE
COPY ./patch1.txt $CATKIN_WS
RUN patch /root/sros_catkin_ws/src/ros_comm/clients/roscpp/src/libros/transport/transport_udp.cpp < patch1.txt
RUN . /opt/ros/melodic/setup.sh && catkin_make_isolated --install -DCMAKE_BUILD_TYPE=Release
    # catkin build --no-status --summarize

# setup demo bashrc
# RUN echo 'source "$CATKIN_WS/install/setup.bash"' >> ~/.bashrc

# setup demo config
COPY ./config /root/.ros/sros/config/


######################
# Install `aztarna`
######################
# copy the aztarna files the FS and install it
COPY ./aztarna /root/aztarna
# RUN cd /root/aztarna && git checkout ${AZTARNA_COMMIT} && python3 setup.py install
RUN cd /root/aztarna && python3 setup.py install

# setup entrypoint
COPY ./ros_entrypoint.sh /

ENTRYPOINT ["/ros_entrypoint.sh"]
CMD ["bash"]
