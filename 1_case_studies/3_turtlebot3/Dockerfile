ARG DISTRO=foxy
FROM ros:$DISTRO

# all variables are reset at FROM, so set the distro again
ARG DISTRO=foxy
ARG DEBIAN_FRONTEND=noninteractive

#######################
# Fix mess with ROS GPG Key Expiration
#######################
# https://discourse.ros.org/t/ros-gpg-key-expiration-incident/20669/27
RUN apt-get update || true \
    && apt install -y curl \
    && curl -s https://raw.githubusercontent.com/ros/rosdistro/master/ros.asc | apt-key add - \
    && apt-get update


# install helpful developer tools
RUN apt-get update && apt-get install -y \
      bash-completion \
      byobu \
      ccache \
      fish \
      glances \
      tshark \
      micro \
      nano \
      python3-argcomplete \
      python3-pip \
      tree \
      vim \
    && rm -rf /var/lib/apt/lists/*

#######################
# Install OpenDDS
#######################
# see https://github.com/objectcomputing/OpenDDS/blob/master/Dockerfile
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y \
    cmake \
    curl \
    g++ \
    make \
    libxerces-c-dev \
    libssl-dev \
    perl-base \
    perl-modules \
    git \
    wget

# Fetch OpenDDS - DDS-3.17-pre1
# RUN git clone https://github.com/objectcomputing/OpenDDS /opt/OpenDDS \
#     && cd /opt/OpenDDS \
#     && git checkout e1a955c54a28b60c04aad44780709e4cd370f78c
# RUN git clone https://github.com/objectcomputing/OpenDDS /opt/OpenDDS -b DDS-3.17-pre1
RUN git clone https://github.com/objectcomputing/OpenDDS /opt/OpenDDS -b DDS-3.17
# RUN git clone https://github.com/objectcomputing/OpenDDS /opt/OpenDDS -b DDS-3.16.1
# RUN git clone https://github.com/objectcomputing/OpenDDS /opt/OpenDDS -b DDS-3.16
# RUN git clone https://github.com/objectcomputing/OpenDDS /opt/OpenDDS -b DDS-3.18
# RUN git clone https://github.com/objectcomputing/OpenDDS /opt/OpenDDS -b DDS-3.18.1

ARG ACE_CONFIG_OPTION="--doc-group"
RUN cd /opt/OpenDDS && \
    ./configure --prefix=/usr/local --security ${ACE_CONFIG_OPTION} && \
    ./tools/scripts/show_build_config.pl && \
    make -j12 && \
    make install && \
    ldconfig && \
    . /opt/OpenDDS/setenv.sh && \
    cp -a ${MPC_ROOT} /usr/local/share/MPC

ENV ACE_ROOT=/usr/local/share/ace \
    TAO_ROOT=/usr/local/share/tao \
    DDS_ROOT=/usr/local/share/dds \
    MPC_ROOT=/usr/local/share/MPC \
    PATH=".:/usr/local/share/ace/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

WORKDIR /opt/OpenDDS/tests/DCPS/Messenger
RUN mwc.pl -type gnuace && make

# Get it into ROS 2 workspace
RUN mkdir -p /opt/opendds_ws/src
WORKDIR /opt/opendds_ws
RUN wget https://github.com/oci-labs/rmw_build/raw/master/rmw_opendds.repos \
    && wget https://github.com/oci-labs/rmw_build/raw/master/ros2.repos  -O opendds_ros2.repos \
    && vcs import src < rmw_opendds.repos \
    && vcs import src < opendds_ros2.repos \
    && git clone https://github.com/ros2/rosidl_dds src/rosidl_dds \
    && git clone https://github.com/ROBOTIS-GIT/turtlebot3 -b foxy-devel src/turtlebot3

# Build in two steps as defined @ https://github.com/oci-labs/rmw_build/blob/master/build_all.sh
# Build rmw
RUN /bin/bash -c ". /opt/ros/$DISTRO/setup.bash \
      && colcon build --merge-install \
        --packages-up-to rmw_opendds_cpp"

# Build rest
RUN /bin/bash -c ". /opt/ros/$DISTRO/setup.bash \
      && . install/local_setup.bash \
      && colcon build --merge-install \
        --packages-up-to rmw_opendds_cpp rcl_interfaces examples_rclcpp_minimal_publisher \
        examples_rclcpp_minimal_subscriber examples_rclcpp_minimal_service \
        examples_rclcpp_minimal_client turtlebot3_teleop"


#######################
# Install RTI Connext DDS
#######################
## From archives
#
# # set up environment
# ENV NDDSHOME /opt/rti.com/rti_connext_dds-6.0.1
# WORKDIR $NDDSHOME
# # ADD https://s3.amazonaws.com/RTI/Bundles/6.1.0/Evaluation/rti_connext_dds-6.1.0-lm-x64Linux4gcc7.3.0.run ./
# COPY ./rti ./
# RUN chmod +x ./rti_connext_dds-6.1.0-lm-x64Linux4gcc7.3.0.run
# RUN yes | ./rti_connext_dds-6.1.0-lm-x64Linux4gcc7.3.0.run && \
#     mv y/*/* ./ && rm -rf y
#
# # set RTI DDS environment
# ENV CONNEXTDDS_DIR $NDDSHOME
# ENV PATH "$NDDSHOME/bin":$PATH
# ENV LD_LIBRARY_PATH "$NDDSHOME/lib/x64Linux4gcc7.3.0":$LD_LIBRARY_PATH
# # set RTI openssl environment
# ENV PATH "$NDDSHOME/third_party/openssl-1.1.1k/x64Linux4gcc7.3.0/release/bin":$PATH
# ENV LD_LIBRARY_PATH "$NDDSHOME/third_party/openssl-1.1.1k/x64Linux4gcc7.3.0/release/lib":$LD_LIBRARY_PATH

## From deb files
# install RTI Connext
ENV RTI_NC_LICENSE_ACCEPTED yes
RUN apt-get update && apt-get install -y \
      ros-$DISTRO-rmw-connext-cpp \
    && rm -rf /var/lib/apt/lists/*

# set up environment
ENV NDDSHOME /opt/rti.com/rti_connext_dds-5.3.1
ENV PATH "$NDDSHOME/bin":$PATH
ENV LD_LIBRARY_PATH "$NDDSHOME/lib/x64Linux3gcc5.4.0":$LD_LIBRARY_PATH
# ENV LD_LIBRARY_PATH "$NDDSHOME/lib/x64Linux4gcc7.3.0":$LD_LIBRARY_PATH

# install RTI Security
WORKDIR $NDDSHOME
ADD https://s3.amazonaws.com/RTI/Bundles/5.3.1/Evaluation/rti_connext_dds_secure-5.3.1-eval-x64Linux3gcc5.4.0.tar.gz ./
RUN tar -xvf rti_connext_dds_secure-5.3.1-eval-x64Linux3gcc5.4.0.tar.gz -C ./
# COPY ./rti ./
RUN rtipkginstall rti_security_plugins-5.3.1-eval-x64Linux3gcc5.4.0.rtipkg && \
    rtipkginstall openssl-1.0.2n-5.3.1-host-x64Linux.rtipkg && \
    tar -xvf openssl-1.0.2n-target-x64Linux3gcc5.4.0.tar.gz
ENV PATH "$NDDSHOME/openssl-1.0.2n/x64Linux3gcc5.4.0/release/bin":$PATH
ENV LD_LIBRARY_PATH "$NDDSHOME/openssl-1.0.2n/x64Linux3gcc5.4.0/release/lib":$LD_LIBRARY_PATH

# # install RTI QoS
# WORKDIR $NDDSHOME
# COPY rti/NDDS_QOS_PROFILES.xml ./
# ENV NDDS_QOS_PROFILES "$NDDSHOME/NDDS_QOS_PROFILES.xml"

#######################
# Install RTPS dissector
#######################
RUN pip3 install git+https://github.com/vmayoral/scapy@rtps

#######################
# Install navigation2 and TB3
#######################
WORKDIR /opt

# install turtlebot external packages
RUN apt-get update && apt-get install -y \
      ros-$DISTRO-rviz2 \
      ros-$DISTRO-rqt* \
      ros-$DISTRO-navigation2 \
      ros-$DISTRO-nav2-bringup \
      ros-$DISTRO-turtlebot3* \
      ros-$DISTRO-key-teleop \
      ros-$DISTRO-demo-nodes-cpp \
    && rm -rf /var/lib/apt/lists/*

#######################
# Install CycloneDDS
#######################
RUN apt-get update && apt-get install -y \
      ros-foxy-rmw-cyclonedds-cpp \
    && rm -rf /var/lib/apt/lists/*

COPY configs configs
COPY exploits exploits

RUN echo "alias poc='/usr/bin/byobu -f /opt/configs/pocs.conf attach'" >> /root/.bashrc && \
    echo "alias poc_headless='/usr/bin/byobu -f /opt/configs/pocs_headless.conf attach'" >> /root/.bashrc && \
    echo "alias opendds='/usr/bin/byobu -f /opt/configs/opendds.conf attach'" >> /root/.bashrc

ENV TURTLEBOT3_MODEL='burger' \
    GAZEBO_MODEL_PATH=/usr/share/gazebo-11/models:/opt/ros/foxy/share/turtlebot3_gazebo/models

COPY ./entrypoint.sh /
ENTRYPOINT ["/entrypoint.sh"]
CMD ["bash"]
