FROM ros:dashing

LABEL maintainer="Víctor Mayoral Vilches v.mayoralv@gmail.com"

ENV TERM xterm
ENV ROS_DISTRO dashing
ENV ROS_WS=/opt/ros2_asan_ws
WORKDIR $ROS_WS

ENV LANG C.UTF-8
ENV LC_ALL C.UTF-8

RUN \
       apt-get update -qq && apt-get install -qq -y \
         wget \
         clang clang-format-3.9 clang-tidy clang-tools \
      && rm -rf /var/lib/apt/lists/*

# mixins are configuration files used to compile ROS 2 easily
RUN apt-get update -qq && apt-get install -y python3-colcon-mixin git
RUN colcon mixin add default https://raw.githubusercontent.com/colcon/colcon-mixin-repository/master/index.yaml
RUN colcon mixin update default

# colcon-santizer-reports for analyzing ROS 2
#   a plugin for colcon test that parses sanitizer issues 
#   from stdout/stderr, deduplicates the issues, and outputs them to a CSV.
RUN git clone https://github.com/colcon/colcon-sanitizer-reports.git
RUN cd colcon-sanitizer-reports && python3 setup.py install

RUN apt install -y ccache
# increase cache size
RUN ccache -M 10G 
ENV CC=/usr/lib/ccache/gcc
ENV CXX=/usr/lib/ccache/g++

# Download sources of ROS 2 Dashing
RUN mkdir -p $ROS_WS/src \
    && wget https://raw.githubusercontent.com/ros2/ros2/release-latest/ros2.repos \
    && vcs import src < ros2.repos
    # && cd src && git clone https://github.com/AcutronicRobotics/moveit2
    # wstool init --shallow . https://raw.githubusercontent.com/ros-planning/moveit2/master/moveit.rosinstall

# Ignore a bunch of packages that aren't intentended to be tested
RUN touch src/ros2/common_interfaces/actionlib_msgs/COLCON_IGNORE \
  && touch src/ros2/common_interfaces/common_interfaces/COLCON_IGNORE \
  && touch src/ros2/rosidl_typesupport_opensplice/opensplice_cmake_module/COLCON_IGNORE \
  && touch src/ros2/rmw_fastrtps/rmw_fastrtps_dynamic_cpp/COLCON_IGNORE \
  && touch src/ros2/rmw_opensplice/rmw_opensplice_cpp/COLCON_IGNORE \
  && touch src/ros2/ros1_bridge/COLCON_IGNORE \
  && touch src/ros2/rosidl_typesupport_opensplice/rosidl_typesupport_opensplice_c/COLCON_IGNORE \
  && touch src/ros2/rosidl_typesupport_opensplice/rosidl_typesupport_opensplice_cpp/COLCON_IGNORE \
  && touch src/ros2/common_interfaces/shape_msgs/COLCON_IGNORE \
  && touch src/ros2/common_interfaces/stereo_msgs/COLCON_IGNORE \
  && touch src/ros2/common_interfaces/trajectory_msgs/COLCON_IGNORE
  
# Get last version of FastRTPS and install dependencies
RUN cd src/eProsima/Fast-RTPS/ && git checkout master && git pull
RUN apt install --no-install-recommends -y \
  libasio-dev \
  libtinyxml2-dev \
  liblog4cxx-dev \
  less \
  tmux \
  vim

# RUN rosdep init 
RUN rosdep update && \
  rosdep install --from-paths src --ignore-src --rosdistro dashing -y --skip-keys "console_bridge fastcdr fastrtps libopensplice67 libopensplice69 rti-connext-dds-5.3.1 urdfdom_headers"
  
##########################################################
#       ASan
##########################################################
# Build code
RUN colcon build --build-base=build-asan --install-base=install-asan \
    --cmake-args -DOSRF_TESTING_TOOLS_CPP_DISABLE_MEMORY_TOOLS=ON \
                 -DINSTALL_EXAMPLES=OFF -DSECURITY=ON --no-warn-unused-cli \
                 -DCMAKE_BUILD_TYPE=Debug \
    --mixin asan-gcc \
    --packages-up-to test_communication \
    --symlink-install

# # Launch tests 
# RUN colcon test --build-base=build-asan --install-base=install-asan \
#     --event-handlers sanitizer_report+ --packages-up-to test_communication

##########################################################
#       TSan
##########################################################
# TODO

CMD ["bash"]