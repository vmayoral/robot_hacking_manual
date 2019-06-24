FROM ros:dashing

LABEL maintainer="Víctor Mayoral Vilches v.mayoralv@gmail.com"

ENV TERM xterm
ENV ROS_DISTRO dashing
ENV ROS_WS=/opt/ros2_moveit2_ws
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

RUN apt install --no-install-recommends -y \
  libasio-dev \
  libtinyxml2-dev \
  liblog4cxx-dev \
  less \
  tmux \
  vim

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

# Download moveit source, so that we can get necessary dependencies
RUN mkdir -p $ROS_WS/src \
    && wget https://raw.githubusercontent.com/AcutronicRobotics/moveit2/master/moveit2.repos \
    && vcs import src < moveit2.repos \
    && cd src && git clone https://github.com/AcutronicRobotics/moveit2
    # wstool init --shallow . https://raw.githubusercontent.com/ros-planning/moveit2/master/moveit.rosinstall

# TODO remove once https://github.com/ros2/geometry2/issues/116 is fixed
RUN mv $ROS_WS/src/geometry2/tf2_kdl $ROS_WS/src/
RUN rm -rf $ROS_WS/src/geometry2
# Apparently actions don't get installed right away, same with other deps
RUN apt-get update && apt-get install -y ros-dashing-rclcpp-action \
      libboost-date-time-dev \
      libboost-system-dev \
      libboost-thread-dev \
      libboost-filesystem-dev \
      ros-dashing-libcurl-vendor \
      ros-dashing-resource-retriever \
      libassimp-dev \
      libqhull-dev \
      ros-dashing-yaml-cpp-vendor \
      libboost-iostreams-dev \
      libfcl-dev

# Download all MoveIt 2 dependencies
RUN \
    apt-get -qq update && \
    rosdep update -q && \
    rosdep install -q -y --from-paths . --ignore-src --rosdistro ${ROS_DISTRO} --as-root=apt:false || true && \
    # Clear apt-cache to reduce image size
    rm -rf /var/lib/apt/lists/*
    
##########################################################
#       ASan
##########################################################

# Fetch some additional dependencies
RUN apt-get update && apt-get install -y libompl-dev python-vcstool python3-colcon-common-extensions libasan5

# Build code
# RUN /bin/bash -c "source /opt/ros/dashing/setup.bash && colcon build"
# Connected with https://github.com/AcutronicRobotics/moveit2/issues/112, we use --merge-install instead
RUN /bin/bash -c "source /opt/ros/dashing/setup.bash \
                    && colcon build --build-base=build-asan --install-base=install-asan\
                    --cmake-args -DOSRF_TESTING_TOOLS_CPP_DISABLE_MEMORY_TOOLS=ON \
                                 -DINSTALL_EXAMPLES=OFF -DSECURITY=ON --no-warn-unused-cli \
                                 -DCMAKE_BUILD_TYPE=Debug \
                    --mixin asan-gcc --merge-install \
                    --packages-up-to moveit_core"

# # Launch tests 
# RUN colcon test --build-base=build-asan --install-base=install-asan \
#     --event-handlers sanitizer_report+ --packages-up-to test_communication

##########################################################
#       TSan
##########################################################
# TODO

CMD ["bash"]