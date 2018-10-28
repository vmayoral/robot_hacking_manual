#!/usr/bin/env bash

# #######################################
# # setup environment for ROS installation from packages
# #######################################
# # install packages
# apt-get update && apt-get install -q -y \
#     dirmngr \
#     gnupg2 \
#     lsb-release \
#     && rm -rf /var/lib/apt/lists/*
# # setup keys
# apt-key adv --keyserver hkp://keyserver.ubuntu.com:80 --recv-keys 421C365BD9FF1F717815A3895523BAEEB01FA116
# # setup sources.list
# echo "deb http://packages.ros.org/ros/ubuntu `lsb_release -sc` main" > /etc/apt/sources.list.d/ros-latest.list
# # install bootstrap tools
# apt-get update && apt-get install --no-install-recommends -y \
#     python-rosdep \
#     python-rosinstall \
#     python-vcstools \
#     && rm -rf /var/lib/apt/lists/*
# # setup environment
# export LANG=C.UTF-8
# export LC_ALL=C.UTF-8
# # bootstrap rosdep
# rosdep init \
#     && rosdep update
# # install ros packages
# export ROS_DISTRO=kinetic
# apt-get update && apt-get install -y \
#     ros-kinetic-ros-core=1.3.2-0* \
#     && rm -rf /var/lib/apt/lists/*

# #######################################
# # setup environment for ROS installation from sources
# #   NOT AUTOMATIC, minor issues need to be manually fixed
# #######################################
#
# apt-get update
# apt-get install -y python python-pip git
# pip install -U rosdep rosinstall_generator wstool rosinstall
# pip install --upgrade setuptools
# pip install -U rospkg
# # apt-get install python-rosdep python-rosinstall-generator python-wstool python-rosinstall build-essential
# rosdep init
# rosdep update
#
# mkdir /home/vagrant/ros_catkin_ws
# cd /home/vagrant/ros_catkin_ws
# rosinstall_generator ros_comm --rosdistro kinetic --deps --wet-only --tar > kinetic-ros_comm-wet.rosinstall
# wstool init -j8 src kinetic-ros_comm-wet.rosinstall
#
# # problem with rospkg, TODO fix
# rosdep install --from-paths src --ignore-src --rosdistro kinetic -y
#
# # TODO: automate installation of console_bridge, for now, install manually
# #   http://wiki.ros.org/console_bridge
# # since it was installed manually:
# # add to .bashrc:
# # export LD_LIBRARY_PATH="/usr/local/lib/x86_64-linux-gnu":$LD_LIBRARY_PATH
#
# apt-get install libtinyxml-dev python-defusedxml
#
# # in case compilation fails due to a lack of memory, set up swap https://digitizor.com/create-swap-file-ubuntu-linux/
# ./src/catkin/bin/catkin_make_isolated --install -DCMAKE_BUILD_TYPE=Release

#######################################
# Install mono
#######################################
apt-key adv --keyserver hkp://keyserver.ubuntu.com:80 --recv-keys 3FA7E0328081BFF6A14DA29AA6A19B38D3D831EF
apt-get update && apt-get install apt-transport-https
echo "deb https://download.mono-project.com/repo/ubuntu stable-trusty main" | tee /etc/apt/sources.list.d/mono-official-stable.list
apt-get update && apt-get -y install mono-devel
# alternatively, build it from source: https://www.mono-project.com/docs/compiling-mono/linux/
  # RUN certmgr -ssl -m https://go.microsoft.com
  # RUN certmgr -ssl -m https://nugetgallery.blob.core.windows.net
  # RUN certmgr -ssl -m https://nuget.org
  # RUN mozroots --import --sync

# Install a few additional dependencies
apt-get install -y nuget git

# # Get a simple talker/listener into the scenario, get roschaos
# cp -r pubsub_example /home/vagrant/ros_catkin_ws/src/pubsub_example

#######################################
# Install roschaos and simple example
#######################################
cd /home/vagrant/ros_catkin_ws/src && git clone https://github.com/ruffsl/roschaos
/bin/bash -c "cd /home/vagrant/ros_catkin_ws \
    && /home/vagrant/ros_catkin_ws/install_isolated/setup.bash \
    && catkin_make_isolated --install"
    # && catkin_make_isolated --install --install-space /opt/ros/kinetic"
    # && cd && rm -r /home/vagrant/ros_catkin_ws"

#######################################
# Install ROSPenTo
#######################################
  # Install ROSPenTo
cd /home/vagrant && git clone https://github.com/jr-robotics/ROSPenTo
cd /home/vagrant/ROSPenTo && nuget restore && msbuild

#   #Copy SSH banner
# rm -rf /etc/update-motd.d/* && rm -rf /etc/legal && \
#     sed -i 's/\#force_color_prompt=yes/force_color_prompt=yes/' /home/vagrant/.bashrc

# Create an alias for ROSPenTo and rospento
echo 'alias ROSPenTo="mono /home/vagrant/ROSPenTo/RosPenToConsole/bin/Debug/RosPenToConsole.exe"' >> /home/vagrant/.bashrc
echo 'alias rospento="mono /home/vagrant/ROSPenTo/RosPenToConsole/bin/Debug/RosPenToConsole.exe"' >> /home/vagrant/.bashrc
echo '/home/vagrant/ros_catkin_ws/install_isolated/setup.bash' >> /home/vagrant/.bashrc

#######################################
# Install Volatility
#######################################
# First, install Volatility Dependancies
apt-get install -y ca-certificates zlib1g-dev python-pillow python-crypto python-lxml python-setuptools
apt-get install -y libssl-dev \
                           python-dev \
                           libc-dev \
                           libjpeg-dev \
                           automake \
                           autoconf \
                           python-pip \
                           git \
                           libjansson-dev \
                           libtool \
                           flex
pip install --upgrade pip
pip install simplejson \
                    construct \
                    openpyxl \
                    haystack \
                    distorm3 \
                    colorama \
                    pycoin \
                    pytz
# install YARA
export YARA_VERSION=3.7.1
export YARA_PY_VERSION=3.7.0
set -x \
  && echo "Install Yara from source..." \
  && cd /tmp/ \
  && git clone --recursive --branch v$YARA_VERSION https://github.com/VirusTotal/yara.git \
  && cd /tmp/yara \
  && ./bootstrap.sh \
  && sync \
  && apt-get install -y libmagic-dev \
  && ./configure --with-crypto \
                 --enable-magic \
                 --enable-cuckoo \
                 --enable-dotnet
cd /tmp/yara \
   && make \
   && make install \
   && echo "Install yara-python..." \
   && cd /tmp/ \
   && git clone --recursive --branch v$YARA_PY_VERSION https://github.com/VirusTotal/yara-python \
   && cd yara-python \
   && python setup.py build --dynamic-linking \
   && sudo python setup.py install \
   && echo "Make test_rule..." \
   && mkdir /rules \
   && echo "rule dummy { condition: true }" > /rules/test_rule \
   && rm -rf /tmp/*
# Install distorm3
apt-get install -y pcregrep libpcre++-dev
cd /tmp \
  && git clone https://github.com/gdabah/distorm \
  && cd /tmp/distorm \
  && sudo python setup.py install \
  && sudo rm -rf /tmp/*
# Install PyCrypto
apt-get install -y libgmp3-dev wget
cd /tmp \
    && wget http://ftp.dlitz.net/pub/dlitz/crypto/pycrypto/pycrypto-2.6.tar.gz \
    && tar -xvzf pycrypto-2.6.tar.gz \
    && cd pycrypto-2.6 \
    && sudo python setup.py install \
    && sudo rm -rf /tmp/*
# Install ujson
pip install ujson pillow

# Install now volatility
export VOL_VERSION=2.6
cd /home/vagrant/ \
  && echo "===> Installing Volatility from source..." \
  && cd volatility \
  && sudo python setup.py install \
  && sudo rm -rf /tmp/*

# Installing the Malware Plugins
cd /usr/local/lib/python2.7/dist-packages/volatility-2.6-py2.7.egg/volatility/plugins/ \
    && wget http://code.google.com/p/malwarecookbook/source/browse/trunk/malware.py

# Fetch the profile, for this particular distro, Ubuntu 16.04.5
cd /home/vagrant \
    && apt-get install -y unzip \
    # && wget https://github.com/volatilityfoundation/profiles/blob/master/Linux/Ubuntu/x64/Ubuntu16045.zip?raw=true \
    && wget https://github.com/volatilityfoundation/profiles/blob/master/Linux/Ubuntu/x64/Ubuntu14045.zip?raw=true \
    && sudo mv Ubuntu14045.zip\?raw\=true /usr/local/lib/python2.7/dist-packages/volatility-2.6-py2.7.egg/volatility/plugins/overlays/linux/Ubuntu14045.zip

# # This creates an issue with the installation
# # Installing the community Plugins
# cd /usr/local/lib/python2.7/dist-packages/volatility-2.6-py2.7.egg/volatility/plugins/ \
#     && git clone https://github.com/volatilityfoundation/community
