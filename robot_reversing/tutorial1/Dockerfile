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
RUN /bin/bash -c "cd /root/ros_catkin_ws \
  && source /opt/ros/kinetic/setup.bash \
  && catkin_make_isolated --install --install-space /opt/ros/kinetic \
  && cd && rm -r /root/ros_catkin_ws"


# Install ROSPenTo
RUN cd /root && git clone https://github.com/jr-robotics/ROSPenTo
RUN cd /root/ROSPenTo && nuget restore && msbuild

#Copy SSH banner
RUN rm -rf /etc/update-motd.d/* && rm -rf /etc/legal && \
  sed -i 's/\#force_color_prompt=yes/force_color_prompt=yes/' /root/.bashrc
# Create an alias for ROSPenTo and rospento
RUN echo 'alias ROSPenTo="mono /root/ROSPenTo/RosPenToConsole/bin/Debug/RosPenToConsole.exe"' >> /root/.bashrc
RUN echo 'alias rospento="mono /root/ROSPenTo/RosPenToConsole/bin/Debug/RosPenToConsole.exe"' >> /root/.bashrc


# To install volatility project, we gain inspiration from:
  # - https://github.com/blacktop/docker-yara/blob/master/3.7/Dockerfile
  # - https://github.com/blacktop/docker-volatility/blob/master/2.6/Dockerfile

# First, install Volatility Dependancies
RUN apt-get install -y ca-certificates zlib1g-dev python-pillow python-crypto python-lxml python-setuptools
RUN apt-get install -y libssl-dev \
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
RUN pip install --upgrade pip
RUN pip install simplejson \
                    construct \
                    openpyxl \
                    haystack \
                    distorm3 \
                    colorama \
                    # ipython \
                    pycoin \
                    pytz
# install YARA
ENV YARA_VERSION 3.7.1
ENV YARA_PY_VERSION 3.7.0
RUN set -x \
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
RUN cd /tmp/yara \
   && make \
   && make install \
   && echo "Install yara-python..." \
   && cd /tmp/ \
   && git clone --recursive --branch v$YARA_PY_VERSION https://github.com/VirusTotal/yara-python \
   && cd yara-python \
   && python setup.py build --dynamic-linking \
   && python setup.py install \
   && echo "Make test_rule..." \
   && mkdir /rules \
   && echo "rule dummy { condition: true }" > /rules/test_rule \
   && rm -rf /tmp/*
# Install distorm3
RUN apt-get install -y pcregrep libpcre++-dev
RUN cd /tmp \
  && git clone https://github.com/gdabah/distorm \
  && cd /tmp/distorm \
  && python setup.py install \
  && rm -rf /tmp/*
# Install PyCrypto
RUN apt-get install -y libgmp3-dev wget
RUN cd /tmp \
    && wget http://ftp.dlitz.net/pub/dlitz/crypto/pycrypto/pycrypto-2.6.tar.gz \
    && tar -xvzf pycrypto-2.6.tar.gz \
    && cd pycrypto-2.6 \
    && python setup.py install \
    && rm -rf /tmp/*
# Install ujson
RUN pip install ujson pillow

# Install now volatility
ENV VOL_VERSION 2.6
# remove this and use git clone as below
COPY volatility /tmp/volatility
RUN cd /tmp \
  && echo "===> Installing Volatility from source..." \
  # && git clone --recursive --branch $VOL_VERSION https://github.com/volatilityfoundation/volatility.git \
  # && git clone --recursive https://github.com/vmayoral/volatility.git \
  && cd volatility \
  && python setup.py install \
  && rm -rf /tmp/*

# Installing the Malware Plugins
RUN cd /usr/local/lib/python2.7/dist-packages/volatility-2.6-py2.7.egg/volatility/plugins/ \
    && wget http://code.google.com/p/malwarecookbook/source/browse/trunk/malware.py

# Fetch the profile, for this particular distro, Ubuntu 16.04.5
RUN cd /root \
    && apt-get install -y unzip \
    # && wget https://github.com/volatilityfoundation/profiles/blob/master/Linux/Ubuntu/x64/Ubuntu16045.zip \
    && wget https://github.com/volatilityfoundation/profiles/blob/master/Linux/Ubuntu/x64/Ubuntu16045.zip?raw=true \
    # && unzip Ubuntu16045.zip?raw=true
    && mv Ubuntu16045.zip?raw=true /usr/local/lib/python2.7/dist-packages/volatility-2.6-py2.7.egg/volatility/plugins/overlays/linux/Ubuntu16045.zip

COPY launch_script.bash /root/
ENTRYPOINT ["/root/launch_script.bash"]
