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

# copy the aztarna files the FS and install it
COPY ./aztarna /root/aztarna
# RUN cd /root/aztarna && git checkout ${AZTARNA_COMMIT} && python3 setup.py install
RUN cd /root/aztarna && python3 setup.py install
