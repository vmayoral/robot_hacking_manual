# Copyright 2018 Víctor Mayoral Vilches - All Rights Reserved
#
# Unauthorized copying of this file, via any medium is strictly prohibited
# without previous consent.

# Default, 64 bit image
# FROM ubuntu:16.04

# # 32 bit image
FROM i686/ubuntu

#--------------------
# General setup
#--------------------
# setup environment
ENV LANG C.UTF-8
ENV LC_ALL C.UTF-8

WORKDIR /root
RUN apt-get update
RUN apt-get install -y binutils \
    gcc gdb

RUN apt-get update

# Utilities for the hack
RUN apt-get install -y vim \
  less python3 python wget bsdmainutils tcpdump \
  net-tools

RUN apt-get update
RUN apt-get install -y git cowsay

#--------------------
# Set up proper (comfortable) gdb environment
#--------------------
RUN wget -P ~ git.io/.gdbinit

# # SELECT ONE OR THE OTHER
# # Or, set up the Python Exploit Development Assistance for GDB (PEDA)
# RUN git clone https://github.com/longld/peda.git
# RUN echo "source /root/peda/peda.py" >> /root/.gdbinit

#--------------------
# Set up checksec
#--------------------
RUN git clone https://github.com/slimm609/checksec.sh
# RUN export PATH="/root/checksec.sh":$PATH

#--------------------
# Set up rp++
#--------------------
RUN wget https://github.com/downloads/0vercl0k/rp/rp-lin-x86
RUN mv rp-lin-x86 rp++
RUN chmod +x rp++

RUN apt-get update
RUN apt-get install -y netcat

# #--------------------
# # Set up python3-pwntools
# #--------------------
# RUN apt-get install -y python3-dev python3-pip
# RUN pip3 install --upgrade pip
# RUN pip3 install --upgrade git+https://github.com/arthaud/python3-pwntools.git

#--------------------
# Set up pwntools
#--------------------
# Install packages
RUN apt-get update
RUN apt-get upgrade -y
RUN apt-get install -y software-properties-common && \
    apt-add-repository -y ppa:pwntools/binutils && \
    apt-add-repository -y ppa:fkrull/deadsnakes-python2.7
RUN apt-get update
RUN apt-get install -y binutils-arm-linux-gnu \
                       binutils-i386-linux-gnu \
                       binutils-mips-linux-gnu \
                       binutils-mips64-linux-gnu

RUN apt-get install -y --force-yes git python2.7 python-pip python-dev libffi-dev libssl-dev
RUN pip install --upgrade setuptools
RUN pip install requests

RUN groupadd -r pwntools
RUN useradd -mrg pwntools pwntools
RUN rm -rf /var/lib/apt/lists/*

# Install pwntools
RUN git clone -b 3.7.1 https://github.com/Gallopsled/pwntools.git && \
    pip install --upgrade --editable pwntools

# Install z3
RUN git clone https://github.com/Z3Prover/z3.git && \
    cd z3 && \
    python scripts/mk_make.py --python && \
    cd build && \
    make && \
    make install && \
    cd / && \
    rm -rf z3


#--------------------
# Copy source files
#--------------------
# COPY client.c /root

#--------------------
# Compile code
#--------------------
# RUN gcc client.c -g -o client -fno-stack-protector -z execstack

#--------------------
# Entry point
#--------------------
CMD ["bash"]
