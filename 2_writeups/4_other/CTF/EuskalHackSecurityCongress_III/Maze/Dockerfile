# Copyright 2018 Víctor Mayoral Vilches - All Rights Reserved
#
# Unauthorized copying of this file, via any medium is strictly prohibited

# Default, 64 bit image
FROM ubuntu:16.04

# # 32 bit image
# FROM i686/ubuntu

# ARMv8
# FROM arm64v8/ubuntu:16.04 # sources.list not working
# FROM arm64v8/debian:latest # sources.list not working
# FROM arm64v8/alpine:latest # sources.list not working

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

#--------------------
# Copy source files
#--------------------
COPY Maze /root
RUN chmod +x /root/Maze

#--------------------
# Compile code
#--------------------
# RUN gcc client.c -g -o client -fno-stack-protector -z execstack

#--------------------
# Entry point
#--------------------
CMD ["bash"]
