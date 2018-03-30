# Copyright 2018 Víctor Mayoral Vilches - All Rights Reserved
#
# Unauthorized copying of this file, via any medium is strictly prohibited

# Default, 64 bit image
# FROM ubuntu:16.04

# 32 bit image
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
  less python3 python wget bsdmainutils

#--------------------
# Set up proper (comfortable) gdb environment
#--------------------
RUN wget -P ~ git.io/.gdbinit

#--------------------
# Copy source files
#--------------------
COPY rop1.c /root
COPY rop2.c /root

#--------------------
# Compile code
#--------------------
RUN gcc rop1.c -g -o rop1
# Compile without tricks to avoid overflows
RUN gcc rop1.c -g -o rop1_noprotection -fno-stack-protector -z execstack

RUN gcc rop2.c -g -o rop2
# Compile without tricks to avoid overflows
RUN gcc rop2.c -g -o rop2_noprotection -fno-stack-protector -z execstack

#--------------------
# Entry point
#--------------------
CMD ["bash"]
