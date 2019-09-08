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

#--------------------
# Copy source files
#--------------------
COPY rop1.c /root
COPY rop2.c /root
COPY rop3.c /root
COPY rop4.c /root
COPY rop5.c /root
COPY rop6.c /root

#--------------------
# Compile code
#--------------------
RUN gcc rop1.c -g -o rop1
# Compile without tricks to avoid overflows
RUN gcc rop1.c -g -o rop1_noprotection -fno-stack-protector -z execstack

RUN gcc rop2.c -g -o rop2
# Compile without tricks to avoid overflows
RUN gcc rop2.c -g -o rop2_noprotection -fno-stack-protector -z execstack

RUN gcc -m32 -g -O0 -fno-stack-protector -o rop3 rop3.c -ldl
RUN gcc -m32 -g -fno-stack-protector -o rop4 rop4.c
RUN gcc -m32 -g -fno-stack-protector -o rop5 rop5.c

RUN gcc rop6.c -g -o rop6 -fno-stack-protector -z execstack
COPY rop6_exploit.py /root

# Avoid re-running the whole file
RUN rm /root/.gdbinit
RUN wget -P ~ git.io/.gdbinit

#--------------------
# Entry point
#--------------------
CMD ["bash"]
