# build from this 64 bit image
FROM superkojiman/pwnbox

#--------------------
# General setup
#--------------------
# setup environment
ENV LANG C.UTF-8
ENV LC_ALL C.UTF-8

WORKDIR /root

#--------------------
# Copy source files
#--------------------
COPY vulnerable.c /root
COPY exploit2.c /root

#--------------------
# Compile code
#--------------------
RUN gcc vulnerable.c -m32 -g -o vulnerable -fno-stack-protector -z execstack
RUN gcc exploit2.c -m32 -g -o exploit2 -fno-stack-protector -z execstack


#--------------------
# Entry point
#--------------------
# CMD ["bash"]
ENTRYPOINT ["/bin/bash"]
