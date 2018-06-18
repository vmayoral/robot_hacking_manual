### Building a pwnbox

The aim of this tutorial is to build a docker container to perform security
assessments and CTFs. Ideally, I'll reuse existing tools.

Using [1], we can fetch the docker image from the docker Hub with:
```bash
docker pull superkojiman/pwnbox
```

Afterwards, simple specific containers can be created by extending this image.
An example is provided below:

```
# 64 bit image
FROM superkojiman/pwnbox

#--------------------
# General setup
#--------------------
# setup environment
ENV LANG C.UTF-8
ENV LC_ALL C.UTF-8

WORKDIR /root

#--------------------
# Entry point
#--------------------
# CMD ["bash"]
ENTRYPOINT ["/bin/bash"]
```

Alternatively, the [Dockerfile](Dockerfile) provided in this folder contains a
set of instructions to build a docker container from an Ubuntu machine that allows
to use pwntools. To build and run it, proceed as follows:

The container can be built with:
```bash
docker build -t basic_cybersecurity8:latest .
```
and runned with:
```bash
docker run --privileged -it basic_cybersecurity8:latest
```

### Bibliography
- [1] pwnbox. Retrieved from https://github.com/superkojiman/pwnbox.
- [2] pwntools-docker. Retrieved from https://github.com/RobertLarsen/pwntools-docker.
- [3] python3-pwntools. Retrieved from https://github.com/arthaud/python3-pwntools.
