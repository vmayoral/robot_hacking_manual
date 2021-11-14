FROM ubuntu:bionic

# Modify this at build time using '--build-arg' flag.
ARG IMAGE_URL=https://s3-eu-west-1.amazonaws.com/ur-support-site/51826/Controller_USB-CB3.1-3.9.1.64192.img

RUN apt -y update && \
	apt install -y wget

RUN wget $IMAGE_URL --output-document ur_controller.img --progress=dot:giga

RUN UNITS="$(fdisk -l ur_controller.img | awk '/Sector size/{print $(NF-1)}')" && \
	START_SECTOR="$(fdisk -l ur_controller.img | awk '/ur_.*img1/{print $3}')" && \
	echo "sectors of $UNITS bytes. Start sector $START_SECTOR" && \
	OFFSET="$(awk -v units="$UNITS" -v start="$START_SECTOR" 'BEGIN{print units * start;}')" && \
	echo "offset $OFFSET" && \
	echo "export UNITS="${UNITS}"" >> /env.sh && \
	echo "export START_SECTOR="${START_SECTOR}"" >> /env.sh && \
	echo "export OFFSET="${OFFSET}"" >> /env.sh && \
	cat /env.sh

COPY docker_entrypoint.sh /docker_entrypoint.sh
RUN chmod +x /docker_entrypoint.sh
ENTRYPOINT ["/docker_entrypoint.sh"]
CMD ["/bin/bash"]
