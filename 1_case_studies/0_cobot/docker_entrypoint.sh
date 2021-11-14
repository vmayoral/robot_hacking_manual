#!/bin/bash
set -e
if [ ! -f /env.sh ]; then
    echo "No env.sh file. Nothing to do."
    exec "$@"
fi
if [ ! -d /outside ]; then
    echo "Run this image with a bind mount using '/outside' as the container mounted directory. Exiting."
    exit 1
fi

source /env.sh
mkdir -p /mnt/urfs1
mount -o ro,loop,offset="$OFFSET" ur_controller.img /mnt/urfs1
echo "Mounted UR controller image."
# the -C flag and the '.' is important so the base directory of the files in the archive is / instead of /mnt/urfs1
tar -C /mnt/urfs1/ -zcvf ur-fs.tar.gz .
echo "Extracted UR filesystem image"
umount /mnt/urfs1
mv ur-fs.tar.gz /outside
echo "DONE creating UR filesystem image. Exiting."
exit 0
