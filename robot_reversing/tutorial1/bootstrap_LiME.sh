#!/usr/bin/env bash

#######################################
# setup LiME
#######################################
cd $HOME && git clone https://github.com/504ensicsLabs/LiME
cd $HOME/LiME/src && make
cd $HOME/LiME/src && cp lime-*.ko lime.ko
cd $HOME/LiME/src && sudo mv lime.ko /lib/modules/

## Try it out:
# sudo insmod /lib/modules/lime.ko "path=/home/vagrant/test.lime format=lime"
