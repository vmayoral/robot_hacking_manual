#!/bin/bash

if [ $# -ne 1 ];then
	echo "Usage: $0 <binary>"
	exit 1
fi

hexdump -v -e '1/1 "\\"' -e '1/1 "x%02x"' $1 ; echo
