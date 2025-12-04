#!/bin/bash

if [ "$#" -ne 2 ]; then
	echo "Usage: $0 <sourceFile> <outputBinary>"
	exit 1
else
	test arm-linux-gnueabihf-gcc
	if [ "$?" -ne 0 ];then
		echo "Installation Instructions"
		echo "sudo apt install gcc-arm-linux-gnueabihf"
		echo "sudo dpkg --add-architecture armhf && sudo apt-get update && sudo apt-get install libc6:armhf libstdc++6:armhf"
	fi
	arm-linux-gnueabihf-gcc -fno-stack-protector -z execstack -z norelro -no-pie -o $2 $1
fi
