#!/bin/bash

if [ "$#" -ne 2 ]; then
	echo "Usage: $0 <sourceFile> <outputBinary>"
	exit 1
else
	test gcc
	if [ "$?" -ne 0 ];then
		echo "Installation Instructions"
		echo "sudo apt update && sudo apt install build-essential"
	fi
	gcc -fno-stack-protector -z execstack -z norelro -no-pie -o $2 $1
fi
