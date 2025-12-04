#!/bin/zsh

if [[ "$#" -ne 2 ]]; then
	echo "Usage: $0 <sourceCodeName> <compiledBinaryName>"
	exit 1
else
	gcc -fno-stack-protector -no-pie -fno-pie -z execstack -z norelro -o 64Bit/$2_64 source_code/$1
fi
