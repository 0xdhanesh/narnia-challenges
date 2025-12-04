#!/bin/zsh

if [[ "$#" -ne 2 ]]; then
	echo "Usage: $0 <sourceCodeName> <compiledBinaryName>"
	exit 1
else
	gcc -m32 -fno-stack-protector -no-pie -fno-pie -z execstack -z norelro -o 32Bit/$2_32 source_code/$1
fi
