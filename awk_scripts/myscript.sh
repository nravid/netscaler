#!/bin/bash

files=$(ls)

<<fileloop
echo "Hello World!"
echo $files

if [ -f ./myscript.sh ]
then
    echo "File Exists"
else
    echo "File missing"
fi
fileloop


<<fileforloop
for curr_file in $files

do
    echo $curr_file
done
fileforloop

