#!/bin/sh

if [ $# -eq 0 ]
then 
find ./output/ -not -name ".gitkeep" -type f -delete
echo "All files deleted"
else
find ./output/ -name "$1" -type f -delete
echo "$1 deleted"
fi
echo "Goodbye"

