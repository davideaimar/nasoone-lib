#!/bin/sh

if [ "$1" = "All" ]
then 
find ./output/ -name "*" -type f -delete
echo "All files deleted"
else
find ./output/ -name "$1" -type f -delete
echo "File deleted"
fi
echo "Goodbye"

