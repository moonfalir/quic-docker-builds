#! /bin/sh

#update scripts

git pull

#start client-container

./start-container.sh "$@"