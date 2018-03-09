#! /bin/sh

#update scripts
cd /quic-docker-builds
git pull

#start client-container

./startup-prep.sh "$@"