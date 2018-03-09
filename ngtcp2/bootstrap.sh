#! /bin/sh

#update scripts
cd /quic-docker-builds
git pull

#start client-container

/quic-docker-builds/ngtcp2/startup-prep.sh "$@"