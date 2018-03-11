#! /bin/sh

#update scripts

echo "updating startup-prep.sh"
cd /quic-docker-builds
git pull

#start client-container
echo "executing startup-prep.sh"
/quic-docker-builds/quicly/startup-prep.sh "$@"