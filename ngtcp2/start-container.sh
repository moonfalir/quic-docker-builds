#! /bin/sh
# start container
docker run --rm -it --net=host -v /home/jonas/Documents/bachelorproef/quic-docker-builds/ngtcp2/sharedDir:/sharedDir ngtcp2
