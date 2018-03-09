#! /bin/sh
# start container
docker run --rm -it --net=host --entrypoint /quic-docker-builds/ngtcp2/bootstrap.sh ngtcp2
