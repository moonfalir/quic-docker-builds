#!/bin/bash

show_help() {
   echo "Usage: ${0##*/} [-u] ...

   		-u update startup script"
}
#if -u given, override the entrypoint script to first update startup-prep.sh
override=""
while getopts uh opt ; do
	case $opt in
		u)  override="--entrypoint /quic-docker-builds/picoquic/bootstrap.sh"
			;;
		h) show_help
		   exit 0
		   ;;
		*) show_help >&2
		   exit 1
		   ;;
    esac
done

# start container
dockerrun="docker run --rm -it --net=host -v ~/Documents/bachelorproef/quic-docker-builds/picoquic/serverlogs:/serverlogs"
dockerrun="$dockerrun $override picoquic"
eval $dockerrun