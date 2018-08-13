#!/bin/bash

show_help() {
   echo "Usage: ${0##*/} [-d] [-i] [-f] ...

   		-u update startup script"
}
#if -u given, override the entrypoint script to first update startup-prep.sh
override="--entrypoint /quic-docker-builds/quicker-clients/bootstrap.sh"
parameter=""
while getopts hdif opt ; do
	case $opt in
		d)  parameter="duplicates"
		    ;;
	   	i)  parameter="initials"
		    ;;
	    f)  parameter="flowblocking"
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
dockerrun="docker run --rm -it --net=host -v ~/Documents/bachelorproef/quic-docker-builds/quicker-clients/serverlogs:/serverlogs"
dockerrun="$dockerrun $override quicker-clients $parameter"
eval $dockerrun