#!/bin/bash

show_help() {
   echo "Usage: ${0##*/} [-u] [-d] [-i] ...

   		-u update startup script"
}
#if -u given, override the entrypoint script to first update startup-prep.sh
override=""
parameter=""
while getopts uhdif opt ; do
	case $opt in
		u)  override="--entrypoint /quic-docker-builds/quicker-clients/bootstrap.sh"
			;;
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