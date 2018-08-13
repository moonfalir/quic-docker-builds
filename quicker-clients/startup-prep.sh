#!/bin/bash

cd ../ && cd /quicker

# update & rebuild ngtcp2 code
if [[ $1 == "duplicates" ]];
then
	git pull origin d11-duplicate-packets
elif [[ $1 == "initials" ]]; 
then
	git pull origin d11-sent-2-initial
else
	git pull origin d11-baseclient
fi

npm install
tsc -p ./

echo "Ready to run"

# open bash
/bin/bash
