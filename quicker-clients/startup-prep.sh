#!/bin/bash

cd ../ && cd /quicker

# update & rebuild ngtcp2 code
if [[ $1 == "duplicates" ]];
then
	git pull origin d11-duplicate-packets
elif [[ $1 == "initials" ]]; 
then
	git pull origin d11-sent-2-initial
elif [[ $1 == "flowblocking" ]]; 
then
	git pull origin d11-exceeding-maxdata
elif [[ $1 == "longtransfer" ]]; 
then
	git pull origin d11-long-transfer
elif [[ $1 == "0rtt" ]]; 
then
	git pull origin d11-incorrect-0rtt
else
	git pull origin d11-baseclient
fi

npm install
tsc -p ./

cd ./out/

echo "Ready to run"

# open bash
/bin/bash
