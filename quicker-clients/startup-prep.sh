#! /bin/sh

cd ../ && cd /quicker

# update & rebuild ngtcp2 code
if [ $1 = "duplicates" ]; then
	git checkout -b d11-duplicate-packets
elif [ $1 = "initials" ]; then
	git checkout -b d11-sent-2-initial
fi

npm install

echo "Ready to run"

# open bash
/bin/bash
