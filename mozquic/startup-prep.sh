#! /bin/sh

cd ../ && cd /trafficserver

# update & rebuild ats code
git pull

make && make install

echo "Ready to run"

# open bash
/bin/bash
