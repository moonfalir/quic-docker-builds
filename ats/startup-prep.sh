#! /bin/sh

cd ../ && cd /ats

# update & rebuild ats code
git pull

make && make install

echo "Ready to run"

# open bash
/bin/bash
