#! /bin/sh

cd ../ && cd /picoquic

# update & rebuild pico code
git pull

make 

echo "Ready to run"

# open bash
/bin/bash
