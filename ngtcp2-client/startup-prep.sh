#! /bin/sh

cd ../ && cd /ngtcp2

# update & rebuild ngtcp2 code
git pull

make -j$(nproc)

echo "Ready to run"

# open bash
/bin/bash
