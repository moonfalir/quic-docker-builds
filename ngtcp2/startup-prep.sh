#! /bin/sh
# update & rebuild ngtcp2 code
git pull

make -j$(nproc)

# open bash
# /bin/bash