#! /bin/sh

cd ../ && cd /quicker

# update & rebuild ngtcp2 code
git checkout -b master
npm install

echo "Ready to run"

# open bash
/bin/bash
