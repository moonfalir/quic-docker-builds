#! /bin/sh

cd ../ && cd /quicker

# update & rebuild ngtcp2 code
npm install
cd ./out/

echo "Ready to run"

# open bash
/bin/bash
