#! /bin/sh

cd ../ && cd /quicker

# update & rebuild ngtcp2 code
git pull
npm install

echo "Ready to run"

# open bash
/bin/bash
