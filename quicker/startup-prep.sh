#! /bin/sh

cd ../ && cd /quicker

# update & rebuild ngtcp2 code
git checkout 1ba4322029cefffaa5cb6295bda9c0c2f278642a
npm install

echo "Ready to run"

# open bash
/bin/bash
