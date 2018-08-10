#! /bin/sh

cd ../ && cd /quicker

# update & rebuild ngtcp2 code
git checkout 4e4bedb6f86047a0cc9c41ce66d930d94e6f6222
npm install

echo "Ready to run"

# open bash
/bin/bash
