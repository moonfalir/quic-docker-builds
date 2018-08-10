#! /bin/sh

cd ../ && cd /quicker

# update & rebuild ngtcp2 code
git checkout 7b6bedc0aa570eca687ea8f72627b70755b26ceb
npm install

echo "Ready to run"

# open bash
/bin/bash
