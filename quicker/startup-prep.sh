#! /bin/sh

cd ../ && cd /quicker

# update & rebuild ngtcp2 code
git checkout a27bb339a4f8f1f057a29589c1380e8ff547ea75
npm install

echo "Ready to run"

# open bash
/bin/bash
