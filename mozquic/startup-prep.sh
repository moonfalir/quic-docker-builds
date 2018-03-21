#! /bin/sh

cd ../ && cd /mozquic

# update & rebuild ats code
git pull

make

echo "Ready to run"

# open bash
/bin/bash
