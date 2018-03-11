#! /bin/sh

cd ../ && cd /quicly

# update & rebuild quicly code
git pull

cmake && make 

echo "Ready to run"

# open bash
/bin/bash
