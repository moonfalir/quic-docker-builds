#! /bin/sh

cd /ngtcp2
# update & rebuild ngtcp2 code
git pull

make -j$(nproc)

# copy private key and server certificate
echo "copying server key and certificate"

cp /ngtcp2-server.key /ngtcp2/server.key
cp /ngtcp2-server.crt /ngtcp2/server.crt

# open bash
/bin/bash