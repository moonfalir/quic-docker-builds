#! /bin/sh

mkdir ./openssl

cd ./openssl

repository="https://github.com/openssl/openssl"

localFolder="."

git clone --depth 1 "$repository" "$localFolder"

./config enable-tls1_3 --prefix=$PWD/build

make -j$(nproc)

make install_sw

cd ../

mkdir ./ngtcp2

cd ./ngtcp2

repository="https://github.com/ngtcp2/ngtcp2"

localFolder="."

git clone "$repository" "$localFolder"

autoreconf -i

./configure PKG_CONFIG_PATH=$PWD/../openssl/build/lib/pkgconfig LDFLAGS="-Wl,-rpath,$PWD/../openssl/build/lib"

make -j$(nproc) check

cp /server.key /ngtcp2/server.key

cp /server.crt /ngtcp2/server.crt

cp /run-ngtcp2-client.sh /ngtcp2/run-client.sh

cp /run-ngtcp2-server.sh /ngtcp2/run-server.sh

/bin/bash