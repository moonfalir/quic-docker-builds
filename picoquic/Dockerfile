# OS used
FROM ubuntu:16.04

# install basic packages 
RUN apt-get update && apt-get install -y \
 git \ 
 make \ 
 pkg-config \ 
 autoconf \ 
 automake \ 
 autotools-dev \ 
 libtool \ 
 libev-dev \
 cmake \
 openssl

# clone and build openssl
RUN git clone --depth 1 https://github.com/openssl/openssl

WORKDIR ./openssl

RUN ./config enable-tls1_3 --prefix=$PWD/build && make && make install

WORKDIR ../

# clone and build picotls

RUN git clone https://github.com/h2o/picotls

WORKDIR ./picotls


RUN git submodule init && git submodule update && PKG_CONFIG_PATH=$PWD/../openssl/build/lib/pkgconfig cmake . && make && make 

WORKDIR ../

# clone and build picoquic

RUN git clone https://github.com/private-octopus/picoquic

WORKDIR ./picoquic

RUN git checkout d5bc5fa12e74def1ddbb71ce7d794fa13bc72cac

RUN PKG_CONFIG_PATH=$PWD/../openssl/build/lib/pkgconfig cmake . && make

# clone scripts repo

WORKDIR ../

RUN git clone https://github.com/moonfalir/quic-docker-builds

RUN chmod +x /quic-docker-builds/picoquic/startup-prep.sh

ENTRYPOINT ["/quic-docker-builds/picoquic/startup-prep.sh"]