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
 libev-dev

# clone and build openssl
RUN git clone --depth 1 https://github.com/openssl/openssl

WORKDIR ./openssl

RUN ./config enable-tls1_3 --prefix=$PWD/build && make -j$(nproc) && make install_sw

WORKDIR ../

# clone and build ngtcp2

RUN git clone https://github.com/ngtcp2/ngtcp2

WORKDIR ./ngtcp2

RUN autoreconf -i && ./configure PKG_CONFIG_PATH=$PWD/../openssl/build/lib/pkgconfig LDFLAGS="-Wl,-rpath,$PWD/../openssl/build/lib" && make -j$(nproc) check

# clone scripts repo

WORKDIR ../

RUN git clone https://github.com/moonfalir/quic-docker-builds

RUN chmod +x /quic-docker-builds/ngtcp2/startup-prep.sh

# copy scripts over to container
COPY server.key server.crt ./
 
ENTRYPOINT ["/quic-docker-builds/ngtcp2/startup-prep.sh"]