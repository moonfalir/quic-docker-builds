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

RUN ./config enable-tls1_3 --prefix=$PWD/build && make && make install

WORKDIR ../

# clone and build ats

RUN git clone --depth 1 --branch quic-latest https://github.com/apache/trafficserver

WORKDIR ./traffifserver

RUN ./configure --prefix=$PWD/atsbuild --with-openssl=$PWD/../openssl --enable-debug && make && make install

WORKDIR ../

RUN git clone https://github.com/moonfalir/quic-docker-builds

RUN chmod +x /quic-docker-builds/ngtcp2/startup-prep.sh

# copy scripts over to container
COPY server.key server.crt ./

ENTRYPOINT ["/quic-docker-builds/ngtcp2/startup-prep.sh"]