# OS used
FROM ubuntu:16.04

# install basic packages 
RUN apt-get update && apt-get install -y \
 git \ 
 make \
 gcc \
 g++ \
 pkg-config \ 
 autoconf \ 
 automake \ 
 autotools-dev \ 
 libtool \ 
 libev-dev \
 libmodule-install-perl \
 libssl-dev \
 tcl-dev \
 libpcre3-dev \
 libcap-dev \
 libhwloc-dev

# clone and build openssl
RUN git clone --depth 1 https://github.com/openssl/openssl

WORKDIR ./openssl

RUN ./config enable-tls1_3 --prefix=$PWD/build && make && make install

WORKDIR ../

# clone and build ats

RUN git clone --depth 1 --branch quic-latest https://github.com/apache/trafficserver

WORKDIR ./trafficserver

RUN autoreconf -if && ./configure --prefix=$PWD/atsbuild --with-openssl=$PWD/../openssl/build --enable-debug && make && make install

WORKDIR ../

RUN git clone https://github.com/moonfalir/quic-docker-builds

RUN chmod +x /quic-docker-builds/ats/startup-prep.sh

ENTRYPOINT ["/quic-docker-builds/ats/startup-prep.sh"]