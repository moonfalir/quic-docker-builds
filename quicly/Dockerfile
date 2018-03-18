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
 cmake

# clone and build openssl
RUN git clone --depth 1 https://github.com/openssl/openssl

WORKDIR ./openssl

RUN ./config enable-tls1_3 --prefix=$PWD/build && make && make install

WORKDIR ../

# clone and build quicly

RUN git clone https://github.com/h2o/quicly

WORKDIR ./quicly 

RUN PKG_CONFIG_PATH=$PWD/../openssl/build/lib/pkgconfig cmake && make && make check

# clone scripts repo

WORKDIR ../

RUN git clone https://github.com/moonfalir/quic-docker-builds

RUN chmod +x /quic-docker-builds/quicly/startup-prep.sh

# copy scripts over to container
COPY server.key server.crt ./

ENTRYPOINT ["/quic-docker-builds/quicly/startup-prep.sh"]