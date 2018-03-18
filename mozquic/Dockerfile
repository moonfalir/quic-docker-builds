# OS used
FROM ubuntu:16.04

# install basic packages 
RUN apt-get update && apt-get install -y \
 git \ 
 make \ 
 pkg-config \ 
 autoconf \ 
 automake

# clone and build openssl
RUN git clone --depth 1 https://github.com/openssl/openssl

WORKDIR ./openssl

RUN ./config enable-tls1_3 --prefix=$PWD/build && make && make install

WORKDIR ../

# clone and build mozquic

RUN git clone git@github.com:mcmanus/mozquic.git && git clone git@github.com:nss-dev/nss.git && hg clone https://hg.mozilla.org/projects/nspr 

WORKDIR nss 
RUN git checkout origin/NSS_3_36_BRANCH && nss/build.sh

WORKDIR mozquic 
RUN make

RUN git clone https://github.com/moonfalir/quic-docker-builds

RUN chmod +x /quic-docker-builds/mozquic/startup-prep.sh

ENTRYPOINT ["/quic-docker-builds/mozquic/startup-prep.sh"]