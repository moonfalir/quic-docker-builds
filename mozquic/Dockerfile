# OS used
FROM ubuntu:16.04

# install basic packages 
RUN apt-get update && apt-get install -y \
 git \ 
 make \ 
 pkg-config \ 
 autoconf \ 
 automake \
 python \
 python-dev \
 gcc \
 mercurial \
 gyp \
 ninja

# clone and build mozquic

RUN git clone https://github.com/mcmanus/mozquic && git clone https://github.com/nss-dev/nss && hg clone https://hg.mozilla.org/projects/nspr 

WORKDIR nss 
RUN git checkout origin/NSS_3_36_BRANCH && ./build.sh -v -j 2

WORKDIR mozquic 
RUN make

# clone script repo

WORKDIR ../

RUN git clone https://github.com/moonfalir/quic-docker-builds

RUN chmod +x /quic-docker-builds/mozquic/startup-prep.sh

ENTRYPOINT ["/quic-docker-builds/mozquic/startup-prep.sh"]