# OS used
FROM ubuntu:18.04

# install basic packages 
RUN apt-get update && apt-get install -y \
 git \ 
 gcc-7 \ 
 g++ \  
 make \
 libev-dev \
 libssl-dev \
 libhttp-parser-dev \
 libbsd-dev \
 cmake \
 doxygen \
 graphviz \
 mercurial \
 pkg-config

# install quant
COPY ./quant/ /quant/

WORKDIR ./quant

RUN mkdir Debug && mkdir ./Debug/external && mkdir ./Debug/external/lib

WORKDIR ./Debug

RUN cmake .. && make

WORKDIR ../

RUN mkdir Release && mkdir ./Release/external && mkdir ./Release/external/lib

WORKDIR ./Release

RUN cmake -DCMAKE_BUILD_TYPE=Release .. && make

COPY server.key server.crt ../Debug/bin/

# clone scripts repo

WORKDIR /

RUN git clone https://github.com/moonfalir/quic-docker-builds

RUN chmod +x /quic-docker-builds/quant/startup-prep.sh

COPY index.html /quant/Debug/bin/

COPY 100MB.zip /quant/Debug/bin/

ENTRYPOINT ["/quic-docker-builds/quant/startup-prep.sh"]