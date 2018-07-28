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

# install quant
RUN git clone --single-branch -b 11 https://github.com/NTAP/quant

WORKDIR ./quant

RUN mkdir Debug

WORKDIR ./Debug

RUN cmake .. && make

WORKDIR ../

RUN mkdir Release

WORKDIR ./Release

RUN cmake -DCMAKE_BUILD_TYPE=Release .. && make

WORKDIR ../

# clone scripts repo

WORKDIR ../

RUN git clone https://github.com/moonfalir/quic-docker-builds

RUN chmod +x /quic-docker-builds/quant/startup-prep.sh

ENTRYPOINT ["/quic-docker-builds/quant/startup-prep.sh"]