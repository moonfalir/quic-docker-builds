# OS used
FROM ubuntu:16.04

# install basic packages 
RUN apt-get update && apt-get install -y \
 git \ 
 gcc \ 
 g++ \  
 make \
 python \
 nasm \
 npm \
 libssl-dev
 
# install specific node js
COPY ./node/ /node/

WORKDIR ./node

RUN ./configure --openssl-no-asm && make && cp /node/out/Release/node /usr/bin/

WORKDIR ../

# install quicker
RUN git clone --single-branch -b draft-11 https://github.com/rmarx/quicker

WORKDIR ./quicker

RUN npm install typescript -g && npm install && tsc -p ./

# clone scripts repo

WORKDIR ../

RUN git clone https://github.com/moonfalir/quic-docker-builds

RUN chmod +x /quic-docker-builds/quicker/startup-prep.sh

ENTRYPOINT ["/quic-docker-builds/quicker/startup-prep.sh"]