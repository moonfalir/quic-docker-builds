# OS used
FROM ubuntu:16.04

# install basic packages 
RUN apt-get update && apt-get install -y \
 git \ 
 gcc \ 
 g++ \  
 make \
 python
 
# install specific node js
RUN git clone https://github.com/rmarx/node

WORKDIR ./node

WORKDIR ../

# install quicker
RUN git clone https://github.com/rmarx/quicker

WORKDIR ./quicker

# clone scripts repo

WORKDIR ../

RUN git clone https://github.com/moonfalir/quic-docker-builds

RUN chmod +x /quic-docker-builds/quicker/startup-prep.sh

ENTRYPOINT ["/quic-docker-builds/quicker/startup-prep.sh"]