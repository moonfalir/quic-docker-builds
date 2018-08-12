# OS used
FROM ubuntu:18.04

# install basic packages 
RUN apt-get update && apt-get install -y \
 git \ 
 gcc-7 \ 
 g++ \  
 make \
 python \
 nasm \
 libssl-dev
 
# install specific node js
RUN git clone -b add_quicker_support-tls-d28 https://github.com/kevin-kp/node

WORKDIR ./node

RUN git checkout 257a17bbd3f6e3e1ae7b536cc2ef7b79714362af 

#copy new tls13_enc.cc file with key export and qtls_wrap.cc with call back

COPY tls13_enc.c /node/deps/openssl/openssl/ssl/

COPY qtls_wrap.cc /node/src/

RUN ./configure --openssl-no-asm && make && cp /node/out/Release/node /usr/bin/

WORKDIR ../

# install quicker
RUN git clone https://github.com/moonfalir/quicker

WORKDIR /quicker

RUN git checkout -b d11-baseclient

RUN apt-get install -y npm && npm install typescript -g && npm install && tsc -p ./

# clone scripts repo

WORKDIR ../

RUN git clone https://github.com/moonfalir/quic-docker-builds

RUN chmod +x /quic-docker-builds/quicker/startup-prep.sh

ENTRYPOINT ["/quic-docker-builds/quicker/startup-prep.sh"]