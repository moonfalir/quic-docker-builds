FROM ubuntu:16.04

RUN apt-get update

RUN apt-get install git -y

RUN apt-get install make -y

RUN apt-get install pkg-config -y

RUN apt-get install autoconf -y

RUN apt-get install automake -y

RUN apt-get install autotools-dev -y

RUN apt-get install libtool -y

RUN apt-get install libev-dev -y

COPY compilecode.sh /compilecode.sh

COPY run-ngtcp2-server.sh /run-ngtcp2-server.sh

COPY run-ngtcp2-client.sh /run-ngtcp2-client.sh

COPY ngtcp2-server.key /server.key

COPY ngtcp2-server.crt /server.crt

CMD ["/compilecode.sh"]