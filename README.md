To generate a private key and certificate for a server use:
openssl req -newkey rsa:2048 -nodes -keyout server.key -x509 -days 365 -out server.crt