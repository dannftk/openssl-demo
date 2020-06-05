# TLS demo

This repository contains a TLS server and TLS client written in C for demonstration purposes.

# Requirements

You need to have `libssl1.0` and `libssl1.0-dev` (or a later version) installed.

# Build

```
gcc -o build/client client.c -I /usr/include/openssl/ -lssl -lcrypto
gcc -o build/server server.c -I /usr/include/openssl/ -lssl -lcrypto
```

# Run

To create X509 certificates (hit Enter 7 times after starting this):
```
openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days 365
```

Start the server:
```
build/server
```

Start the client:
```
build/client
```

# References

See also:
* https://wiki.openssl.org/index.php/Simple_TLS_Server
* https://wiki.openssl.org/index.php/SSL/TLS_Client

# Security Test

Check the server by running testssl.sh, easiest in docker (replace IP, if needed):
```
docker run --rm -ti drwetter/testssl.sh 10.200.0.1:4433
```
