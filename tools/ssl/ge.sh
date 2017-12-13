#!/bin/sh

# Key considerations for algorithm "RSA" ≥ 2048-bit
openssl genrsa -out server_rsa.key 2048
openssl req -new -x509 -sha256 -key server_rsa.key -out server_rsa.crt -days 3650

# Key considerations for algorithm "ECDSA" ≥ secp384r1
# List ECDSA the supported curves (openssl ecparam -list_curves)
openssl ecparam -genkey -name secp384r1 -out server_ecdsa.key
openssl req -new -x509 -sha256 -key server_ecdsa.key -out server_ecdsa.crt -days 3650

