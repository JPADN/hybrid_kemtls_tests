#!/bin/bash

# The following flags are mutual for the client and the server
# -pqtls 
# -clientauth 
# -handshakes 
# -hybridroot
# -cachedcert
# -classicmceliece
# -ipserver
# -ipclient

CLIENT_IP=127.0.0.1
SERVER_IP=127.0.0.1

MUTUAL_FLAGS="-ipclient ${CLIENT_IP} -ipserver ${SERVER_IP} -handshakes 5 -hybridroot dilithium"
