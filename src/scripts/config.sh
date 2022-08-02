#!/bin/bash

# The following flags are mutual for the client and the server
# -classic
# -pqtls 
# -clientauth 
# -handshakes 
# -rootcert 
# -rootkey 
# -hybridroot
# -cachedcert
# -classicmceliece



MUTUAL_FLAGS="-hybridroot dilithium -handshakes 10 -cachedcert"
