# Go executable path
GO="go"

# The following flags are common for the client and the server
# -handshakes -hybridroot -pqtls -clientauth -rootcert -rootkey

COMMON_FLAGS="-handshakes 10 -rootcert root_ca/root_cert_P256.pem -rootkey root_ca/root_key_P256.pem -pqtls"
# COMMON_FLAGS="-hybridroot -handshakes 10 -clientauth"

