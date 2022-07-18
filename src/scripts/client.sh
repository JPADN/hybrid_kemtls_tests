#!/bin/bash
source config.sh

# Client exclusive flags:
# -ipclient
# -ipserver

cd ..

go run launch_client.go common.go parse_hybrid_root.go stats_kemtls.go stats_tls.go plot_functions.go \
-ipclient 127.0.0.1 \
-ipserver teste \
-rootcert /home/jpadn1/projects/labsec/go_stuff/lego/.dev/certificates/ae9102b6d64604f2f7825b8e2f7adb2b49a319e96c0d8f7527e2a8de54050cd0fb31586f2b0cabfd51df5d7a00170573f7acc9941e2a7e634b85a9f7b3d5431fbfd563458eed6f00c340b7b1420fb69352843f468695b0a0598eb02e294875a32bf59c09d322052526dad5fe429018abdf/teste.crt \
${MUTUAL_FLAGS}
