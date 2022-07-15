#!/bin/bash
source config.sh

# Client exclusive flags:
# -ipclient
# -ipserver

cd ..

go run launch_client.go common.go parse_hybrid_root.go stats_kemtls.go stats_tls.go plot_functions.go \
-ipclient 127.0.0.1 \
-ipserver teste \
${MUTUAL_FLAGS}
