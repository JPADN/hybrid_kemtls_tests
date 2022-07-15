#!/bin/bash
source config.sh

# Client exclusive flags:
# -ipclient
# -ipserver
# -wrapdir

cd ..

go run launch_client.go common.go parse_hybrid_root.go stats_kemtls.go stats_tls.go plot_functions.go \
-ipclient 127.0.0.1 \
-ipserver teste \
-wrapdir /home/jpadn/projects/lego/.dev/certificates \
${MUTUAL_FLAGS}
