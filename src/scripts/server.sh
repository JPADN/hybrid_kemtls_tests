#!/bin/bash
source config.sh

# Server exclusive flags
# -ipserver
# -http
# -kex
# -authserver

cd ..

go run launch_servers.go common.go parse_hybrid_root.go stats_tls.go stats_kemtls.go plot_functions.go \
-ipserver teste \
${MUTUAL_FLAGS}
