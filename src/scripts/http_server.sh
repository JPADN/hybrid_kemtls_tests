#!/bin/bash
source config.sh

# HTTP server exclusive flags
# -http
# -kex
# -authserver

cd ..

go run launch_servers.go common.go parse_hybrid_root.go stats_tls.go stats_kemtls.go plot_functions.go \
-http \
-kex P256_HQC_128 \
-authserver P256_HQC_128 \
${MUTUAL_FLAGS}