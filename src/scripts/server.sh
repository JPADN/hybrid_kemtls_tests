#!/bin/bash
source config.sh

cd ..

go run launch_servers.go common.go parse_hybrid_root.go stats_tls.go stats_kemtls.go plot_functions.go \
${MUTUAL_FLAGS}