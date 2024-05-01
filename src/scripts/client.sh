#!/bin/bash
source config.sh

cd ..

go run launch_client.go common.go parse_hybrid_root.go stats_kemtls.go stats_tls.go plot_functions.go \
${MUTUAL_FLAGS}
