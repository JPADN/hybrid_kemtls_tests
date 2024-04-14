#!/bin/bash
source config.sh

# gobench exclusive flags
# -benchkex
# -benchauth
# -u
# -t
# -k
# -c
# -r
# -f
# -d
# -tw
# -tr
# -auth

cd ..

go run gobench.go common.go parse_hybrid_root.go stats_tls.go stats_kemtls.go plot_functions.go \
-benchkex P256_HQC_128 \
-benchauth P256_HQC_128 \
-u https://127.0.0.1:4433 \
-c 100 \
-t 10 \
${MUTUAL_FLAGS}
