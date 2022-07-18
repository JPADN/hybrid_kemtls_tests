#!/bin/bash
source config.sh

# Server exclusive flags
# -ipserver
# -http
# -kex
# -authserver
# -wrapdir

cd ..

go run launch_servers.go common.go parse_hybrid_root.go stats_tls.go stats_kemtls.go plot_functions.go \
-ipserver teste \
-wrapdir /home/jpadn1/projects/labsec/go_stuff/lego/.dev/certificates \
${MUTUAL_FLAGS}
