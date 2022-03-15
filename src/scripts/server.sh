source config.sh

# Server exclusive flags
# -ipserver
# -http
# -kex
# -authserver

cd ..

go run launch_servers.go hybrid_server_kemtls.go parse_hybrid_root.go stats_pqtls.go stats_kemtls.go plot_functions.go \
-ipserver 127.0.0.1 \
${COMMON_FLAGS}
