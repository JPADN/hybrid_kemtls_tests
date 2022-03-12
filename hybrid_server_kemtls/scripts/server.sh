source config.sh

# Server flags
# - ipserver
# - http

cd ..

go run launch_servers.go hybrid_server_kemtls.go parse_hybrid_root.go stats_pqtls.go stats_kemtls.go plot_functions.go -ipserver 127.0.0.1 -http ${COMMON_FLAGS}