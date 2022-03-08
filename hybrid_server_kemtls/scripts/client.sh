source config.sh

# Client flags:
# -ipclient

cd ..

${GO} run launch_client.go hybrid_server_kemtls.go parse_hybrid_root.go stats_kemtls.go stats_pqtls.go plot_functions.go -ipclient 127.0.0.1 ${COMMON_FLAGS}