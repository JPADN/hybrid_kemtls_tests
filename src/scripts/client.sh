source config.sh

# Client exclusive flags:
# -ipclient
# -ipserver

cd ..

go run launch_client.go common.go parse_hybrid_root.go stats_kemtls.go stats_pqtls.go plot_functions.go \
-ipclient 127.0.0.1 \
-ipserver 127.0.0.1 \
${MUTUAL_FLAGS}