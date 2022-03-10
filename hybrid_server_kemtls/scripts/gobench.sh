source config.sh

# gobench additional flags (regarding gobench original flags):
# -kex
# -authalgo

cd ..
go run gobench.go hybrid_server_kemtls.go parse_hybrid_root.go stats_pqtls.go stats_kemtls.go plot_functions.go -k=true -u https://127.0.0.1:4433 -c 10 -t 5 -kex P521_NTRU_HPS_4096_1229 -authalgo P521_Falcon1024 ${COMMON_FLAGS}