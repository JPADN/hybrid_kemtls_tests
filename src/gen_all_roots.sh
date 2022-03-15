ALGS=(P256_Dilithium2 P256_Falcon512 P384_Dilithium3 P521_Dilithium5 P521_Falcon1024 P256 P384 P521)

cd ..

for dir in ${ALGS[*]}
do
go run generate_root.go hybrid_server_kemtls.go stats_pqtls.go stats_kemtls.go plot_functions.go parse_hybrid_root.go \
-algo ${dir}
done