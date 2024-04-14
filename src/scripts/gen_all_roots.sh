#!/bin/bash

HYBRID_ALGS=(P256_Dilithium2 P384_Dilithium3 P521_Dilithium5)

cd ..

for algo in ${HYBRID_ALGS[*]}
do
go run generate_root.go common.go stats_tls.go stats_kemtls.go plot_functions.go parse_hybrid_root.go \
-algo ${algo}
done