#!/bin/bash

HYBRID_ALGS=(P256_Dilithium2 P256_Falcon512 P384_Dilithium3 P521_Dilithium5 P521_Falcon1024)
CLASSIC_ALGS=(P256 P384 P521)

cd ..

for algo in ${HYBRID_ALGS[*]}
do
go run generate_root.go common.go stats_tls.go stats_kemtls.go plot_functions.go parse_hybrid_root.go \
-algo ${algo}
done

for algo in ${CLASSIC_ALGS[*]}
do
go run generate_root.go common.go stats_tls.go stats_kemtls.go plot_functions.go parse_hybrid_root.go \
-algo ${algo} \
-classic
done