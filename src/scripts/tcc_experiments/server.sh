#!/bin/bash

SERVER_IP=127.0.0.1
NUM_HANDSHAKES=1000
BENCHMARK_REPS=1000
HYBRID_ROOT=dilithium

cd ../..

# KEMs and Signatures benchmark
go run bench.go common.go parse_hybrid_root.go stats_kemtls.go stats_tls.go \
-reps $BENCHMARK_REPS

# Test 1.1: Hybrid KEMTLS
go run launch_servers.go common.go parse_hybrid_root.go stats_tls.go stats_kemtls.go plot_functions.go \
-ipserver $SERVER_IP \
-handshakes $NUM_HANDSHAKES \
-hybridroot $HYBRID_ROOT

# Test 1.2: Hybrid PQTLS
go run launch_servers.go common.go parse_hybrid_root.go stats_tls.go stats_kemtls.go plot_functions.go \
-ipserver $SERVER_IP \
-handshakes $NUM_HANDSHAKES \
-hybridroot $HYBRID_ROOT \
-pqtls 

# Test 2.1: Hybrid KEMTLS-PDK
go run launch_servers.go common.go parse_hybrid_root.go stats_tls.go stats_kemtls.go plot_functions.go \
-ipserver $SERVER_IP \
-handshakes $NUM_HANDSHAKES \
-hybridroot $HYBRID_ROOT \
-cachedcert

# Test 2.2: Hybrid KEMTLS-PDK Classic McEliece
go run launch_servers.go common.go parse_hybrid_root.go stats_tls.go stats_kemtls.go plot_functions.go \
-ipserver $SERVER_IP \
-handshakes $NUM_HANDSHAKES \
-hybridroot $HYBRID_ROOT \
-cachedcert \
-classicmceliece

# Test 2.3: Hybrid PQTLS Cached Certs
go run launch_servers.go common.go parse_hybrid_root.go stats_tls.go stats_kemtls.go plot_functions.go \
-ipserver $SERVER_IP \
-handshakes $NUM_HANDSHAKES \
-hybridroot $HYBRID_ROOT \
-pqtls \
-cachedcert