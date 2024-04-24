#!/bin/bash

SERVER_IP=127.0.0.1
NUM_HANDSHAKES=1
HYBRID_ROOT=dilithium

cd ..

# Test 1.1: Hybrid KEMTLS
go run launch_client.go common.go parse_hybrid_root.go stats_kemtls.go stats_tls.go plot_functions.go \
-ipserver $SERVER_IP \
-handshakes $NUM_HANDSHAKES \
-hybridroot $HYBRID_ROOT

read -p "Enter para avançar para o próximo teste
" DUMMY_VAR

# Test 1.2: Hybrid PQTLS
go run launch_client.go common.go parse_hybrid_root.go stats_kemtls.go stats_tls.go plot_functions.go \
-ipserver $SERVER_IP \
-handshakes $NUM_HANDSHAKES \
-hybridroot $HYBRID_ROOT \
-pqtls

read -p "Enter para avançar para o próximo teste" DUMMY_VAR

# Test 2.1: Hybrid KEMTLS-PDK
go run launch_client.go common.go parse_hybrid_root.go stats_kemtls.go stats_tls.go plot_functions.go \
-ipserver $SERVER_IP \
-handshakes $NUM_HANDSHAKES \
-hybridroot $HYBRID_ROOT \
-cachedcert

read -p "Enter para avançar para o próximo teste" DUMMY_VAR

# Test 2.2: Hybrid KEMTLS-PDK Classic McEliece
go run launch_client.go common.go parse_hybrid_root.go stats_kemtls.go stats_tls.go plot_functions.go \
-ipserver $SERVER_IP \
-handshakes $NUM_HANDSHAKES \
-hybridroot $HYBRID_ROOT \
-cachedcert \
-classicmceliece

read -p "Enter para avançar para o próximo teste" DUMMY_VAR

# Test 2.3: Hybrid PQTLS Cached Certs
go run launch_client.go common.go parse_hybrid_root.go stats_kemtls.go stats_tls.go plot_functions.go \
-ipserver $SERVER_IP \
-handshakes $NUM_HANDSHAKES \
-hybridroot $HYBRID_ROOT \
-pqtls \
-cachedcert



