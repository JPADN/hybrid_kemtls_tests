#!/bin/bash
source config.sh

cd ../..


if $EXP_HYBRID_KEMTLS; then
  printf "\nExperiment: Hybrid KEMTLS\n\n"
  # Test 1.1: Hybrid KEMTLS
  go run launch_servers.go common.go parse_hybrid_root.go stats_tls.go stats_kemtls.go plot_functions.go \
  -ipserver $SERVER_IP \
  -ipclient $CLIENT_IP \
  -handshakes $NUM_HANDSHAKES \
  -hybridroot $HYBRID_ROOT
fi

if $EXP_HYBRID_PQTLS; then
  printf "\nExperiment: Hybrid PQTLS\n\n"
  # Test 1.2: Hybrid PQTLS
  go run launch_servers.go common.go parse_hybrid_root.go stats_tls.go stats_kemtls.go plot_functions.go \
  -ipserver $SERVER_IP \
  -ipclient $CLIENT_IP \
  -handshakes $NUM_HANDSHAKES \
  -hybridroot $HYBRID_ROOT \
  -pqtls
fi

if $EXP_HYBRID_KEMTLS_PDK; then
  printf "\nExperiment: Hybrid KEMTLS-PDK\n\n"
  # Test 2.1: Hybrid KEMTLS-PDK
  go run launch_servers.go common.go parse_hybrid_root.go stats_tls.go stats_kemtls.go plot_functions.go \
  -ipserver $SERVER_IP \
  -ipclient $CLIENT_IP \
  -handshakes $NUM_HANDSHAKES \
  -hybridroot $HYBRID_ROOT \
  -cachedcert
fi

if $EXP_HYBRID_KEMTLS_PDK_CLASSIC_MCELIECE; then
  printf "\nExperiment: Hybrid KEMTLS-PDK with Classic-McEliece\n\n"
  # Test 2.2: Hybrid KEMTLS-PDK Classic McEliece
  go run launch_servers.go common.go parse_hybrid_root.go stats_tls.go stats_kemtls.go plot_functions.go \
  -ipserver $SERVER_IP \
  -ipclient $CLIENT_IP \
  -handshakes $NUM_HANDSHAKES \
  -hybridroot $HYBRID_ROOT \
  -cachedcert \
  -classicmceliece
fi

if $EXP_HYBRID_PQTLS_CACHED_CERTS; then
  printf "\nExperiment: Hybrid PQTLS with cached certificates\n\n"
  # Test 2.3: Hybrid PQTLS Cached Certs
  go run launch_servers.go common.go parse_hybrid_root.go stats_tls.go stats_kemtls.go plot_functions.go \
  -ipserver $SERVER_IP \
  -ipclient $CLIENT_IP \
  -handshakes $NUM_HANDSHAKES \
  -hybridroot $HYBRID_ROOT \
  -pqtls \
  -cachedcert
fi

if $EXP_HYBRID_KEMTLS_LOAD_TEST; then
  printf "\nExperiment: Hybrid KEMTLS Load test\n\n"
  for NUM_CLIENTS in ${NUM_CLIENTS_LIST[*]}
  do  
    go run launch_servers.go common.go parse_hybrid_root.go stats_tls.go stats_kemtls.go plot_functions.go \
    -ipserver $SERVER_IP \
    -ipclient $CLIENT_IP \
    -hybridroot $HYBRID_ROOT \
    -http \
    -kex P256_HQC_128 \
    -authserver P256_HQC_128

    go run launch_servers.go common.go parse_hybrid_root.go stats_tls.go stats_kemtls.go plot_functions.go \
    -ipserver $SERVER_IP \
    -ipclient $CLIENT_IP \
    -hybridroot $HYBRID_ROOT \
    -http \
    -kex P256_BIKE_L1 \
    -authserver P256_BIKE_L1
  done
fi


if $EXP_HYBRID_KEMTLS_PDK_LOAD_TEST; then
  printf "\nExperiment: Hybrid KEMTLS-PDK Load test\n\n"  
  for NUM_CLIENTS in ${NUM_CLIENTS_LIST[*]}
  do 
    go run launch_servers.go common.go parse_hybrid_root.go stats_tls.go stats_kemtls.go plot_functions.go \
    -ipserver $SERVER_IP \
    -ipclient $CLIENT_IP \
    -hybridroot $HYBRID_ROOT \
    -http \
    -kex P256_HQC_128 \
    -authserver P256_HQC_128 \
    -cachedcert

    go run launch_servers.go common.go parse_hybrid_root.go stats_tls.go stats_kemtls.go plot_functions.go \
    -ipserver $SERVER_IP \
    -ipclient $CLIENT_IP \
    -hybridroot $HYBRID_ROOT \
    -http \
    -kex P256_BIKE_L1 \
    -authserver P256_BIKE_L1 \
    -cachedcert

    # Classic McEliece
    go run launch_servers.go common.go parse_hybrid_root.go stats_tls.go stats_kemtls.go plot_functions.go \
    -ipserver $SERVER_IP \
    -ipclient $CLIENT_IP \
    -hybridroot $HYBRID_ROOT \
    -http \
    -kex P256_HQC_128 \
    -authserver P256_Classic_McEliece_348864 \
    -cachedcert \
    -classicmceliece

    go run launch_servers.go common.go parse_hybrid_root.go stats_tls.go stats_kemtls.go plot_functions.go \
    -ipserver $SERVER_IP \
    -ipclient $CLIENT_IP \
    -hybridroot $HYBRID_ROOT \
    -http \
    -kex P256_BIKE_L1 \
    -authserver P256_Classic_McEliece_348864 \
    -cachedcert \
    -classicmceliece

  done
fi


if $EXP_HYBRID_PQTLS_LOAD_TEST; then
  printf "\nExperiment: Hybrid PQTLS Load test\n\n"  
  for NUM_CLIENTS in ${NUM_CLIENTS_LIST[*]}
  do
    go run launch_servers.go common.go parse_hybrid_root.go stats_tls.go stats_kemtls.go plot_functions.go \
    -ipserver $SERVER_IP \
    -ipclient $CLIENT_IP \
    -hybridroot $HYBRID_ROOT \
    -http \
    -kex P256_HQC_128 \
    -authserver P256_Dilithium2 \
    -pqtls

    go run launch_servers.go common.go parse_hybrid_root.go stats_tls.go stats_kemtls.go plot_functions.go \
    -ipserver $SERVER_IP \
    -ipclient $CLIENT_IP \
    -hybridroot $HYBRID_ROOT \
    -http \
    -kex P256_BIKE_L1 \
    -authserver P256_Dilithium2 \
    -pqtls
  done
fi

if $EXP_HYBRID_PQTLS_CACHED_CERT_LOAD_TEST; then  
  printf "\nExperiment: Hybrid PQTLS cached cert Load test\n\n"  
  for NUM_CLIENTS in ${NUM_CLIENTS_LIST[*]}
  do  
    go run launch_servers.go common.go parse_hybrid_root.go stats_tls.go stats_kemtls.go plot_functions.go \
    -ipserver $SERVER_IP \
    -ipclient $CLIENT_IP \
    -hybridroot $HYBRID_ROOT \
    -http \
    -kex P256_HQC_128 \
    -authserver P256_Dilithium2 \
    -pqtls \
    -cachedcert
    
    go run launch_servers.go common.go parse_hybrid_root.go stats_tls.go stats_kemtls.go plot_functions.go \
    -ipserver $SERVER_IP \
    -ipclient $CLIENT_IP \
    -hybridroot $HYBRID_ROOT \
    -http \
    -kex P256_BIKE_L1 \
    -authserver P256_Dilithium2 \
    -pqtls \
    -cachedcert
  done
fi

if $EXP_BENCHMARK; then
  printf "\nExperiment: Hybrid KEMs and Hybrid Signatures Benchmark\n\n"
  # KEMs and Signatures benchmark
  go run bench.go common.go parse_hybrid_root.go stats_kemtls.go stats_tls.go \
  -reps $BENCHMARK_REPS
fi