#!/bin/bash
source ../config.sh

cd ../../..

if $EXP_HYBRID_KEMTLS; then
  printf "\nExperiment: Hybrid KEMTLS\n\n"
  # Test 1.1: Hybrid KEMTLS
  go run launch_client.go common.go parse_hybrid_root.go stats_kemtls.go stats_tls.go plot_functions.go \
  -ipserver $SERVER_IP \
  -ipclient $CLIENT_IP \
  -handshakes $NUM_HANDSHAKES \
  -hybridroot $HYBRID_ROOT
fi

if $EXP_HYBRID_PQTLS; then
  printf "\nExperiment: Hybrid PQTLS\n\n"
  # Test 1.2: Hybrid PQTLS
  go run launch_client.go common.go parse_hybrid_root.go stats_kemtls.go stats_tls.go plot_functions.go \
  -ipserver $SERVER_IP \
  -ipclient $CLIENT_IP \
  -handshakes $NUM_HANDSHAKES \
  -hybridroot $HYBRID_ROOT \
  -pqtls
fi

if $EXP_HYBRID_KEMTLS_PDK; then
  printf "\nExperiment: Hybrid KEMTLS-PDK\n\n"
  # Test 2.1: Hybrid KEMTLS-PDK
  go run launch_client.go common.go parse_hybrid_root.go stats_kemtls.go stats_tls.go plot_functions.go \
  -ipserver $SERVER_IP \
  -ipclient $CLIENT_IP \
  -handshakes $NUM_HANDSHAKES \
  -hybridroot $HYBRID_ROOT \
  -cachedcert  
fi

if $EXP_HYBRID_KEMTLS_PDK_CLASSIC_MCELIECE; then
  printf "\nExperiment: Hybrid KEMTLS-PDK with Classic-McEliece\n\n"
  # Test 2.2: Hybrid KEMTLS-PDK Classic McEliece
  go run launch_client.go common.go parse_hybrid_root.go stats_kemtls.go stats_tls.go plot_functions.go \
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
  go run launch_client.go common.go parse_hybrid_root.go stats_kemtls.go stats_tls.go plot_functions.go \
  -ipserver $SERVER_IP \
  -ipclient $CLIENT_IP \
  -handshakes $NUM_HANDSHAKES \
  -hybridroot $HYBRID_ROOT \
  -pqtls \
  -cachedcert
fi

if $EXP_HYBRID_KEMTLS_LOAD_TEST; then
  printf "\nExperiment: Hybrid KEMTLS Load test\n\n"
  # Clean results file
  rm -f csv/load_test_kemtls.csv
  for NUM_CLIENTS in ${NUM_CLIENTS_LIST[*]}
  do  
    sleep 3s
    go run gobench.go common.go parse_hybrid_root.go stats_tls.go stats_kemtls.go plot_functions.go \
    -benchkex P256_HQC_128 \
    -benchauth P256_HQC_128 \
    -u https://${SERVER_IP}:4433 \
    -ipclient $CLIENT_IP \
    -c $NUM_CLIENTS \
    -t $LOAD_TEST_SECONDS \
    -hybridroot $HYBRID_ROOT
    
    sleep 3s
    go run gobench.go common.go parse_hybrid_root.go stats_tls.go stats_kemtls.go plot_functions.go \
    -benchkex P256_BIKE_L1 \
    -benchauth P256_BIKE_L1 \
    -u https://${SERVER_IP}:4433 \
    -ipclient $CLIENT_IP \
    -c $NUM_CLIENTS \
    -t $LOAD_TEST_SECONDS \
    -hybridroot $HYBRID_ROOT
  done
fi

if $EXP_HYBRID_KEMTLS_PDK_LOAD_TEST; then
  printf "\nExperiment: Hybrid KEMTLS-PDK Load test\n\n"  
  rm -f csv/load_test_kemtls_pdk.csv
  for NUM_CLIENTS in ${NUM_CLIENTS_LIST[*]}
  do
    sleep 3s
    go run gobench.go common.go parse_hybrid_root.go stats_tls.go stats_kemtls.go plot_functions.go \
    -benchkex P256_HQC_128 \
    -benchauth P256_HQC_128 \
    -u https://${SERVER_IP}:4433 \
    -ipclient $CLIENT_IP \
    -c $NUM_CLIENTS \
    -t $LOAD_TEST_SECONDS \
    -hybridroot $HYBRID_ROOT \
    -cachedcert

    sleep 3s
    go run gobench.go common.go parse_hybrid_root.go stats_tls.go stats_kemtls.go plot_functions.go \
    -benchkex P256_BIKE_L1 \
    -benchauth P256_BIKE_L1 \
    -u https://${SERVER_IP}:4433 \
    -ipclient $CLIENT_IP \
    -c $NUM_CLIENTS \
    -t $LOAD_TEST_SECONDS \
    -hybridroot $HYBRID_ROOT \
    -cachedcert

    # Classic McEliece
    sleep 3s
    go run gobench.go common.go parse_hybrid_root.go stats_tls.go stats_kemtls.go plot_functions.go \
    -benchkex P256_HQC_128 \
    -benchauth P256_Classic_McEliece_348864 \
    -u https://${SERVER_IP}:4433 \
    -ipclient $CLIENT_IP \
    -c $NUM_CLIENTS \
    -t $LOAD_TEST_SECONDS \
    -hybridroot $HYBRID_ROOT \
    -cachedcert \
    -classicmceliece

    sleep 3s
    go run gobench.go common.go parse_hybrid_root.go stats_tls.go stats_kemtls.go plot_functions.go \
    -benchkex P256_BIKE_L1 \
    -benchauth P256_Classic_McEliece_348864 \
    -u https://${SERVER_IP}:4433 \
    -ipclient $CLIENT_IP \
    -c $NUM_CLIENTS \
    -t $LOAD_TEST_SECONDS \
    -hybridroot $HYBRID_ROOT \
    -cachedcert \
    -classicmceliece
  done
fi

if $EXP_HYBRID_PQTLS_LOAD_TEST; then
  printf "\nExperiment: Hybrid PQTLS Load test\n\n"  
  rm -f csv/load_test_pqtls.csv
  for NUM_CLIENTS in ${NUM_CLIENTS_LIST[*]}
  do
    sleep 3s
    go run gobench.go common.go parse_hybrid_root.go stats_tls.go stats_kemtls.go plot_functions.go \
    -benchkex P256_HQC_128 \
    -benchauth P256_Dilithium2 \
    -u https://${SERVER_IP}:4433 \
    -ipclient $CLIENT_IP \
    -c $NUM_CLIENTS \
    -t $LOAD_TEST_SECONDS \
    -hybridroot $HYBRID_ROOT \
    -pqtls

    sleep 3s
    go run gobench.go common.go parse_hybrid_root.go stats_tls.go stats_kemtls.go plot_functions.go \
    -benchkex P256_BIKE_L1 \
    -benchauth P256_Dilithium2 \
    -u https://${SERVER_IP}:4433 \
    -ipclient $CLIENT_IP \
    -c $NUM_CLIENTS \
    -t $LOAD_TEST_SECONDS \
    -hybridroot $HYBRID_ROOT \
    -pqtls
  done
fi

if $EXP_HYBRID_PQTLS_CACHED_CERT_LOAD_TEST; then
  printf "\nExperiment: Hybrid PQTLS cached cert Load test\n\n"
  rm -f csv/load_test_pqtls_cached_cert.csv
  for NUM_CLIENTS in ${NUM_CLIENTS_LIST[*]}
  do
    sleep 3s
    go run gobench.go common.go parse_hybrid_root.go stats_tls.go stats_kemtls.go plot_functions.go \
    -benchkex P256_HQC_128 \
    -benchauth P256_Dilithium2 \
    -u https://${SERVER_IP}:4433 \
    -ipclient $CLIENT_IP \
    -c $NUM_CLIENTS \
    -t $LOAD_TEST_SECONDS \
    -hybridroot $HYBRID_ROOT \
    -pqtls \
    -cachedcert

    sleep 3s
    go run gobench.go common.go parse_hybrid_root.go stats_tls.go stats_kemtls.go plot_functions.go \
    -benchkex P256_BIKE_L1 \
    -benchauth P256_Dilithium2 \
    -u https://${SERVER_IP}:4433 \
    -ipclient $CLIENT_IP \
    -c $NUM_CLIENTS \
    -t $LOAD_TEST_SECONDS \
    -hybridroot $HYBRID_ROOT \
    -pqtls \
    -cachedcert
  done
fi


