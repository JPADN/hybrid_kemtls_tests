#!/bin/bash

#inform the number of handshakes, then 'true' or 'false' for PQTLS and CLIENTAUTH

#The delays and packet losses are at localhost
HANDSHAKE_NUMBER=$1
PQTLS=$2
CLIENTAUTH=$3

cd ..

## Create a build
GOKEMTLSPATH=/home/user/go-kemtls/bin/go       
$GOKEMTLSPATH build launch_servers.go common.go parse_hybrid_root.go stats_tls.go stats_kemtls.go plot_functions.go
$GOKEMTLSPATH build launch_client.go common.go parse_hybrid_root.go stats_kemtls.go stats_tls.go plot_functions.go 


## Start - Latency Variations
for i in 1 5 50 150; do
    echo "\t\t\t\t\t\t\t\t --------- Latency ${i} ms..."
    #Create rule
    sudo tc qdisc add dev lo root netem delay ${i}ms
    ./launch_servers -ipserver 127.0.0.1 -ipclient 127.0.0.1 -hybridroot dilithium -cachedcert=false -http=false -handshakes $HANDSHAKE_NUMBER -pqtls=$PQTLS -clientauth=$CLIENTAUTH &
    sleep 5
    ./launch_client -ipserver 127.0.0.1 -ipclient 127.0.0.1  -hybridroot dilithium -cachedcert=false -handshakes $HANDSHAKE_NUMBER -pqtls=$PQTLS -clientauth=$CLIENTAUTH 
    killall ./launch_servers
    #remove it
    sudo tc qdisc delete dev lo root netem delay ${i}ms
    # copy results
    if [ $PQTLS ]
    then
        zip -q -r results-pqtls-${i}ms.zip graphs csv/pqtls-client.csv csv/pqtls-server.csv
        mv results-pqtls-${i}ms.zip ../../results-simulated/
    else
        zip -q -r results-kemtls-${i}ms.zip graphs csv/kemtls-client.csv csv/kemtls-server.csv
        mv results-kemtls-${i}ms.zip ../../results-simulated/
    fi
done

######################################################### LOSS

## Start - Latency Variations
for i in 1 2 3 5; do
    echo "\t\t\t\t\t\t\t\t Loss - ${i}%"
    #Create rule    
    sudo tc qdisc add dev lo root netem loss ${i}%
    ./launch_servers -ipserver 127.0.0.1 -ipclient 127.0.0.1 -hybridroot dilithium -cachedcert=false -http=false -handshakes $HANDSHAKE_NUMBER -pqtls=$PQTLS -clientauth=$CLIENTAUTH &
    sleep 5
    ./launch_client -ipserver 127.0.0.1 -ipclient 127.0.0.1  -hybridroot dilithium -cachedcert=false -handshakes $HANDSHAKE_NUMBER -pqtls=$PQTLS -clientauth=$CLIENTAUTH 
    killall ./launch_servers
    #remove it
    sudo tc qdisc delete dev lo root netem loss ${i}%
    # copy results
    if [ $PQTLS ]
    then
        zip -q -r results-pqtls-loss${i}p.zip graphs csv/pqtls-client.csv csv/pqtls-server.csv
        mv results-pqtls-loss${i}p.zip ../../results-simulated/
    else
        zip -q -r results-kemtls-loss${i}p.zip graphs csv/kemtls-client.csv csv/kemtls-server.csv
        mv results-kemtls-loss${i}p.zip ../../results-simulated/
    fi
done

echo "End of netem testing. CSV resuls at ../../results-simulated/."