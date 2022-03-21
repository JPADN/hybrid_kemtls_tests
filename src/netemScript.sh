#!/bin/bash

#inform the number of handshakes

#This script assumes server previously executing. The delays and packet losses are at localhost
HANDSHAKE_NUMBER=$1


#First 1 ms
echo "\t\t\t\t\t\t\t\t Latency - 1ms"
sudo tc qdisc add dev lo root netem delay 1ms
/home/USER/go-kemtls/bin/go run launch_client.go plot_functions.go common.go -ip 127.0.0.1 -tlspeer client -handshakes $HANDSHAKE_NUMBER
#remove it
sudo tc qdisc delete dev lo root netem delay 1ms
# copy results
zip -q -r results-1ms.zip graphs kemtls-client.csv
mv results-1ms.zip ../../results-simulated/


#First 10 ms
echo "\t\t\t\t\t\t\t\t Latency - 5ms"
sudo tc qdisc add dev lo root netem delay 5ms
/home/USER/go-kemtls/bin/go run launch_client.go plot_functions.go common.go -ip 127.0.0.1 -tlspeer client -handshakes $HANDSHAKE_NUMBER
#remove it
sudo tc qdisc delete dev lo root netem delay 5ms
# copy results
zip -q -r results-5ms.zip graphs kemtls-client.csv
mv results-5ms.zip ../../results-simulated/


#First 100 ms
echo "\t\t\t\t\t\t\t\t Latency - 50ms"
sudo tc qdisc add dev lo root netem delay 50ms
/home/USER/go-kemtls/bin/go run launch_client.go plot_functions.go common.go -ip 127.0.0.1 -tlspeer client -handshakes $HANDSHAKE_NUMBER
#remove it
sudo tc qdisc delete dev lo root netem delay 50ms
# copy results
zip -q -r results-50ms.zip graphs kemtls-client.csv
mv results-50ms.zip ../../results-simulated/


#First 300 ms
echo "\t\t\t\t\t\t\t\t Latency - 150ms"
sudo tc qdisc add dev lo root netem delay 150ms
/home/USER/go-kemtls/bin/go run launch_client.go plot_functions.go common.go -ip 127.0.0.1 -tlspeer client -handshakes $HANDSHAKE_NUMBER
#remove it
sudo tc qdisc delete dev lo root netem delay 150ms
# copy results
zip -q -r results-150ms.zip graphs kemtls-client.csv
mv results-150ms.zip ../../results-simulated/


#400 ms
#echo "\t\t\t\t\t\t\t\t Latency - 400ms"
#sudo tc qdisc add dev lo root netem delay 400ms
#/home/USER/go-kemtls/bin/go run launch_client.go plot_functions.go common.go -ip 127.0.0.1 -tlspeer client -handshakes $HANDSHAKE_NUMBER
#remove it
#sudo tc qdisc delete dev lo root netem delay 400ms
# copy results
#zip -r results-400ms.zip graphs kemtls-client.csv
#mv results-400ms.zip ../../results-simulated/



######################################################### LOSS

#1%
echo "\t\t\t\t\t\t\t\t Loss - 1%"
sudo tc qdisc add dev lo root netem loss 1%
/home/USER/go-kemtls/bin/go run launch_client.go plot_functions.go common.go -ip 127.0.0.1 -tlspeer client -handshakes $HANDSHAKE_NUMBER
#remove it
sudo tc qdisc delete dev lo root netem loss 1%
# copy results
zip -q -r results-loss1p.zip graphs kemtls-client.csv 
mv results-loss1p.zip ../../results-simulated/


#3%
echo "\t\t\t\t\t\t\t\t Loss - 3%"
sudo tc qdisc add dev lo root netem loss 3%
/home/USER/go-kemtls/bin/go run launch_client.go plot_functions.go common.go -ip 127.0.0.1 -tlspeer client -handshakes $HANDSHAKE_NUMBER
#remove it
sudo tc qdisc delete dev lo root netem loss 3%
# copy results
zip -q -r results-loss3p.zip graphs kemtls-client.csv
mv results-loss3p.zip ../../results-simulated/

#5%
echo "\t\t\t\t\t\t\t\t Loss - 5%"
sudo tc qdisc add dev lo root netem loss 5%
/home/USER/go-kemtls/bin/go run launch_client.go plot_functions.go common.go -ip 127.0.0.1 -tlspeer client -handshakes $HANDSHAKE_NUMBER
#remove it
sudo tc qdisc delete dev lo root netem loss 5%
# copy results
zip -q -r results-loss5p.zip graphs kemtls-client.csv
mv results-loss5p.zip ../../results-simulated/

#10%
echo "\t\t\t\t\t\t\t\t Loss - 10%"
sudo tc qdisc add dev lo root netem loss 10%
/home/USER/go-kemtls/bin/go run launch_client.go plot_functions.go common.go -ip 127.0.0.1 -tlspeer client -handshakes $HANDSHAKE_NUMBER
#remove it
sudo tc qdisc delete dev lo root netem loss 10%
# copy results
zip -q -r results-loss10p.zip graphs kemtls-client.csv
mv results-loss10p.zip ../../results-simulated/

