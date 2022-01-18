package main

import (
	"crypto/kem"
	"crypto/tls"
	"flag"
	"fmt"
	"log"
)

func main() {
	flag.Parse()

	clientMsg := "hello, server"

	keys := sortAlgorithmsMap()

	port := 4433

	for _, k := range keys {
		strport := fmt.Sprintf("%d", port)
		fmt.Println("\t\t\t\t\t\t\t\t" + k + ":" + strport)
		kexCurveID, err := nameToCurveID(k)
		if err != nil {
			log.Fatal(err)
		}

		clientConfig := initClient()
		// Select here the algorithm to be used in the KEX
		clientConfig.CurvePreferences = []tls.CurveID{kexCurveID}

		fmt.Printf("Starting KEMTLS Handshakes: KEX Algorithm: %s (0x%x) - Auth Algorithm: %s (0x%x)\n",
			k, kem.ID(kexCurveID),
			k, kem.ID(kexCurveID)) //note: removed 'authCurveID'

		for i := 1; i < *handshakes; i++ {
			testConnHybrid(clientMsg, clientMsg, clientConfig, clientConfig, "client", *IPserver, strport)
		}
		port++
	}
}
