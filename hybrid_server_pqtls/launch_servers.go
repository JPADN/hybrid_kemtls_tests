package main

//run with /.../go-kemtls/bin/go run launch_servers.go hybrid_server_kemtls.go

import (
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"log"
	"sync"
)

var wg sync.WaitGroup

//wrapper function to start a server in each port
func startServerHybrid(serverMsg string, serverConfig *tls.Config, ipserver string, port string) {
	//defer wg.Done()
	go testConnHybrid(serverMsg, serverMsg, serverConfig, serverConfig, "server", ipserver, port)
}

func launchPQTLSServer() {
	fmt.Println("Starting servers...")

	flag.Parse()

	port := 4433

	keysKEX, keysAuth := orderAlgorithmsMap()

	rootCertHybrid := new(tls.Certificate)
	var err error

	*rootCertHybrid, err = tls.X509KeyPair([]byte(rootCertPEMED25519Dilithim3), []byte(rootKeyPEMED25519Dilithium3))
	if err != nil {
		panic(err)
	}

	rootCertHybrid.Leaf, err = x509.ParseCertificate(rootCertHybrid.Certificate[0])
	if err != nil {
		panic(err)
	}

	/* ----------------------------------- End ---------------------------------- */

	for _, kAuth := range keysAuth {
		///authSigID := nameToHybridSigID(*authAlgo)
		rootSigID := nameToHybridSigID(*rootCAAlgo)
		intSigID := nameToHybridSigID(*intCAAlgo)

		_, intCACert, intCAPriv := initCAs(rootSigID, intSigID)

		for _, k := range keysKEX {
			strport := fmt.Sprintf("%d", port)
			kexCurveID, err := nameToCurveID(k)
			if err != nil {
				log.Fatal(err)
			}
			/* auth is the same here
			authCurveID, err := nameToCurveID(*authAlgo)
			if err != nil {
				log.Fatal(err)
			}*/
			authSigID := nameToHybridSigID(*authAlgo)

			/* -------------------------------- Modified -------------------------------- */
			serverConfig := initServer(authSigID, intCACert, intCAPriv)
			/* ----------------------------------- End ---------------------------------- */

			// Select here the algorithm to be used in the KEX
			serverConfig.CurvePreferences = []tls.CurveID{kexCurveID}

			serverMsg := "hello, client"

			wg.Add(1)
			//start
			fmt.Println("Starting " + k + " Hybrid PQTLS " + kAuth + " server at " + *IPserver + ":" + strport + "...")
			startServerHybrid(serverMsg, serverConfig, *IPserver, strport)

			port++
		}
	}

	wg.Wait() //endless but required
}

func main() {
	launchPQTLSServer()
}
