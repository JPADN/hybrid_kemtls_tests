package main

//run with /.../go-kemtls/bin/go run launch_servers.go hybrid_server_kemtls.go

import (
	"crypto/tls"
	"flag"
	"fmt"
	"log"
	"sync"
	"crypto/x509"
)

var wg sync.WaitGroup

//wrapper function to start a server in each port
func startServerHybrid(serverMsg string, serverConfig *tls.Config, ipserver string, port string) {
	//defer wg.Done()
	go testConnHybrid(serverMsg, serverMsg, serverConfig, serverConfig, "server", ipserver, port)
}

func launchServer() {
	fmt.Println("Starting servers...")

	flag.Parse()

	port := 4433

	keysKEX, keysAuth := sortAlgorithmsMap()

	rootCertHybrid := new(tls.Certificate)
	var err error

	*rootCertHybrid, err = tls.X509KeyPair([]byte(rootCert), []byte(rootKey))
	if err != nil {
		panic(err)
	}

	rootCertHybrid.Leaf, err = x509.ParseCertificate(rootCertHybrid.Certificate[0])
	if err != nil {
		panic(err)
	}

	intSigAlgo := nameToHybridSigID(*intCAAlgo)

	// Creating intermediate CA to sign the Server Certificate
	intCACert, intCAPriv := initCAs(rootCertHybrid.Leaf, rootCertHybrid.PrivateKey, intSigAlgo)

	if !*pqtls {
		//for each algo
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

			authCurveID := kexCurveID

			serverConfig := initServer(authCurveID, intCACert, intCAPriv, rootCertHybrid.Leaf)
			
			// Select here the algorithm to be used in the KEX
			serverConfig.CurvePreferences = []tls.CurveID{kexCurveID}

			serverMsg := "hello, client"

			wg.Add(1)
			//start
			fmt.Println("Starting " + k + " Hybrid KEMTLS server at " + *IPserver + ":" + strport + "...")
			startServerHybrid(serverMsg, serverConfig, *IPserver, strport)

			port++
		}	
	}	else {

		for _, kAuth := range keysAuth {

			for _, k := range keysKEX {
				strport := fmt.Sprintf("%d", port)
				
				kexCurveID, err := nameToCurveID(k)
				if err != nil {
					log.Fatal(err)
				}
				
				authSigID := nameToHybridSigID(kAuth)

				serverConfig := initServer(authSigID, intCACert, intCAPriv, rootCertHybrid.Leaf)
			
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
	}

	wg.Wait() //endless but required
}
	

func main() {
	launchServer()
}
