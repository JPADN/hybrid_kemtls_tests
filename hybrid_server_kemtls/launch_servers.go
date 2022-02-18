package main

// Command to run:
// go run launch_servers.go hybrid_server_kemtls.go parse_hybrid_root.go 

import (
	"crypto/tls"	
	"crypto/x509"	
	"flag"
	"fmt"
	"log"
	"sync"
	"regexp"
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

	//want same levels for the algos
	reLevel1 := regexp.MustCompile(`P256`)
	reLevel3 := regexp.MustCompile(`P384`)
	reLevel5 := regexp.MustCompile(`P521`)
	
	var rootCertX509 *x509.Certificate
	var rootPriv interface{}

	if *hybridRoot {
		rootCertX509, rootPriv = constructHybridRoot()
	
	} else {

		tempRootCertTLS, err := tls.X509KeyPair([]byte(rootCert), []byte(rootKey))
		if err != nil {
			panic(err)
		}

		rootCertX509, err = x509.ParseCertificate(tempRootCertTLS.Certificate[0])
		if err != nil {
			panic(err)
		}

		rootPriv = tempRootCertTLS.PrivateKey
	}

	
	intSigAlgo := nameToHybridSigID(*intCAAlgo)

	// Creating intermediate CA to sign the Server Certificate
	intCACert, intCAPriv := initCAs(rootCertX509, rootPriv, intSigAlgo)

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

			serverConfig := initServer(authCurveID, intCACert, intCAPriv, rootCertX509)
			
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

		i := 0

		for _, kAuth := range keysAuth {

			for _, k := range keysKEX {
				strport := fmt.Sprintf("%d", port)
				
				kexCurveID, err := nameToCurveID(k)
				if err != nil {
					log.Fatal(err)
				}

				// auth in the same level
				if reLevel1.MatchString(kAuth) && !reLevel1.MatchString(k) {
					continue
				}
				if reLevel3.MatchString(kAuth) && !reLevel3.MatchString(k) {
					continue
				}
				if reLevel5.MatchString(kAuth) && !reLevel5.MatchString(k) {
					continue
				}
				
				authSigID := nameToHybridSigID(kAuth)

				serverConfig := initServer(authSigID, intCACert, intCAPriv, rootCertX509)
			
				// Select here the algorithm to be used in the KEX
				serverConfig.CurvePreferences = []tls.CurveID{kexCurveID}

				serverMsg := "hello, client"

				wg.Add(1)
				//start
				fmt.Println(fmt.Sprintf("%v", i) + " Starting " + k + " Hybrid PQTLS " + kAuth + " server at " + *IPserver + ":" + strport + "...")

				startServerHybrid(serverMsg, serverConfig, *IPserver, strport)

				port++
				i++
			}
		}	
	}

	wg.Wait() //endless but required
}
	

func main() {
	launchServer()
}
