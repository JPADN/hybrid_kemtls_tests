package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"log"
	"sync"
	"strconv"
)

var wg sync.WaitGroup

// Launches a temporary TLS server to be used by the gobench client in order to obtain the server certificate
// preliminarily to the HTTP load test
func launchTempServer(tlsConfig *tls.Config, clientMsg, serverMsg, ipserver, port string) {	

	ln := newLocalListener(ipserver, port)
	defer ln.Close()

	serverConn, err := ln.Accept()
	if err != nil {
		fmt.Println(err)		
	}
	server := tls.Server(serverConn, tlsConfig)
	if err := server.Handshake(); err != nil {
		fmt.Printf("Handshake error %v\n", err)
	}		

	err = server.Close()
	if err != nil {
		fmt.Println(err)
	}
}

// wrapper function to start a server in each port
func startServerHybrid(clientMsg, serverMsg string, serverConfig *tls.Config, ipserver string, port string) {	
	if *isHTTP {
		if *cachedCert {
			portInt, err := strconv.Atoi(port)
			if err != nil {
				panic(err)
			}

			portInt = portInt + 1
			portTemp := strconv.Itoa(portInt)

			launchTempServer(serverConfig, clientHSMsg, serverHSMsg, ipserver, portTemp)
		}
		launchHTTPSServer(serverConfig, port)
	} else {
		go testConnHybrid(clientMsg, serverMsg, serverConfig, "server", ipserver, port)
	}
	
}

func main() {
	fmt.Println("Starting servers...")

	flag.Parse()

	port := 4433

	var keysKEX, keysAuth []string

	if *isHTTP {
		keysKEX = []string{*kex}
		keysAuth = []string{*auth}
	} else {	
		keysKEX = testsKEXAlgorithms
		keysAuth = testsSignatureAlgorithms
		if *classicMcEliece {
			keysKEX = append(keysKEX, "P256_Classic-McEliece-348864")
		}
	}

	securityLevelNum := 1
	securityLevelKauthNum := 1

	if !*pqtls {
		kemtlsInitCSVServer()
		
		for _, k := range keysKEX {
			strport := fmt.Sprintf("%d", port)

			kexCurveID, err := nameToCurveID(k)
			if err != nil {
				log.Fatal(err)
			}

			var authCurveID tls.CurveID

			if *classicMcEliece {
				authCurveID = tls.P256_Classic_McEliece_348864
			} else {
				authCurveID = kexCurveID
			}

			if *isHTTP {
				if *auth != "" {
					authCurveID, err = nameToCurveID(*auth)
					if err != nil {
						panic(err)
					}
				} else {
					authCurveID = kexCurveID	
				}				
			} else {
				authCurveID = kexCurveID
			}
			
			securityLevelNum = getSecurityLevel(k)

			rootCertX509, intCACert, intCAPriv := constructChain(securityLevelNum)

			serverConfig := initServer(authCurveID, intCACert, intCAPriv, rootCertX509)

			// Select here the algorithm to be used in the KEX
			serverConfig.CurvePreferences = []tls.CurveID{kexCurveID}

			wg.Add(1)
			
			//start		
			fmt.Printf("Starting Hybrid KEMTLS server at %s:%s  |  KEX: %s  Auth: %s\n", *IPserver, strport, k, k)
			
			startServerHybrid(clientHSMsg, serverHSMsg, serverConfig, *IPserver, strport)

			port++
		}
	} else {
		tlsInitCSVServer()

		for _, kAuth := range keysAuth {

			for _, k := range keysKEX {
				strport := fmt.Sprintf("%d", port)

				kexCurveID, err := nameToCurveID(k)
				if err != nil {
					log.Fatal(err)
				}

				securityLevelNum = getSecurityLevel(k)
				securityLevelKauthNum = getSecurityLevel(kAuth)

				// auth in the same level
				if securityLevelNum != securityLevelKauthNum {
					continue
				}

				authSigID := nameToSigID(kAuth)

				rootCertX509, intCACert, intCAPriv := constructChain(securityLevelNum)

				serverConfig := initServer(authSigID, intCACert, intCAPriv, rootCertX509)

				// Select here the algorithm to be used in the KEX
				serverConfig.CurvePreferences = []tls.CurveID{kexCurveID}

				wg.Add(1)
				//start

				fmt.Printf("Starting Hybrid TLS server at %s:%s  |  KEX: %s  Auth: %s", *IPserver, strport, k, kAuth)

				startServerHybrid(clientHSMsg, serverHSMsg, serverConfig, *IPserver, strport)

				port++
			}
		}
	}

	wg.Wait() //endless but required
}

