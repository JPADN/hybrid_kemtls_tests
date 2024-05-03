package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"log"
	"os"
	"strconv"
	"sync"
)

var wg sync.WaitGroup

// Launches a temporary TLS server to be used by the gobench client in order to obtain the server certificate
// preliminarily to the HTTP load test
func launchTempServer(tlsConfig *tls.Config, clientMsg, serverMsg, port string) {	

	ln := newLocalListener(port)
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
func startServerHybrid(clientMsg, serverMsg string, serverConfig *tls.Config, port string) {	
	if *isHTTP {
		if *cachedCert {
			portInt, err := strconv.Atoi(port)
			if err != nil {
				panic(err)
			}

			portInt = portInt + 1
			portTemp := strconv.Itoa(portInt)

			launchTempServer(serverConfig, clientHSMsg, serverHSMsg, portTemp)
		}
		launchHTTPSServer(serverConfig, port)
	} else {
		go testConnHybrid(clientMsg, serverMsg, serverConfig, "server", "", port)
	}
	
}

func main() {
	fmt.Println("Starting servers...")	
	fmt.Printf("Process PID is %d\n\n", os.Getpid())
	
		
	flag.Parse()

	port := 4433

	var keysKEX, keysAuth []string

	if *isHTTP {
		keysKEX = []string{*kex}
		keysAuth = []string{*auth}
	} else {	
		keysKEX = testsKEXAlgorithms
		keysAuth = testsSignatureAlgorithms		
	}

	if !*pqtls {
		kemtlsInitCSVServer()
		
		for _, k := range keysKEX {
			strport := fmt.Sprintf("%d", port)

			var kAuth string

			if *classicMcEliece {
				secLevel := getSecurityLevel(k)				
				kAuth = classicMcElieceAlgorithmsPerSecLevel[secLevel]				
			} else if *isHTTP && *auth != "" {
				kAuth = *auth
			} else {
				kAuth = k
			}

			serverConfig, err := initConfigurationAndCertChain(k, kAuth, false)
			if err != nil {
				log.Fatal(err)
			}
			if serverConfig == nil {
				continue
			}
			
			//start		
			fmt.Printf("Starting Hybrid KEMTLS server at %s:%s  |  KEX: %s  Auth: %s\n", *IPserver, strport, k, kAuth)
			
			startServerHybrid(clientHSMsg, serverHSMsg, serverConfig, strport)

			port++
		}
	} else {
		tlsInitCSVServer()

		for _, kAuth := range keysAuth {

			for _, k := range keysKEX {
				strport := fmt.Sprintf("%d", port)
				
				serverConfig, err := initConfigurationAndCertChain(k, kAuth, false)
				if err != nil {
					log.Fatal(err)
				}
				if serverConfig == nil {
					continue
				}

				//start
				fmt.Printf("Starting Hybrid PQTLS server at %s:%s  |  KEX: %s  Auth: %s\n", *IPserver, strport, k, kAuth)

				startServerHybrid(clientHSMsg, serverHSMsg, serverConfig, strport)

				port++
			}
		}
	}

	if *synchronize {		
		if *isHTTP {
			waitNotification("FINISHED", serverNotificationPort)		
		} else {
			notify("SERVERS ARE READY", *IPclient, clientNotificationPort)
			waitNotification("FINISHED", serverNotificationPort)					
		}	
  } else {
		wg.Add(1)
		wg.Wait()
	}
}

