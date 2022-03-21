package main

// Command to run: (similar as launch_client)

import (
	"crypto/tls"
	"flag"
	"fmt"
	"log"
	"regexp"
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
		httpServer(serverConfig, port)
	} else {
		go testConnHybrid(clientMsg, serverMsg, serverConfig, "server", ipserver, port)
	}
	
}

func launchServer() {
	fmt.Println("Starting servers...")

	flag.Parse()

	port := 4433

	var keysKEX, keysAuth []string

	if *isHTTP {
		keysKEX = []string{*kex}
		keysAuth = []string{*auth}
	} else {
		keysKEX, keysAuth = sortAlgorithmsMap()
	}

	reLevel1 := regexp.MustCompile(`P256`)
	reLevel3 := regexp.MustCompile(`P384`)
	reLevel5 := regexp.MustCompile(`P521`)

	securityLevelNum := 1
	securityLevelKauthNum := 1

	if !*pqtls {
		kemtlsInitCSVServer()
		//for each algo
		for _, k := range keysKEX {
			strport := fmt.Sprintf("%d", port)

			kexCurveID, err := nameToCurveID(k)
			if err != nil {
				log.Fatal(err)
			}

			authCurveID := kexCurveID

			securityLevelNum = getSecurityLevel(k)

			rootCertX509, intCACert, intCAPriv := constructChain(securityLevelNum)

			serverConfig := initServer(authCurveID, intCACert, intCAPriv, rootCertX509)

			// Select here the algorithm to be used in the KEX
			serverConfig.CurvePreferences = []tls.CurveID{kexCurveID}

			wg.Add(1)
			//start
			fmt.Println("Starting " + k + " Hybrid KEMTLS server at " + *IPserver + ":" + strport + "...")
			startServerHybrid(clientHSMsg, serverHSMsg, serverConfig, *IPserver, strport)

			port++
		}
	} else {

		i := 0
		pqtlsInitCSVServer()

		for _, kAuth := range keysAuth {

			for _, k := range keysKEX {
				strport := fmt.Sprintf("%d", port)

				kexCurveID, err := nameToCurveID(k)
				if err != nil {
					log.Fatal(err)
				}
				//fmt.Println(kAuth + " " + k)

				securityLevelNum = getSecurityLevel(k)
				securityLevelKauthNum = getSecurityLevel(kAuth)

				// auth in the same level
				if securityLevelNum != securityLevelKauthNum {
					continue
				}

				//only hybrids
				if !reLevel1.MatchString(k) && !reLevel3.MatchString(k) && !reLevel5.MatchString(k) {
					continue
				}
				if !reLevel1.MatchString(kAuth) && !reLevel3.MatchString(kAuth) && !reLevel5.MatchString(kAuth) {
					continue
				}

				authSigID := nameToHybridSigID(kAuth)

				rootCertX509, intCACert, intCAPriv := constructChain(securityLevelNum)

				serverConfig := initServer(authSigID, intCACert, intCAPriv, rootCertX509)

				// Select here the algorithm to be used in the KEX
				serverConfig.CurvePreferences = []tls.CurveID{kexCurveID}

				wg.Add(1)
				//start
				fmt.Println(fmt.Sprintf("%v", i) + " Starting " + k + " Hybrid PQTLS " + kAuth + " server at " + *IPserver + ":" + strport + "...")

				startServerHybrid(clientHSMsg, serverHSMsg, serverConfig, *IPserver, strport)

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
