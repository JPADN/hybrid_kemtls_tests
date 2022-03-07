package main

// Command to run: (similar as launch_client)

import (
	"crypto/liboqs_sig"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"log"
	"regexp"
	"sync"
)

var wg sync.WaitGroup

// wrapper function to start a server in each port
func startServerHybrid(serverMsg string, serverConfig *tls.Config, ipserver string, port string, isHTTP bool) {	
	if isHTTP {
		httpServer(serverConfig, port)
	} else {
		go testConnHybrid(serverMsg, serverMsg, serverConfig, serverConfig, "server", ipserver, port)
	}
	
}

func constructChain(secNum int) (rootCertX509 *x509.Certificate, intCACert *x509.Certificate, rootPriv interface{}) {

	if *hybridRoot {
		rootCertX509, rootPriv = constructHybridRoot(secNum)

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

	// Creating intermediate CA to sign the Server Certificate
	intCACert, intCAPriv := initCAs(rootCertX509, rootPriv, rootPriv.(*liboqs_sig.PrivateKey).SigId)

	return rootCertX509, intCACert, intCAPriv
}

func getSecurityLevel(k string) (level int) {
	// want same levels for the algos
	reLevel1 := regexp.MustCompile(`P256`)
	reLevel3 := regexp.MustCompile(`P384`)
	reLevel5 := regexp.MustCompile(`P521`)

	if reLevel1.MatchString(k) || k == "Kyber512" || k == "LightSaber_KEM" || k == "NTRU_HPS_2048_509" {
		return 1
	} else {
		if reLevel3.MatchString(k) || k == "Kyber768" || k == "Saber_KEM" || k == "NTRU_HPS_2048_677" || k == "NTRU_HRSS_701" {
			return 3
		} else {
			if reLevel5.MatchString(k) || k == "Kyber1024" || k == "FireSaber_KEM" || k == "NTRU_HPS_4096_821" || k == "NTRU_HPS_4096_1229" || k == "NTRU_HRSS_1373" {
				return 5
			} else {
				panic("Error when recovering NIST security level number.")
			}
		}
	}
}

func launchServer() {
	fmt.Println("Starting servers...")

	flag.Parse()

	port := 4433

	keysKEX, keysAuth := sortAlgorithmsMap()

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

			serverMsg := "hello, client"

			wg.Add(1)
			//start
			fmt.Println("Starting " + k + " Hybrid KEMTLS server at " + *IPserver + ":" + strport + "...")
			startServerHybrid(serverMsg, serverConfig, *IPserver, strport, true)

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

				serverMsg := "hello, client"

				wg.Add(1)
				//start
				fmt.Println(fmt.Sprintf("%v", i) + " Starting " + k + " Hybrid PQTLS " + kAuth + " server at " + *IPserver + ":" + strport + "...")

				startServerHybrid(serverMsg, serverConfig, *IPserver, strport, true)

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
