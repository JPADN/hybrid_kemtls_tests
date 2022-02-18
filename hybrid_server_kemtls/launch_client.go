package main

// Run with:
// go run launch_client.go hybrid_server_kemtls.go parse_hybrid_root.go client_stats_kemtls.go plot_functions.go -ip 127.0.0.1 -tlspeer client -handshakes 10


import (
	"crypto/kem"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"log"
	"regexp"
	"time"	
	"gonum.org/v1/plot/plotter"
)

func main() {
	flag.Parse()

	var intCACert *x509.Certificate = nil
	var intCAPriv interface{} = nil

	clientMsg := "hello, server"

	port := 4433	

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


	if *clientAuth {
		intSigAlgo := nameToHybridSigID(*intCAAlgo)
		
		// Creating intermediate CA to sign the Client Certificate
		intCACert, intCAPriv = initCAs(rootCertX509, rootPriv, intSigAlgo)
	}

	//struct for the metrics
	var algoResults ClientResultsInfo

	//list of structs
	var algoResultsList []ClientResultsInfo

	var re *regexp.Regexp
	
	//boxPlot data
	if *pqtls {
		re = regexp.MustCompile(`P256`)
	} else {
		re = regexp.MustCompile(`P256|P384`)
	}

	var boxPlotValues []plotter.Values
	var kexNames []string

	//prepare output file
	initCSV()

	keysKEX, keysAuth := sortAlgorithmsMap()

	
	if !*pqtls {
	
		for _, k := range keysKEX {
		
		strport := fmt.Sprintf("%d", port)
		fmt.Println("\t\t\t\t\t\t\t\t" + k + ":" + strport)
		
		kexCurveID, err := nameToCurveID(k)		
		if err != nil {
			log.Fatal(err)
		}
		
		clientConfig := initClient(kexCurveID, intCACert, intCAPriv, rootCertX509)

		// Select here the algorithm to be used in the KEX
		clientConfig.CurvePreferences = []tls.CurveID{kexCurveID}

		fmt.Printf("Starting KEMTLS Handshakes: KEX Algorithm: %s (0x%x) - Auth Algorithm: %s (0x%x)\n",
			k, kem.ID(kexCurveID),
			k, kem.ID(kexCurveID)) //note: removed 'authCurveID'

		var timingsFullProtocol []float64
		var timingsProcessServerHello []float64
		var timingsWriteClientHello []float64
		var timingsWriteKEMCiphertext []float64

		for i := 0; i < *handshakes; i++ {
			timingState, _, err := testConnHybrid(clientMsg, clientMsg, clientConfig, clientConfig, "client", *IPserver, strport)
			if err != nil {
				log.Fatal(err)
			}
			timingsFullProtocol = append(timingsFullProtocol, float64(timingState.clientTimingInfo.FullProtocol)/float64(time.Millisecond))
			timingsProcessServerHello = append(timingsProcessServerHello, float64(timingState.clientTimingInfo.ProcessServerHello)/float64(time.Millisecond))
			timingsWriteClientHello = append(timingsWriteClientHello, float64(timingState.clientTimingInfo.WriteClientHello)/float64(time.Millisecond))
			timingsWriteKEMCiphertext = append(timingsWriteKEMCiphertext, float64(timingState.clientTimingInfo.WriteKEMCiphertext)/float64(time.Millisecond))
		}

		//save results first
		saveCSV(timingsFullProtocol, timingsProcessServerHello, timingsWriteClientHello, timingsWriteKEMCiphertext, k, *handshakes)

		algoResults = computeStats(timingsFullProtocol, timingsProcessServerHello, timingsWriteClientHello, timingsWriteKEMCiphertext, *handshakes)
		algoResults.kexName = k
		algoResults.authName = k

		algoResultsList = append(algoResultsList, algoResults)

		if re.MatchString(k) {
			//boxplot data for hybrids
			boxPlotValues = append(boxPlotValues, (timingsFullProtocol))
			kexNames = append(kexNames, k)
		}

		port++
	}
		
	//export results
	resultsExporter(algoResultsList, boxPlotValues, kexNames, *handshakes)
	fmt.Println("End of test.")
	
	} else {

		// Remove later
		keysAuth = []string{"P521_Falcon1024"}

		for _, kAuth := range keysAuth {
			
			for _, k := range keysKEX {
			
				strport := fmt.Sprintf("%d", port)
			
				fmt.Println("\t\t\t\t\t\t\t\t" + k + ":" + strport)
			
				kexCurveID, err := nameToCurveID(k)					
				if err != nil {
					log.Fatal(err)
				}

				authSig := nameToHybridSigID(kAuth)
			
				clientConfig := initClient(authSig, intCACert, intCAPriv, rootCertX509)

				// Select here the algorithm to be used in the KEX
				clientConfig.CurvePreferences = []tls.CurveID{kexCurveID}

				fmt.Printf("Starting PQTLS Handshakes: KEX Algorithm: %s - Auth Algorithm: %s \n",
						k, kAuth) //note: removed 'authCurveID'

				var timingsFullProtocol []float64
				var timingsProcessServerHello []float64
				var timingsWriteClientHello []float64
					//var timingsWriteKEMCiphertext []float64

				for i := 0; i < *handshakes; i++ {
					timingState, _, err := testConnHybrid(clientMsg, clientMsg, clientConfig, clientConfig, "client", *IPserver, strport)
					if err != nil {
						log.Fatal(err)
					}
					timingsFullProtocol = append(timingsFullProtocol, float64(timingState.clientTimingInfo.FullProtocol)/float64(time.Millisecond))
					timingsProcessServerHello = append(timingsProcessServerHello, float64(timingState.clientTimingInfo.ProcessServerHello)/float64(time.Millisecond))
					timingsWriteClientHello = append(timingsWriteClientHello, float64(timingState.clientTimingInfo.WriteClientHello)/float64(time.Millisecond))
						//timingsWriteKEMCiphertext = append(timingsWriteKEMCiphertext, float64(timingState.clientTimingInfo.WriteKEMCiphertext)/float64(time.Millisecond))
				}

				//save results first
				saveCSV(timingsFullProtocol, timingsProcessServerHello, timingsWriteClientHello, k, kAuth, *handshakes)

				algoResults = computeStats(timingsFullProtocol, timingsProcessServerHello, timingsWriteClientHello, nil, *handshakes)
				algoResults.kexName = k
				algoResults.authName = kAuth

				algoResultsList = append(algoResultsList, algoResults)

				if re.MatchString(k) {
					//boxplot data for hybrids
					boxPlotValues = append(boxPlotValues, (timingsFullProtocol))
					kexNames = append(kexNames, k)
				}

				port++
			}
		}
		resultsExporter(algoResultsList, boxPlotValues, kexNames, *handshakes)
		fmt.Println("End of test.")
	}		
}
