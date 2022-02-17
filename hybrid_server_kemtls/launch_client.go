package main

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
	stats	"tls_tests/hybrid_server_kemtls/statspqtls"
)

func main() {
	flag.Parse()

	var intCACert *x509.Certificate = nil
	var intCAPriv interface{} = nil

	clientMsg := "hello, server"

	port := 4433

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

	if *clientAuth {
		intSigAlgo := nameToHybridSigID(*intCAAlgo)
		
		// Creating intermediate CA to sign the Client Certificate
		intCACert, intCAPriv = initCAs(rootCertHybrid.Leaf, rootCertHybrid.PrivateKey, intSigAlgo)
	}

	//struct for the metrics
	var algoResults stats.ClientResultsInfo

	//list of structs
	var algoResultsList []stats.ClientResultsInfo

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
	stats.InitCSV()

	keysKEX, keysAuth := sortAlgorithmsMap()

	
	if !*pqtls {
	
		for _, k := range keysKEX {
		
		strport := fmt.Sprintf("%d", port)
		fmt.Println("\t\t\t\t\t\t\t\t" + k + ":" + strport)
		
		kexCurveID, err := nameToCurveID(k)		
		if err != nil {
			log.Fatal(err)
		}
		
		clientConfig := initClient(kexCurveID, intCACert, intCAPriv, rootCertHybrid.Leaf)

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
		stats.SaveCSV(timingsFullProtocol, timingsProcessServerHello, timingsWriteClientHello, timingsWriteKEMCiphertext, k, *handshakes)

		algoResults = stats.ComputeStats(timingsFullProtocol, timingsProcessServerHello, timingsWriteClientHello, timingsWriteKEMCiphertext, *handshakes)
		algoResults.KexName = k
		algoResults.AuthName = k

		algoResultsList = append(algoResultsList, algoResults)

		if re.MatchString(k) {
			//boxplot data for hybrids
			boxPlotValues = append(boxPlotValues, (timingsFullProtocol))
			kexNames = append(kexNames, k)
		}

		port++
	}
		
	//export results
	stats.ResultsExporter(algoResultsList, boxPlotValues, kexNames, *handshakes)
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
			
				clientConfig := initClient(authSig, intCACert, intCAPriv, rootCertHybrid.Leaf)

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
				stats.SaveCSV(timingsFullProtocol, timingsProcessServerHello, timingsWriteClientHello, nil, k, *handshakes)

				algoResults = stats.ComputeStats(timingsFullProtocol, timingsProcessServerHello, timingsWriteClientHello, nil, *handshakes)
				algoResults.KexName = k
				algoResults.AuthName = k

				algoResultsList = append(algoResultsList, algoResults)

				if re.MatchString(k) {
					//boxplot data for hybrids
					boxPlotValues = append(boxPlotValues, (timingsFullProtocol))
					kexNames = append(kexNames, k)
				}

				port++
			}
		}
		//	resultsExporter(algoResultsList, boxPlotValues, kexNames, *handshakes)
		fmt.Println("End of test.")
	}		
}
