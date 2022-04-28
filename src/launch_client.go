package main

import (
	"crypto/kem"
	"flag"
	"fmt"
	"log"
	"regexp"
	"time"
	"crypto/tls"

	"gonum.org/v1/plot/plotter"
)


func main() {
	flag.Parse()

	port := 4433
	
	var re *regexp.Regexp
	
	handshakeSizes := make(map[string]uint32)
	var cconnState tls.ConnectionState

	//boxPlot data
	if *pqtls {
		re = regexp.MustCompile(`P256`)
	} else {
		re = regexp.MustCompile(`P256|P384`)
	}

	var boxPlotValues []plotter.Values
	var kexNames []string
	var keysKEX, keysAuth []string

	//prepare output file
	if *pqtls || *classic {
		pqtlsInitCSV()
	} else {
		kemtlsInitCSV()
	}

	if *classic {
		keysKEX = testsClassicAlgorithms
		keysAuth = testsClassicAlgorithms
	} else {  // PQTLS and KEMTLS
		keysKEX = testsKEXAlgorithms
		keysAuth = testsAuthAlgorithms
	}

	if *classicMcEliece {
		keysKEX = append(keysKEX, "P256_Classic-McEliece-348864")
	}

	if !*pqtls && !*classic {

		// struct for the metrics
		var algoResults KEMTLSClientResultsInfo

		// list of structs
		var algoResultsList []KEMTLSClientResultsInfo

		for _, k := range keysKEX {

			var kAuth string
			
			if *classicMcEliece {
				kAuth = "P256_Classic-McEliece-348864"
			} else {
				kAuth = k
			}
			

			strport := fmt.Sprintf("%d", port)
			fmt.Println("\t\t\t\t\t\t\t\t" + k + ":" + strport)

			clientConfig, err := initClientAndAuth(k, kAuth)
			if err != nil {
				log.Fatal(err)
			}
			if clientConfig == nil {
				continue
			}

			fmt.Printf("Starting KEMTLS Handshakes: KEX Algorithm: %s (0x%x) - Auth Algorithm: %s (0x%x)\n",
				k, kem.ID(clientConfig.CurvePreferences[0]),
				kAuth, kem.ID(clientConfig.CurvePreferences[0]))

			var timingsFullProtocol []float64
			var timingsSendAppData []float64
			var timingsProcessServerHello []float64
			var timingsWriteClientHello []float64
			var timingsWriteKEMCiphertext []float64

			if *cachedCert {
				_, connState, err, _ := testConnHybrid(clientHSMsg, serverHSMsg, clientConfig, "client", *IPserver, strport)
				if err != nil {
					fmt.Println("Error establishing first connection for PDK mode:")
					log.Fatal(err)
				}
				clientConfig.CachedCert = connState.CertificateMessage
			}

			for i := 0; i < *handshakes; i++ {
				var timingState timingInfo
				var err error
				var success bool

				timingState, cconnState, err, success = testConnHybrid(clientHSMsg, serverHSMsg, clientConfig, "client", *IPserver, strport)
				if err != nil || success == false {
					//log.Fatal(err)
					i--
					continue //do not count this handshake timing
				}
				timingsFullProtocol = append(timingsFullProtocol, float64(timingState.clientTimingInfo.FullProtocol)/float64(time.Millisecond))
				timingsSendAppData = append(timingsSendAppData, float64(timingState.clientTimingInfo.SendAppData)/float64(time.Millisecond))
				timingsProcessServerHello = append(timingsProcessServerHello, float64(timingState.clientTimingInfo.ProcessServerHello)/float64(time.Millisecond))
				timingsWriteClientHello = append(timingsWriteClientHello, float64(timingState.clientTimingInfo.WriteClientHello)/float64(time.Millisecond))
				timingsWriteKEMCiphertext = append(timingsWriteKEMCiphertext, float64(timingState.clientTimingInfo.WriteKEMCiphertext)/float64(time.Millisecond))
			}

			handshakeSizes["ClientHello"] = cconnState.ClientHandshakeSizes.ClientHello			
			handshakeSizes["ClientKEMCiphertext"] = cconnState.ClientHandshakeSizes.ClientKEMCiphertext
			handshakeSizes["Certificate"] = cconnState.ClientHandshakeSizes.Certificate

			//save results first
			kemtlsSaveCSV(timingsFullProtocol, timingsSendAppData, timingsProcessServerHello, timingsWriteClientHello, timingsWriteKEMCiphertext, k, *handshakes, handshakeSizes)

			algoResults = kemtlsComputeStats(timingsFullProtocol, timingsSendAppData, timingsProcessServerHello, timingsWriteClientHello, timingsWriteKEMCiphertext, *handshakes)
			algoResults.kexName = k
			algoResults.authName = kAuth

			algoResultsList = append(algoResultsList, algoResults)

			if re.MatchString(k) {
				//boxplot data for hybrids
				boxPlotValues = append(boxPlotValues, (timingsFullProtocol))				
				kexNames = append(kexNames, k)

				// TODO: boxplot SendAppData data
			}

			port++
		}

		//export results
		kemtlsResultsExporter(algoResultsList, boxPlotValues, kexNames, *handshakes)
		fmt.Println("End of test.")

	} else {

		// struct for the metrics
		var algoResults PQTLSClientResultsInfo

		// list of structs
		var algoResultsList []PQTLSClientResultsInfo

		for _, kAuth := range keysAuth {

			for _, k := range keysKEX {

				strport := fmt.Sprintf("%d", port)

				clientConfig, err := initClientAndAuth(k, kAuth)
				if err != nil {
					log.Fatal(err)
				}
				if clientConfig == nil {
					continue
				}

				fmt.Printf("Starting PQTLS Handshakes: KEX Algorithm: %s - Auth Algorithm: %s \n",
					k, kAuth) //note: removed 'authCurveID'

				var timingsFullProtocol []float64
				var timingsProcessServerHello []float64
				var timingsWriteClientHello []float64
				//var timingsWriteKEMCiphertext []float64

				if *cachedCert {
					_, connState, err, _ := testConnHybrid(clientHSMsg, serverHSMsg, clientConfig, "client", *IPserver, strport)
					if err != nil {
						fmt.Println("Error establishing first connection for PQTLS (cached) mode:")
						log.Fatal(err)
					}
					clientConfig.CachedCert = connState.CertificateMessage
				}

				for i := 0; i < *handshakes; i++ {
					var timingState timingInfo
					var err error
					var success bool
					
					timingState, cconnState, err, success = testConnHybrid(clientHSMsg, serverHSMsg, clientConfig, "client", *IPserver, strport)
					if err != nil || success == false{
						//log.Fatal(err)
						i--
						continue
					}
					timingsFullProtocol = append(timingsFullProtocol, float64(timingState.clientTimingInfo.FullProtocol)/float64(time.Millisecond))
					timingsProcessServerHello = append(timingsProcessServerHello, float64(timingState.clientTimingInfo.ProcessServerHello)/float64(time.Millisecond))
					timingsWriteClientHello = append(timingsWriteClientHello, float64(timingState.clientTimingInfo.WriteClientHello)/float64(time.Millisecond))
					//timingsWriteKEMCiphertext = append(timingsWriteKEMCiphertext, float64(timingState.clientTimingInfo.WriteKEMCiphertext)/float64(time.Millisecond))
				}

				handshakeSizes["ClientHello"] = cconnState.ClientHandshakeSizes.ClientHello							
				handshakeSizes["Certificate"] = cconnState.ClientHandshakeSizes.Certificate
				handshakeSizes["CertificateVerify"] = cconnState.ClientHandshakeSizes.CertificateVerify

				//save results first
				pqtlsSaveCSV(timingsFullProtocol, timingsProcessServerHello, timingsWriteClientHello, k, kAuth, *handshakes, handshakeSizes)

				algoResults = pqtlsComputeStats(timingsFullProtocol, timingsProcessServerHello, timingsWriteClientHello, *handshakes)
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
		pqtlsResultsExporter(algoResultsList, boxPlotValues, kexNames, *handshakes)
		fmt.Println("End of test.")
	}
}
