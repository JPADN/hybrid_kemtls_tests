package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"log"
	"os"
	"time"
)

func main() {
	flag.Parse()

	if *synchronize {
		waitNotification("SERVERS ARE READY", clientNotificationPort)
	}
	
	fmt.Println("Starting clients...")
	fmt.Printf("Process PID is %d\n", os.Getpid())

	port := 4433
		
	handshakeSizes := make(map[string]uint32)
	var cconnState tls.ConnectionState

	var keysKEX, keysAuth []string

	//prepare output file
	if *pqtls {
		tlsInitCSV()
	} else {
		kemtlsInitCSV()
	}

	keysKEX = testsKEXAlgorithms
	keysAuth = testsSignatureAlgorithms

	// if *classicMcEliece {
	// 	keysKEX = append(keysKEX, "P256_Classic-McEliece-348864")
	// }

	if !*pqtls {

		// struct for the metrics
		var algoResults KEMTLSClientResultsInfo

		// list of structs
		var algoResultsList []KEMTLSClientResultsInfo

		for _, k := range keysKEX {

			var kAuth string
			
			if *classicMcEliece {
				secLevel := getSecurityLevel(k)				
				kAuth = classicMcElieceAlgorithmsPerSecLevel[secLevel]		
			} else {
				kAuth = k
			}
			

			strport := fmt.Sprintf("%d", port)


			clientConfig, err := initConfigurationAndCertChain(k, kAuth, true)
			if err != nil {
				log.Fatal(err)
			}
			if clientConfig == nil {
				continue
			}

			fmt.Printf("Starting KEMTLS Handshakes: KEX: %s  Auth: %s\n", k, kAuth,)

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
			handshakeSizes["Finished"] = cconnState.ClientHandshakeSizes.Finished

			//save results first
			kemtlsSaveCSV(timingsFullProtocol, timingsSendAppData, timingsProcessServerHello, timingsWriteClientHello, timingsWriteKEMCiphertext, k, kAuth, *handshakes, handshakeSizes)

			algoResults = kemtlsComputeStats(timingsFullProtocol, timingsSendAppData, timingsProcessServerHello, timingsWriteClientHello, timingsWriteKEMCiphertext, *handshakes)
			algoResults.kexName = k
			algoResults.authName = kAuth

			algoResultsList = append(algoResultsList, algoResults)
			port++
		}

		kemtlsPrintStatistics(algoResultsList)
		fmt.Println("End of test.")

	} else {

		// struct for the metrics
		var algoResults TLSClientResultsInfo

		// list of structs
		var algoResultsList []TLSClientResultsInfo

		for _, kAuth := range keysAuth {

			for _, k := range keysKEX {

				strport := fmt.Sprintf("%d", port)

				clientConfig, err := initConfigurationAndCertChain(k, kAuth, true)
				if err != nil {
					log.Fatal(err)
				}
				if clientConfig == nil {
					continue
				}

				fmt.Printf("Starting TLS Handshakes: KEX Algorithm: %s - Auth Algorithm: %s \n", k, kAuth)

				var timingsFullProtocol []float64
				var timingsProcessServerHello []float64
				var timingsWriteClientHello []float64
				//var timingsWriteKEMCiphertext []float64

				if *cachedCert {
					_, connState, err, _ := testConnHybrid(clientHSMsg, serverHSMsg, clientConfig, "client", *IPserver, strport)
					if err != nil {
						fmt.Println("Error establishing first connection for TLS (cached) mode:")
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
				handshakeSizes["Finished"] = cconnState.ClientHandshakeSizes.Finished

				//save results first
				tlsSaveCSV(timingsFullProtocol, timingsProcessServerHello, timingsWriteClientHello, k, kAuth, *handshakes, handshakeSizes)

				algoResults = tlsComputeStats(timingsFullProtocol, timingsProcessServerHello, timingsWriteClientHello, *handshakes)
				algoResults.kexName = k
				algoResults.authName = kAuth

				algoResultsList = append(algoResultsList, algoResults)
				port++
			}
		}
		tlsPrintStatistics(algoResultsList)
		fmt.Println("End of test.")
	}

	if *synchronize {
		notify("FINISHED", *IPserver, serverNotificationPort)    
  }
}
