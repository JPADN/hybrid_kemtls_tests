package main

// Run with:
// go run launch_client.go hybrid_server_kemtls.go parse_hybrid_root.go stats_kemtls.go stats_pqtls.go plot_functions.go -ip 127.0.0.1 -tlspeer client -handshakes 10

import (
	"crypto/kem"
	"crypto/tls"
	"flag"
	"fmt"
	"log"
	"regexp"
	"time"

	"gonum.org/v1/plot/plotter"
)


func main() {
	flag.Parse()

	clientMsg := "hello, server"

	port := 4433

	securityLevelNum := 1
	securityLevelKauthNum := 1
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
	if *pqtls {
		pqtlsInitCSV()
	} else {
		kemtlsInitCSV()
	}

	keysKEX, keysAuth := sortAlgorithmsMap()

	var reLevel1, reLevel3, reLevel5 *regexp.Regexp
	if *pqtls {
		//want same levels for the algos
		reLevel1 = regexp.MustCompile(`P256`)
		reLevel3 = regexp.MustCompile(`P384`)
		reLevel5 = regexp.MustCompile(`P521`)
	}

	if !*pqtls {

		// struct for the metrics
		var algoResults KEMTLSClientResultsInfo

		// list of structs
		var algoResultsList []KEMTLSClientResultsInfo

		for _, k := range keysKEX {

			strport := fmt.Sprintf("%d", port)
			fmt.Println("\t\t\t\t\t\t\t\t" + k + ":" + strport)

			kexCurveID, err := nameToCurveID(k)
			if err != nil {
				log.Fatal(err)
			}

			securityLevelNum = getSecurityLevel(k)

			rootCertX509, intCACert, intCAPriv := constructChain(securityLevelNum)

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

			if *cachedCert {
				_, _, connState, err := testConnHybrid(clientMsg, clientMsg, clientConfig, clientConfig, "client", *IPclient, strport)
				if err != nil {
					fmt.Println("Error establishing first connection for PDK mode:")
					log.Fatal(err)
				}
				clientConfig.CachedCert = connState.CertificateMessage
			}

			for i := 0; i < *handshakes; i++ {
				timingState, _, _, err := testConnHybrid(clientMsg, clientMsg, clientConfig, clientConfig, "client", *IPclient, strport)
				if err != nil {
					log.Fatal(err)
				}
				timingsFullProtocol = append(timingsFullProtocol, float64(timingState.clientTimingInfo.FullProtocol)/float64(time.Millisecond))
				timingsProcessServerHello = append(timingsProcessServerHello, float64(timingState.clientTimingInfo.ProcessServerHello)/float64(time.Millisecond))
				timingsWriteClientHello = append(timingsWriteClientHello, float64(timingState.clientTimingInfo.WriteClientHello)/float64(time.Millisecond))
				timingsWriteKEMCiphertext = append(timingsWriteKEMCiphertext, float64(timingState.clientTimingInfo.WriteKEMCiphertext)/float64(time.Millisecond))
			}

			//save results first
			kemtlsSaveCSV(timingsFullProtocol, timingsProcessServerHello, timingsWriteClientHello, timingsWriteKEMCiphertext, k, *handshakes)

			algoResults = kemtlsComputeStats(timingsFullProtocol, timingsProcessServerHello, timingsWriteClientHello, timingsWriteKEMCiphertext, *handshakes)
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

				//only hybrids
				if !reLevel1.MatchString(k) && !reLevel3.MatchString(k) && !reLevel5.MatchString(k) {
					continue
				}
				if !reLevel1.MatchString(kAuth) && !reLevel3.MatchString(kAuth) && !reLevel5.MatchString(kAuth) {
					continue
				}

				rootCertX509, intCACert, intCAPriv := constructChain(securityLevelNum)
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

				if *cachedCert {
					_, _, connState, err := testConnHybrid(clientMsg, clientMsg, clientConfig, clientConfig, "client", *IPclient, strport)
					if err != nil {
						fmt.Println("Error establishing first connection for PQTLS (cached) mode:")
						log.Fatal(err)
					}
					clientConfig.CachedCert = connState.CertificateMessage
				}

				for i := 0; i < *handshakes; i++ {
					timingState, _, _, err := testConnHybrid(clientMsg, clientMsg, clientConfig, clientConfig, "client", *IPclient, strport)
					if err != nil {
						log.Fatal(err)
					}
					timingsFullProtocol = append(timingsFullProtocol, float64(timingState.clientTimingInfo.FullProtocol)/float64(time.Millisecond))
					timingsProcessServerHello = append(timingsProcessServerHello, float64(timingState.clientTimingInfo.ProcessServerHello)/float64(time.Millisecond))
					timingsWriteClientHello = append(timingsWriteClientHello, float64(timingState.clientTimingInfo.WriteClientHello)/float64(time.Millisecond))
					//timingsWriteKEMCiphertext = append(timingsWriteKEMCiphertext, float64(timingState.clientTimingInfo.WriteKEMCiphertext)/float64(time.Millisecond))
				}

				//save results first
				pqtlsSaveCSV(timingsFullProtocol, timingsProcessServerHello, timingsWriteClientHello, k, kAuth, *handshakes)

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
