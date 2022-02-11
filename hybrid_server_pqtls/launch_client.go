package main

import (
	"crypto/tls"
	"encoding/csv"
	"flag"
	"fmt"
	"log"
	"math"
	"os"
	"regexp"
	"time"

	"crypto/x509"

	"gonum.org/v1/plot/plotter"
)

type ClientResultsInfo struct {
	kexName                 string
	authName                string
	avgTotalTime            float64
	avgProcessServerHello   float64
	avgWriteClientHello     float64
	stdevTotalTime          float64
	stdevProcessServerHello float64
	stdevWriteClientHello   float64
}

//Stats: Avg, Stdev.
func computeStats(timingsFullProtocol []float64, timingsProcessServerHello []float64, timingsWriteClientHello []float64, hs int) (r ClientResultsInfo) {

	//counts
	var countTotalTime float64
	var countProcessServerHello float64
	var countWriteClientHello float64

	//Average
	countTotalTime, countProcessServerHello, countWriteClientHello = 0, 0, 0
	for i := 0; i < hs; i++ {
		countTotalTime += timingsFullProtocol[i]
		countProcessServerHello += timingsProcessServerHello[i]
		countWriteClientHello += timingsWriteClientHello[i]
	}

	r.avgTotalTime = (countTotalTime) / float64(hs)
	r.avgProcessServerHello = (countProcessServerHello) / float64(hs)
	r.avgWriteClientHello = (countWriteClientHello) / float64(hs)

	//stdev
	for i := 0; i < hs; i++ {
		r.stdevTotalTime += math.Pow(float64(timingsFullProtocol[i])-r.avgTotalTime, 2)
		r.stdevProcessServerHello += math.Pow(float64(timingsProcessServerHello[i])-r.avgProcessServerHello, 2)
		r.stdevWriteClientHello += math.Pow(float64(timingsWriteClientHello[i])-r.avgWriteClientHello, 2)
	}
	r.stdevTotalTime = math.Sqrt(r.stdevTotalTime / float64(hs))
	r.stdevProcessServerHello = math.Sqrt(r.stdevProcessServerHello / float64(hs))
	r.stdevWriteClientHello = math.Sqrt(r.stdevWriteClientHello / float64(hs))

	return r
}

//print results
func printStatistics(results []ClientResultsInfo) {
	//header
	fmt.Printf("%-23s | ", "TestName")
	fmt.Printf("%-20s | ", "AvgClientTotalTime")
	fmt.Printf("%-20s | ", "StdevClientTotalTime")
	fmt.Printf("%-20s | ", "AvgWrtCHelloTime")
	fmt.Printf("%-20s | ", "StdevWrtCHelloTime")
	fmt.Printf("%-20s | ", "AvgPrSHelloTime")
	fmt.Printf("%-20s | ", "StdevPrSHelloTime")

	for _, r := range results {
		//content
		fmt.Println()
		fmt.Printf("%-23s |", r.kexName)

		fmt.Printf(" %-20f |", r.avgTotalTime)
		fmt.Printf(" %-20f |", r.stdevTotalTime)
		fmt.Printf(" %-20f |", r.avgWriteClientHello)
		fmt.Printf(" %-20f |", r.stdevWriteClientHello)
		fmt.Printf(" %-20f |", r.avgProcessServerHello)
		fmt.Printf(" %-20f |", r.stdevProcessServerHello)
	}
}

func initCSV() {
	csvFile, err := os.Create("pqtls-client.csv")
	if err != nil {
		log.Fatalf("failed creating file: %s", err)
	}
	csvwriter := csv.NewWriter(csvFile)

	header := []string{"algo", "timingFullProtocol", "timingProcessServerHello", "timingWriteClientHello"}

	csvwriter.Write(header)
	csvwriter.Flush()
	csvFile.Close()
}

func saveCSV(timingsFullProtocol []float64, timingsProcessServerHello []float64, timingsWriteClientHello []float64, name string, hs int) {
	csvFile, err := os.OpenFile("pqtls-client.csv", os.O_APPEND|os.O_WRONLY, os.ModeAppend)
	if err != nil {
		log.Fatalf("failed opening file: %s", err)
	}

	csvwriter := csv.NewWriter(csvFile)

	for i := 0; i < hs; i++ {
		arrayStr := []string{name, fmt.Sprintf("%f", timingsFullProtocol[i]),
			fmt.Sprintf("%f", timingsProcessServerHello[i]),
			fmt.Sprintf("%f", timingsWriteClientHello[i]),
			fmt.Sprintf("%f", timingsProcessServerHello[i])}

		if err := csvwriter.Write(arrayStr); err != nil {
			log.Fatalln("error writing record to file", err)
		}
		csvwriter.Flush()
	}
	csvFile.Close()
}

func resultsExporter(results []ClientResultsInfo, boxPlotValues []plotter.Values, names []string, hs int) {
	printStatistics(results)
	//printHybridPenalty(results)
	/*	genbar(results, "Avg Completion Time - Client (ms)")
		genbar(results, "Avg Write Client Hello Time (ms)")
		genbar(results, "Avg Process Server Hello - Client (ms)")
		boxplot(names, boxPlotValues, hs)
		barMarkLines(results, "All")
		barMarkLines(results, "L1")*/
}

func main() {
	flag.Parse()

	clientMsg := "hello, server"

	port := 4433

	/* -------------------------------- Modified -------------------------------- */
	rootCertHybrid := new(tls.Certificate)
	var err error

	*rootCertHybrid, err = tls.X509KeyPair([]byte(rootCertPEMED25519Dilithim3), []byte(rootKeyPEMED25519Dilithium3))
	if err != nil {
		panic(err)
	}

	rootCertHybrid.Leaf, err = x509.ParseCertificate(rootCertHybrid.Certificate[0])
	if err != nil {
		panic(err)
	}
	/* ----------------------------------- End ---------------------------------- */

	//struct for the metrics
	var algoResults ClientResultsInfo

	//list of structs
	var algoResultsList []ClientResultsInfo

	//boxPlot data
	re := regexp.MustCompile(`P256`)
	var boxPlotValues []plotter.Values
	var kexNames []string

	//prepare output file
	initCSV()

	keysKEX, keysAuth := orderAlgorithmsMap()

	for _, kAuth := range keysAuth {
		//authSigID := nameToHybridSigID(kAuth)
		rootSigID := nameToHybridSigID(*rootCAAlgo)
		intSigID := nameToHybridSigID(*intCAAlgo)

		rootCACert, _, _ := initCAs(rootSigID, intSigID)

		for _, k := range keysKEX {
			strport := fmt.Sprintf("%d", port)
			fmt.Println("\t\t\t\t\t\t\t\t" + k + ":" + strport)
			kexCurveID, err := nameToCurveID(k)
			if err != nil {
				log.Fatal(err)
			}

			clientConfig := initClient(rootCACert)

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
			saveCSV(timingsFullProtocol, timingsProcessServerHello, timingsWriteClientHello, k, *handshakes)

			algoResults = computeStats(timingsFullProtocol, timingsProcessServerHello, timingsWriteClientHello, *handshakes)
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
	}

	//export results
	//	resultsExporter(algoResultsList, boxPlotValues, kexNames, *handshakes)
	fmt.Println("End of test.")
}
