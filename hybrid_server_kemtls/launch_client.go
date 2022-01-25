package main

import (
	"crypto/kem"
	"crypto/tls"
	"encoding/csv"
	"flag"
	"fmt"
	"log"
	"math"
	"os"
	"time"

	"gonum.org/v1/plot/plotter"
	"crypto/x509"
)

type ClientResultsInfo struct {
	kexName                 string
	authName                string
	avgTotalTime            float64
	avgWriteKEMCiphertext   float64
	avgProcessServerHello   float64
	avgWriteClientHello     float64
	stdevTotalTime          float64
	stdevWriteKEMCiphertext float64
	stdevProcessServerHello float64
	stdevWriteClientHello   float64
}

//Stats: Avg, Stdev.
func computeStats(timingsFullProtocol []float64, timingsProcessServerHello []float64, timingsWriteClientHello []float64, timingsWriteKEMCiphertext []float64, hs int) (r ClientResultsInfo) {

	//counts
	var countTotalTime float64
	var countProcessServerHello float64
	var countWriteClientHello float64
	var countWriteKEMCiphertext float64

	//Average
	countTotalTime, countProcessServerHello, countWriteClientHello, countWriteKEMCiphertext = 0, 0, 0, 0
	for i := 0; i < hs; i++ {
		countTotalTime += timingsFullProtocol[i]
		countProcessServerHello += timingsProcessServerHello[i]
		countWriteClientHello += timingsWriteClientHello[i]
		countWriteKEMCiphertext += timingsWriteKEMCiphertext[i]
	}

	r.avgTotalTime = (countTotalTime) / float64(hs)
	r.avgProcessServerHello = (countProcessServerHello) / float64(hs)
	r.avgWriteClientHello = (countWriteClientHello) / float64(hs)
	r.avgWriteKEMCiphertext = (countWriteKEMCiphertext) / float64(hs)

	//stdev
	for i := 0; i < hs; i++ {
		r.stdevTotalTime += math.Pow(float64(timingsFullProtocol[i])-r.avgTotalTime, 2)
		r.stdevProcessServerHello += math.Pow(float64(timingsProcessServerHello[i])-r.avgProcessServerHello, 2)
		r.stdevWriteClientHello += math.Pow(float64(timingsWriteClientHello[i])-r.avgWriteClientHello, 2)
		r.stdevWriteKEMCiphertext += math.Pow(float64(timingsWriteKEMCiphertext[i])-r.avgWriteKEMCiphertext, 2)
	}
	r.stdevTotalTime = math.Sqrt(r.stdevTotalTime / float64(hs))
	r.stdevProcessServerHello = math.Sqrt(r.stdevProcessServerHello / float64(hs))
	r.stdevWriteClientHello = math.Sqrt(r.stdevWriteClientHello / float64(hs))
	r.stdevWriteKEMCiphertext = math.Sqrt(r.stdevWriteKEMCiphertext / float64(hs))

	return r
}

//print results
func printStatistics(results []ClientResultsInfo) {
	//header
	fmt.Print("TestName\t| AvgClientTotalTime | StdevClientTotalTime |")
	fmt.Print("AvgWrtCHelloTime | StdevWrtCHelloTime |")
	fmt.Print("AvgPrSHelloTime | StdevPrSHelloTime |")
	fmt.Println("AvgWrtKEMCtTime | StdevWrtKEMCtTime")

	for _, r := range results {
		//content
		fmt.Print(r.kexName + "\t|")
		fmt.Printf(" %f\t     | %f\t\t    |", r.avgTotalTime, r.stdevTotalTime)
		fmt.Printf(" %f\t      | %f\t   |", r.avgWriteClientHello, r.stdevWriteClientHello)
		fmt.Printf(" %f\t    | %f\t        |", r.avgProcessServerHello, r.stdevProcessServerHello)
		fmt.Printf(" %f\t | %f\n", r.avgWriteKEMCiphertext, r.stdevWriteKEMCiphertext)

		/*fmt.Printf("Avg Client Total Time           | Stdev Client Total Time \n\t\t %f\t|\t%f\t\n", r.avgTotalTime, r.stdevTotalTime)
		fmt.Printf("Avg Write Client Hello Time     | Stdev Write Client Hello Time \n\t\t %f\t|\t%f\t\n", r.avgWriteClientHello, r.stdevWriteClientHello)
		fmt.Printf("Avg Process Server Hello Time   | Stdev Process Server Hello Time \n\t\t %f\t|\t%f\t\n", r.avgProcessServerHello, r.stdevProcessServerHello)
		fmt.Printf("Avg Write KEM Ciphertext Time   | Stdev Write KEM Ciphertext Time \n\t\t %f\t|\t%f\t\n", r.avgWriteKEMCiphertext, r.stdevWriteKEMCiphertext)*/
	}
}

func initCSV() {
	csvFile, err := os.Create("kemtls-client.csv")
	if err != nil {
		log.Fatalf("failed creating file: %s", err)
	}
	csvwriter := csv.NewWriter(csvFile)

	header := []string{"algo", "timingFullProtocol", "timingProcessServerHello", "timingWriteClientHello", "timingWriteKEMCiphertext"}

	csvwriter.Write(header)
	csvwriter.Flush()
	csvFile.Close()
}

//func saveCSV(boxPlotValues []plotter.Values, names []string, hs int) {
func saveCSV(timingsFullProtocol []float64, timingsProcessServerHello []float64, timingsWriteClientHello []float64, timingsWriteKEMCiphertext []float64, name string, hs int) {
	csvFile, err := os.OpenFile("kemtls-client.csv", os.O_APPEND|os.O_WRONLY, os.ModeAppend)
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
	genbar(results, "Avg Completion Time - Client (ms)")
	genbar(results, "Avg Write Client Hello Time (ms)")
	genbar(results, "Avg Process Server Hello - Client (ms)")
	genbar(results, "Avg Write KEM Ciphertext - Client (ms)")
	boxplot(names, boxPlotValues, hs)
}

func main() {
	flag.Parse()

	clientMsg := "hello, server"

	port := 4433

	/* -------------------------------- Modified -------------------------------- */
	rootCertP256 := new(tls.Certificate)
	var err error

	*rootCertP256, err = tls.X509KeyPair([]byte(rootCertPEMP256), []byte(rootKeyPEMP256))
		if err != nil {
			panic(err)
		}

	rootCertP256.Leaf, err = x509.ParseCertificate(rootCertP256.Certificate[0])
	if err != nil {
		panic(err)
	}
	/* ----------------------------------- End ---------------------------------- */

	//struct for the metrics
	var algoResults ClientResultsInfo

	//list of structs
	var algoResultsList []ClientResultsInfo

	//boxPlot data
	var boxPlotValues []plotter.Values
	var kexNames []string

	//prepare output file
	initCSV()

	keys := sortAlgorithmsMap()
	for _, k := range keys {
		strport := fmt.Sprintf("%d", port)
		fmt.Println("\t\t\t\t\t\t\t\t" + k + ":" + strport)
		kexCurveID, err := nameToCurveID(k)
		if err != nil {
			log.Fatal(err)
		}

		/* -------------------------------- Modified -------------------------------- */
		clientConfig := initClient(rootCertP256.Leaf)
		/* ----------------------------------- End ---------------------------------- */
		
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

		boxPlotValues = append(boxPlotValues, (timingsFullProtocol))
		kexNames = append(kexNames, k)

		port++
	}
	//export results
	resultsExporter(algoResultsList, boxPlotValues, kexNames, *handshakes)

}
