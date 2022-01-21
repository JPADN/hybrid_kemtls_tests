package main

import (
	"crypto/kem"
	"crypto/tls"
	"flag"
	"fmt"
	"log"
	"math"
	"time"
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

//Stats: Avg, Stdev
func computeStats(timingsFullProtocol []int64, timingsProcessServerHello []int64, timingsWriteClientHello []int64, timingsWriteKEMCiphertext []int64, hs int) (r ClientResultsInfo) {
	//counts
	var countTotalTime int64
	var countProcessServerHello int64
	var countWriteClientHello int64
	var countWriteKEMCiphertext int64

	//Average
	countTotalTime, countProcessServerHello, countWriteClientHello, countWriteKEMCiphertext = 0, 0, 0, 0
	for i := 0; i < hs; i++ {
		countTotalTime += timingsFullProtocol[i]
		countProcessServerHello += timingsProcessServerHello[i]
		countWriteClientHello += timingsWriteClientHello[i]
		countWriteKEMCiphertext += timingsWriteKEMCiphertext[i]
	}

	r.avgTotalTime = float64(countTotalTime) / float64(hs)
	r.avgProcessServerHello = float64(countProcessServerHello) / float64(hs)
	r.avgWriteClientHello = float64(countWriteClientHello) / float64(hs)
	r.avgWriteKEMCiphertext = float64(countWriteKEMCiphertext) / float64(hs)

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

func resultsExporter(results []ClientResultsInfo) {
	printStatistics(results)
	genbar(results, "Avg Completion Time - Client (ms)")
	genbar(results, "Avg Write Client Hello Time (ms)")
	genbar(results, "Avg Process Server Hello - Client (ms)")
	genbar(results, "Avg Write KEM Ciphertext - Client (ms)")
}

func main() {
	flag.Parse()

	clientMsg := "hello, server"

	port := 4433

	//struct for the metrics
	var algoResults ClientResultsInfo

	//list of structs
	var algoResultsList []ClientResultsInfo

	keys := sortAlgorithmsMap()
	for _, k := range keys {
		strport := fmt.Sprintf("%d", port)
		fmt.Println("\t\t\t\t\t\t\t\t" + k + ":" + strport)
		kexCurveID, err := nameToCurveID(k)
		if err != nil {
			log.Fatal(err)
		}

		clientConfig := initClient()
		// Select here the algorithm to be used in the KEX
		clientConfig.CurvePreferences = []tls.CurveID{kexCurveID}

		fmt.Printf("Starting KEMTLS Handshakes: KEX Algorithm: %s (0x%x) - Auth Algorithm: %s (0x%x)\n",
			k, kem.ID(kexCurveID),
			k, kem.ID(kexCurveID)) //note: removed 'authCurveID'

		var timingsFullProtocol []int64
		var timingsProcessServerHello []int64
		var timingsWriteClientHello []int64
		var timingsWriteKEMCiphertext []int64
		for i := 0; i < *handshakes; i++ {
			timingState, _, err := testConnHybrid(clientMsg, clientMsg, clientConfig, clientConfig, "client", *IPserver, strport)
			if err != nil {
				log.Fatal(err)
			}
			timingsFullProtocol = append(timingsFullProtocol, int64(timingState.clientTimingInfo.FullProtocol/time.Millisecond))
			timingsProcessServerHello = append(timingsProcessServerHello, int64(timingState.clientTimingInfo.ProcessServerHello/time.Millisecond))
			timingsWriteClientHello = append(timingsWriteClientHello, int64(timingState.clientTimingInfo.WriteClientHello/time.Millisecond))
			timingsWriteKEMCiphertext = append(timingsWriteKEMCiphertext, int64(timingState.clientTimingInfo.WriteKEMCiphertext/time.Millisecond))
		}

		algoResults = computeStats(timingsFullProtocol, timingsProcessServerHello, timingsWriteClientHello, timingsWriteKEMCiphertext, *handshakes)
		algoResults.kexName = k
		algoResults.authName = k

		algoResultsList = append(algoResultsList, algoResults)
		port++
	}
	//export results
	resultsExporter(algoResultsList)

}
