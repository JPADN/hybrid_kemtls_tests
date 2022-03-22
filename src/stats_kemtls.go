package main

import (
	"encoding/csv"
	"fmt"
	"log"
	"math"
	"os"
	"regexp"
	"strings"

	"gonum.org/v1/plot/plotter"
)

type KEMTLSClientResultsInfo struct {
	kexName                 string
	authName                string
	avgTotalTime            float64
	avgSendAppDataTime 			float64
	avgWriteKEMCiphertext   float64
	avgProcessServerHello   float64
	avgWriteClientHello     float64
	stdevTotalTime          float64
	stdevSendAppDataTime 			float64
	stdevWriteKEMCiphertext float64
	stdevProcessServerHello float64
	stdevWriteClientHello   float64
}

//Stats: Avg, Stdev.
func kemtlsComputeStats(timingsFullProtocol []float64, timingsSendAppData []float64, timingsProcessServerHello []float64, timingsWriteClientHello []float64, timingsWriteKEMCiphertext []float64, hs int) (r KEMTLSClientResultsInfo) {

	//counts
	var countTotalTime float64
	var countSendAppDataTime float64
	var countProcessServerHello float64
	var countWriteClientHello float64
	var countWriteKEMCiphertext float64

	//Average
	countTotalTime, countSendAppDataTime, countProcessServerHello, countWriteClientHello, countWriteKEMCiphertext = 0, 0, 0, 0, 0
	for i := 0; i < hs; i++ {
		countTotalTime += timingsFullProtocol[i]
		countSendAppDataTime += timingsSendAppData[i]
		countProcessServerHello += timingsProcessServerHello[i]
		countWriteClientHello += timingsWriteClientHello[i]
		countWriteKEMCiphertext += timingsWriteKEMCiphertext[i]
	}

	r.avgTotalTime = (countTotalTime) / float64(hs)
	r.avgSendAppDataTime = (countSendAppDataTime) / float64(hs)
	r.avgProcessServerHello = (countProcessServerHello) / float64(hs)
	r.avgWriteClientHello = (countWriteClientHello) / float64(hs)
	r.avgWriteKEMCiphertext = (countWriteKEMCiphertext) / float64(hs)

	//stdev
	for i := 0; i < hs; i++ {
		r.stdevTotalTime += math.Pow(float64(timingsFullProtocol[i])-r.avgTotalTime, 2)
		r.stdevSendAppDataTime += math.Pow(float64(timingsSendAppData[i])-r.avgSendAppDataTime, 2)
		r.stdevProcessServerHello += math.Pow(float64(timingsProcessServerHello[i])-r.avgProcessServerHello, 2)
		r.stdevWriteClientHello += math.Pow(float64(timingsWriteClientHello[i])-r.avgWriteClientHello, 2)
		r.stdevWriteKEMCiphertext += math.Pow(float64(timingsWriteKEMCiphertext[i])-r.avgWriteKEMCiphertext, 2)
	}
	r.stdevTotalTime = math.Sqrt(r.stdevTotalTime / float64(hs))
	r.stdevSendAppDataTime = math.Sqrt(r.stdevSendAppDataTime / float64(hs))
	r.stdevProcessServerHello = math.Sqrt(r.stdevProcessServerHello / float64(hs))
	r.stdevWriteClientHello = math.Sqrt(r.stdevWriteClientHello / float64(hs))
	r.stdevWriteKEMCiphertext = math.Sqrt(r.stdevWriteKEMCiphertext / float64(hs))

	return r
}

//print results
func kemtlsPrintStatistics(results []KEMTLSClientResultsInfo) {
	//header
	fmt.Printf("%-23s | ", "TestName")
	fmt.Printf("%-20s | ", "AvgClientTotalTime")
	fmt.Printf("%-20s | ", "StdevClientTotalTime")
	fmt.Printf("%-20s | ", "AvgSendAppDataTime")
	fmt.Printf("%-20s | ", "stdevSendAppDataTime")
	fmt.Printf("%-20s | ", "AvgWrtCHelloTime")
	fmt.Printf("%-20s | ", "StdevWrtCHelloTime")
	fmt.Printf("%-20s | ", "AvgPrSHelloTime")
	fmt.Printf("%-20s | ", "StdevPrSHelloTime")
	fmt.Printf("%-20s | ", "AvgWrtKEMCtTime")
	fmt.Printf("%-20s ", "StdevWrtKEMCtTime")

	for _, r := range results {
		//content
		fmt.Println()
		fmt.Printf("%-23s |", r.kexName)

		fmt.Printf(" %-20f |", r.avgTotalTime)
		fmt.Printf(" %-20f |", r.stdevTotalTime)
		fmt.Printf(" %-20f |", r.avgSendAppDataTime)
		fmt.Printf(" %-20f |", r.stdevSendAppDataTime)
		fmt.Printf(" %-20f |", r.avgWriteClientHello)
		fmt.Printf(" %-20f |", r.stdevWriteClientHello)
		fmt.Printf(" %-20f |", r.avgProcessServerHello)
		fmt.Printf(" %-20f |", r.stdevProcessServerHello)
		fmt.Printf(" %-20f |", r.avgWriteKEMCiphertext)
		fmt.Printf(" %-20f ", r.stdevWriteKEMCiphertext)
	}
}

func kemtlsInitCSV() {
	csvFile, err := os.Create("csv/kemtls-client.csv")
	if err != nil {
		log.Fatalf("failed creating file: %s", err)
	}
	csvwriter := csv.NewWriter(csvFile)

	header := []string{"algo", "timingFullProtocol", "timingSendAppData", "timingProcessServerHello", "timingWriteClientHello", "timingWriteKEMCiphertext"}

	csvwriter.Write(header)
	csvwriter.Flush()
	csvFile.Close()
}

func kemtlsInitCSVServer() {
	csvFile, err := os.Create("csv/kemtls-server.csv")
	if err != nil {
		log.Fatalf("failed creating file: %s", err)
	}
	csvwriter := csv.NewWriter(csvFile)

	header := []string{"algo", "timingFullProtocol", "timingWriteServerHello", "timingReadKEMCiphertext"}

	csvwriter.Write(header)
	csvwriter.Flush()
	csvFile.Close()
}

//func kemtlsSaveCSV(boxPlotValues []plotter.Values, names []string, hs int) {
func kemtlsSaveCSV(timingsFullProtocol []float64, timingsSendAppData []float64, timingsProcessServerHello []float64, timingsWriteClientHello []float64, timingsWriteKEMCiphertext []float64, name string, hs int) {
	csvFile, err := os.OpenFile("csv/kemtls-client.csv", os.O_APPEND|os.O_WRONLY, os.ModeAppend)
	if err != nil {
		log.Fatalf("failed opening file: %s", err)
	}

	csvwriter := csv.NewWriter(csvFile)

	for i := 0; i < hs; i++ {
		arrayStr := []string{
			name, 
			fmt.Sprintf("%f", timingsFullProtocol[i]),
			fmt.Sprintf("%f", timingsSendAppData[i]),
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

func kemtlsSaveCSVServer(timingsFullProtocol []float64, timingsWriteServerHello []float64, timingsReadKEMCiphertext []float64, name string, hs int) {
	csvFile, err := os.OpenFile("csv/kemtls-server.csv", os.O_APPEND|os.O_WRONLY, os.ModeAppend)
	if err != nil {
		log.Fatalf("failed opening file: %s", err)
	}

	csvwriter := csv.NewWriter(csvFile)

	for i := 0; i < hs; i++ {
		arrayStr := []string{
			name, 
			fmt.Sprintf("%f", timingsFullProtocol[i]),
			fmt.Sprintf("%f", timingsWriteServerHello[i]),
			fmt.Sprintf("%f", timingsReadKEMCiphertext[i])}

		if err := csvwriter.Write(arrayStr); err != nil {
			log.Fatalln("error writing record to file", err)
		}
		csvwriter.Flush()
	}
	csvFile.Close()
}

func printHybridPenalty(results []KEMTLSClientResultsInfo) {
	//hybrid prefixes
	re := regexp.MustCompile(`P256|P384|P521|x25519|x448`)

	//header
	fmt.Println("\n------ Hybrid Penalty ------")
	fmt.Printf("%-23s | ", "TestName")
	fmt.Printf("%-26s | ", "AvgClientTotalTime Penalty")
	fmt.Printf("%-26s | ", "AvgClientSendAppDataTime Penalty")
	fmt.Printf("%-26s | ", "AvgWrtCHelloTime Penalty")
	fmt.Printf("%-26s | ", "AvgPrSHelloTime Penalty")
	fmt.Printf("%-26s  ", "AvgWrtKEMCtTime Penalty")

	foundHybrid := false

	for _, r1 := range results {
		if re.MatchString(r1.kexName) {
			foundHybrid = true
			//find the PQC-only correspondence
			for _, r2 := range results { //str,substr
				if (strings.Contains(r1.kexName, r2.kexName)) && (r1.kexName != r2.kexName) {
					//Fix saber case
					if r2.kexName == "Saber_KEM" &&
						(strings.Contains(r1.kexName, "P256_LightSaber_KEM") || strings.Contains(r1.kexName, "P521_FireSaber_KEM")) {
						continue
					}
					fmt.Println("")
					fmt.Printf("%-23s |", r1.kexName)

					fmt.Printf(" %-26f |", r1.avgTotalTime-r2.avgTotalTime)
					fmt.Printf(" %-26f |", r1.avgSendAppDataTime-r2.avgSendAppDataTime)
					fmt.Printf(" %-26f |", r1.avgWriteClientHello-r2.avgWriteClientHello)
					fmt.Printf(" %-26f |", r1.avgProcessServerHello-r2.avgProcessServerHello)
					fmt.Printf(" %-26f ", r1.avgWriteKEMCiphertext-r2.avgWriteKEMCiphertext)
				}
			}
		}
	}
	fmt.Println("")
	if foundHybrid == false {
		fmt.Println("No hybrid found in this test.")
	}
}

func kemtlsResultsExporter(results []KEMTLSClientResultsInfo, boxPlotValues []plotter.Values, names []string, hs int) {
	kemtlsPrintStatistics(results)
	printHybridPenalty(results)
	genbar(results, "Avg Completion Time - Client (ms)")
	genbar(results, "Avg Send Application Data Time - Client (ms)")
	genbar(results, "Avg Write Client Hello Time (ms)")
	genbar(results, "Avg Process Server Hello - Client (ms)")
	genbar(results, "Avg Write KEM Ciphertext - Client (ms)")
	boxplot(names, boxPlotValues, hs)
	barMarkLines(results, "All")
	barMarkLines(results, "L1")
}
