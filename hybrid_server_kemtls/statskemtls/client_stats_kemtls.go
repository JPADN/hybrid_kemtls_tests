package statskemtls

import (
	"encoding/csv"
	"fmt"
	"log"
	"math"
	"os"
	"regexp"
	"strings"
	// 	"tls_tests/hybrid_server_kemtls/plot"

	"gonum.org/v1/plot/plotter"
)

type ClientResultsInfo struct {
	KexName                 string
	AuthName                string
	AvgTotalTime            float64
	AvgWriteKEMCiphertext   float64
	AvgProcessServerHello   float64
	AvgWriteClientHello     float64
	StdevTotalTime          float64
	StdevWriteKEMCiphertext float64
	StdevProcessServerHello float64
	StdevWriteClientHello   float64
}

//Stats: Avg, Stdev.
func ComputeStats(timingsFullProtocol []float64, timingsProcessServerHello []float64, timingsWriteClientHello []float64, timingsWriteKEMCiphertext []float64, hs int) (r ClientResultsInfo) {

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

	r.AvgTotalTime = (countTotalTime) / float64(hs)
	r.AvgProcessServerHello = (countProcessServerHello) / float64(hs)
	r.AvgWriteClientHello = (countWriteClientHello) / float64(hs)
	r.AvgWriteKEMCiphertext = (countWriteKEMCiphertext) / float64(hs)

	//stdev
	for i := 0; i < hs; i++ {
		r.StdevTotalTime += math.Pow(float64(timingsFullProtocol[i])-r.AvgTotalTime, 2)
		r.StdevProcessServerHello += math.Pow(float64(timingsProcessServerHello[i])-r.AvgProcessServerHello, 2)
		r.StdevWriteClientHello += math.Pow(float64(timingsWriteClientHello[i])-r.AvgWriteClientHello, 2)
		r.StdevWriteKEMCiphertext += math.Pow(float64(timingsWriteKEMCiphertext[i])-r.AvgWriteKEMCiphertext, 2)
	}
	r.StdevTotalTime = math.Sqrt(r.StdevTotalTime / float64(hs))
	r.StdevProcessServerHello = math.Sqrt(r.StdevProcessServerHello / float64(hs))
	r.StdevWriteClientHello = math.Sqrt(r.StdevWriteClientHello / float64(hs))
	r.StdevWriteKEMCiphertext = math.Sqrt(r.StdevWriteKEMCiphertext / float64(hs))

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
	fmt.Printf("%-20s | ", "AvgWrtKEMCtTime")
	fmt.Printf("%-20s ", "StdevWrtKEMCtTime")

	for _, r := range results {
		//content
		fmt.Println()
		fmt.Printf("%-23s |", r.KexName)

		fmt.Printf(" %-20f |", r.AvgTotalTime)
		fmt.Printf(" %-20f |", r.StdevTotalTime)
		fmt.Printf(" %-20f |", r.AvgWriteClientHello)
		fmt.Printf(" %-20f |", r.StdevWriteClientHello)
		fmt.Printf(" %-20f |", r.AvgProcessServerHello)
		fmt.Printf(" %-20f |", r.StdevProcessServerHello)
		fmt.Printf(" %-20f |", r.AvgWriteKEMCiphertext)
		fmt.Printf(" %-20f ", r.StdevWriteKEMCiphertext)
	}
}

func InitCSV() {
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
func SaveCSV(timingsFullProtocol []float64, timingsProcessServerHello []float64, timingsWriteClientHello []float64, timingsWriteKEMCiphertext []float64, name string, hs int) {
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

func printHybridPenalty(results []ClientResultsInfo) {
	//hybrid prefixes
	re := regexp.MustCompile(`P256|P384|P521|x25519|x448`)

	//header
	fmt.Println("\n------ Hybrid Penalty ------")
	fmt.Printf("%-23s | ", "TestName")
	fmt.Printf("%-26s | ", "AvgClientTotalTime Penalty")
	fmt.Printf("%-26s | ", "AvgWrtCHelloTime Penalty")
	fmt.Printf("%-26s | ", "AvgPrSHelloTime Penalty")
	fmt.Printf("%-26s  ", "AvgWrtKEMCtTime Penalty")

	foundHybrid := false

	for _, r1 := range results {
		if re.MatchString(r1.KexName) {
			foundHybrid = true
			//find the PQC-only correspondence
			for _, r2 := range results { //str,substr
				if (strings.Contains(r1.KexName, r2.KexName)) && (r1.KexName != r2.KexName) {
					//Fix saber case
					if r2.KexName == "Saber_KEM" &&
						(strings.Contains(r1.KexName, "P256_LightSaber_KEM") || strings.Contains(r1.KexName, "P521_FireSaber_KEM")) {
						continue
					}
					fmt.Println("")
					fmt.Printf("%-23s |", r1.KexName)

					fmt.Printf(" %-26f |", r1.AvgTotalTime-r2.AvgTotalTime)
					fmt.Printf(" %-26f |", r1.AvgWriteClientHello-r2.AvgWriteClientHello)
					fmt.Printf(" %-26f |", r1.AvgProcessServerHello-r2.AvgProcessServerHello)
					fmt.Printf(" %-26f ", r1.AvgWriteKEMCiphertext-r2.AvgWriteKEMCiphertext)
				}
			}
		}
	}
	fmt.Println("")
	if foundHybrid == false {
		fmt.Println("No hybrid found in this test.")
	}
}

func ResultsExporter(results []ClientResultsInfo, boxPlotValues []plotter.Values, names []string, hs int) {
	printStatistics(results)
	printHybridPenalty(results)
	// plot.Genbar(results, "Avg Completion Time - Client (ms)")
	// plot.Genbar(results, "Avg Write Client Hello Time (ms)")
	// plot.Genbar(results, "Avg Process Server Hello - Client (ms)")
	// plot.Genbar(results, "Avg Write KEM Ciphertext - Client (ms)")
	// plot.Boxplot(names, boxPlotValues, hs)
	// plot.BarMarkLines(results, "All")
	// plot.BarMarkLines(results, "L1")
}
