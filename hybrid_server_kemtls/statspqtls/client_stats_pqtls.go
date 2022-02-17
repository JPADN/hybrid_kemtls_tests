package statspqtls

import (
	"encoding/csv"
	"fmt"
	"log"
	"math"
	"os"

	"gonum.org/v1/plot/plotter"
)

type ClientResultsInfo struct {
	KexName                 string
	AuthName                string
	AvgTotalTime            float64
	AvgProcessServerHello   float64
	AvgWriteClientHello     float64
	StdevTotalTime          float64
	StdevProcessServerHello float64
	StdevWriteClientHello   float64
}

//Stats: Avg, Stdev.
func ComputeStats(timingsFullProtocol []float64, timingsProcessServerHello []float64, timingsWriteClientHello []float64, dummy []float64, hs int) (r ClientResultsInfo) {

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

	r.AvgTotalTime = (countTotalTime) / float64(hs)
	r.AvgProcessServerHello = (countProcessServerHello) / float64(hs)
	r.AvgWriteClientHello = (countWriteClientHello) / float64(hs)

	//stdev
	for i := 0; i < hs; i++ {
		r.StdevTotalTime += math.Pow(float64(timingsFullProtocol[i])-r.AvgTotalTime, 2)
		r.StdevProcessServerHello += math.Pow(float64(timingsProcessServerHello[i])-r.AvgProcessServerHello, 2)
		r.StdevWriteClientHello += math.Pow(float64(timingsWriteClientHello[i])-r.AvgWriteClientHello, 2)
	}
	r.StdevTotalTime = math.Sqrt(r.StdevTotalTime / float64(hs))
	r.StdevProcessServerHello = math.Sqrt(r.StdevProcessServerHello / float64(hs))
	r.StdevWriteClientHello = math.Sqrt(r.StdevWriteClientHello / float64(hs))

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
		fmt.Printf("%-23s |", r.KexName)

		fmt.Printf(" %-20f |", r.AvgTotalTime)
		fmt.Printf(" %-20f |", r.StdevTotalTime)
		fmt.Printf(" %-20f |", r.AvgWriteClientHello)
		fmt.Printf(" %-20f |", r.StdevWriteClientHello)
		fmt.Printf(" %-20f |", r.AvgProcessServerHello)
		fmt.Printf(" %-20f |", r.StdevProcessServerHello)
	}
}

func InitCSV() {
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

func SaveCSV(timingsFullProtocol []float64, timingsProcessServerHello []float64, timingsWriteClientHello []float64, dummy []float64, name string, hs int) {
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

func ResultsExporter(results []ClientResultsInfo, boxPlotValues []plotter.Values, names []string, hs int) {
	printStatistics(results)
	//printHybridPenalty(results)
	/*	genbar(results, "Avg Completion Time - Client (ms)")
		genbar(results, "Avg Write Client Hello Time (ms)")
		genbar(results, "Avg Process Server Hello - Client (ms)")
		boxplot(names, boxPlotValues, hs)
		barMarkLines(results, "All")
			barMarkLines(results, "L1")*/
}
