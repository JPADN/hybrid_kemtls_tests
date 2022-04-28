package main

import (
	"encoding/csv"
	"fmt"
	"log"
	"math"
	"os"

	"gonum.org/v1/plot/plotter"
)

type TLSClientResultsInfo struct {
	kexName                 string
	authName                string
	avgTotalTime            float64
	avgProcessServerHello   float64
	avgWriteClientHello     float64
	stdevTotalTime          float64
	stdevProcessServerHello float64
	stdevWriteClientHello   float64
}

type TLSServerResultsInfo struct {
	kexName              string
	authName             string
	avgTotalTime         float64
	avgWriteCertVerify   float64
	stdevTotalTime       float64
	stdevWriteCertVerify float64
}

//Stats: Avg, Stdev.
func tlsComputeStats(timingsFullProtocol []float64, timingsProcessServerHello []float64, timingsWriteClientHello []float64, hs int) (r TLSClientResultsInfo) {

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
func tlsPrintStatistics(results []TLSClientResultsInfo) {
	//header
	fmt.Printf("%-47s | ", "TestName")
	fmt.Printf("%-20s | ", "AvgClientTotalTime")
	fmt.Printf("%-20s | ", "StdevClientTotalTime")
	fmt.Printf("%-20s | ", "AvgWrtCHelloTime")
	fmt.Printf("%-20s | ", "StdevWrtCHelloTime")
	fmt.Printf("%-20s | ", "AvgPrSHelloTime")
	fmt.Printf("%-20s  ", "StdevPrSHelloTime")

	for _, r := range results {
		//content
		fmt.Println()
		fmt.Printf("%23s %23s |", r.kexName, r.authName)

		fmt.Printf(" %-20f |", r.avgTotalTime)
		fmt.Printf(" %-20f |", r.stdevTotalTime)
		fmt.Printf(" %-20f |", r.avgWriteClientHello)
		fmt.Printf(" %-20f |", r.stdevWriteClientHello)
		fmt.Printf(" %-20f |", r.avgProcessServerHello)
		fmt.Printf(" %-20f ", r.stdevProcessServerHello)
	}
}

func tlsInitCSV() {
	csvFile, err := os.Create("csv/tls-client.csv")
	if err != nil {
		log.Fatalf("failed creating file: %s", err)
	}
	csvwriter := csv.NewWriter(csvFile)

	header := []string{"KEXAlgo", "authAlgo", "timingFullProtocol", "timingProcessServerHello", "timingWriteClientHello"}

	csvwriter.Write(header)
	csvwriter.Flush()
	csvFile.Close()

	csvFile, err = os.Create("csv/tls-client-sizes.csv")
	if err != nil {
		log.Fatalf("failed creating file: %s", err)
	}
	csvwriter = csv.NewWriter(csvFile)

	header = []string{"KEXAlgo", "authAlgo", "ClientHello", "Certificate", "CertificateVerify", "Finished", "Total"}

	csvwriter.Write(header)
	csvwriter.Flush()
	csvFile.Close()
}

func tlsSaveCSV(timingsFullProtocol []float64, timingsProcessServerHello []float64, timingsWriteClientHello []float64, name, authName string, hs int, sizes map[string]uint32) {
	csvFile, err := os.OpenFile("csv/tls-client.csv", os.O_APPEND|os.O_WRONLY, os.ModeAppend)
	if err != nil {
		log.Fatalf("failed opening file: %s", err)
	}

	csvwriter := csv.NewWriter(csvFile)

	for i := 0; i < hs; i++ {
		arrayStr := []string{name, authName, fmt.Sprintf("%f", timingsFullProtocol[i]),
			fmt.Sprintf("%f", timingsProcessServerHello[i]),
			fmt.Sprintf("%f", timingsWriteClientHello[i])}

		if err := csvwriter.Write(arrayStr); err != nil {
			log.Fatalln("error writing record to file", err)
		}
		csvwriter.Flush()
	}
	csvFile.Close()

	csvFile, err = os.OpenFile("csv/tls-client-sizes.csv", os.O_APPEND|os.O_WRONLY, os.ModeAppend)
	if err != nil {
		log.Fatalf("failed opening file: %s", err)
	}

	csvwriter = csv.NewWriter(csvFile)

	totalSizes := sizes["ClientHello"] + sizes["Certificate"] + sizes["CertificateVerify"] + sizes["Finished"]

	arrayStr := []string{name, authName,
		fmt.Sprintf("%d", sizes["ClientHello"]),		
		fmt.Sprintf("%d", sizes["Certificate"]),
		fmt.Sprintf("%d", sizes["CertificateVerify"]),
		fmt.Sprintf("%d", sizes["Finished"]),
		fmt.Sprintf("%d", totalSizes),
	}

	if err := csvwriter.Write(arrayStr); err != nil {
		log.Fatalln("error writing record to file", err)
	}
	csvwriter.Flush()
	csvFile.Close()
}

func tlsResultsExporter(results []TLSClientResultsInfo, boxPlotValues []plotter.Values, names []string, hs int) {
	tlsPrintStatistics(results)
	//plots are not needed (here) since:
	//we are not comparing PQC-only vs Hybrid PQTLS
	//we are not testing KEMTLS together with PQTLS
}

func tlsInitCSVServer() {
	csvFile, err := os.Create("csv/tls-server.csv")
	if err != nil {
		log.Fatalf("failed creating file: %s", err)
	}
	csvwriter := csv.NewWriter(csvFile)

	header := []string{"KEXAlgo", "authAlgo", "timingFullProtocol", "timingWriteServerHello", "timingWriteCertVerify"}

	csvwriter.Write(header)
	csvwriter.Flush()
	csvFile.Close()

	
	csvFile, err = os.Create("csv/tls-server-sizes.csv")
	if err != nil {
		log.Fatalf("failed creating file: %s", err)
	}
	csvwriter = csv.NewWriter(csvFile)

	header = []string{"KEXAlgo", "authAlgo", "ServerHello", "EncryptedExtensions", "Certificate", "CertificateRequest", "CertificateVerify", "Finished", "Total"}

	csvwriter.Write(header)
	csvwriter.Flush()
	csvFile.Close()
}

func tlsSaveCSVServer(timingsFullProtocol []float64, timingsWriteServerHello []float64, timingsWriteCertVerify []float64, name string, authName string, hs int, sizes map[string]uint32) {
	csvFile, err := os.OpenFile("csv/tls-server.csv", os.O_APPEND|os.O_WRONLY, os.ModeAppend)
	if err != nil {
		log.Fatalf("failed opening file: %s", err)
	}

	csvwriter := csv.NewWriter(csvFile)

	for i := 0; i < hs; i++ {
		arrayStr := []string{name, authName, fmt.Sprintf("%f", timingsFullProtocol[i]),
			fmt.Sprintf("%f", timingsWriteServerHello[i]),
			fmt.Sprintf("%f", timingsWriteCertVerify[i]),
		}

		if err := csvwriter.Write(arrayStr); err != nil {
			log.Fatalln("error writing record to file", err)
		}
		csvwriter.Flush()
	}
	csvFile.Close()

	csvFile, err = os.OpenFile("csv/tls-server-sizes.csv", os.O_APPEND|os.O_WRONLY, os.ModeAppend)
	if err != nil {
		log.Fatalf("failed opening file: %s", err)
	}

	csvwriter = csv.NewWriter(csvFile)

	totalSizes := sizes["ServerHello"] + sizes["EncryptedExtensions"] + sizes["Certificate"] + sizes["CertificateRequest"] + sizes["CertificateVerify"] + sizes["Finished"]

	arrayStr := []string{name, authName, 
		fmt.Sprintf("%d", sizes["ServerHello"]),
		fmt.Sprintf("%d", sizes["EncryptedExtensions"]),
		fmt.Sprintf("%d", sizes["Certificate"]),
		fmt.Sprintf("%d", sizes["CertificateRequest"]),
		fmt.Sprintf("%d", sizes["CertificateVerify"]),
		fmt.Sprintf("%d", sizes["Finished"]),
		fmt.Sprintf("%d", totalSizes),
	}

	if err := csvwriter.Write(arrayStr); err != nil {
		log.Fatalln("error writing record to file", err)
	}
	csvwriter.Flush()
	csvFile.Close()

}
