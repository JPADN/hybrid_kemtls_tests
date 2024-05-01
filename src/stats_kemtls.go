package main

import (
	"encoding/csv"
	"fmt"
	"log"
	"math"
	"os"
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

//Stats: Avg, Stdev.
func computeStats(measurements []float64) (avg float64, stdev float64) {

	//counts
	var countTotalTime float64	

	numOfMeasurements := len(measurements) 

	//Average
	countTotalTime = 0;
	for i := 0; i < numOfMeasurements; i++ {
		countTotalTime += measurements[i]		
	}

	avg = (countTotalTime) / float64(numOfMeasurements)

	//stdev
	for i := 0; i < numOfMeasurements; i++ {
		stdev += math.Pow(float64(measurements[i]) - avg, 2)
	}

	stdev = math.Sqrt(stdev / float64(numOfMeasurements))

	return avg, stdev
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

func getClientResultsFileName() string {
	if *cachedCert {
		if *classicMcEliece {
			return "csv/kemtls-pdk-classic-mceliece-client.csv"
		} else {
			return "csv/kemtls-pdk-client.csv"
		}		
	} else {
		return "csv/kemtls-client.csv"
	}
}

func getServerResultsFileName() string {
	if *cachedCert {
		if *classicMcEliece {
			return "csv/kemtls-pdk-classic-mceliece-server.csv"
		} else {
			return "csv/kemtls-pdk-server.csv"
		}		
	} else {
		return "csv/kemtls-server.csv"
	}
}

func getClientSizesResultsFileName() string {
	if *cachedCert {
		if *classicMcEliece {
			return "csv/kemtls-pdk-classic-mceliece-client-sizes.csv"
		} else {
			return "csv/kemtls-pdk-client-sizes.csv"
		}		
	} else {
		return "csv/kemtls-client-sizes.csv"
	}
}

func getServerSizesResultsFileName() string {
	if *cachedCert {
		if *classicMcEliece {
			return "csv/kemtls-pdk-classic-mceliece-server-sizes.csv"
		} else {
			return "csv/kemtls-pdk-server-sizes.csv"
		}		
	} else {
		return "csv/kemtls-server-sizes.csv"
	}
}

func kemtlsInitCSV() {
	csvFile, err := os.Create(getClientResultsFileName())
	if err != nil {
		log.Fatalf("failed creating file: %s", err)
	}
	csvwriter := csv.NewWriter(csvFile)

	header := []string{"kex", "auth", "timingFullProtocol", "timingSendAppData", "timingProcessServerHello", "timingWriteClientHello", "timingWriteKEMCiphertext"}

	csvwriter.Write(header)
	csvwriter.Flush()
	csvFile.Close()

	csvFile, err = os.Create(getClientSizesResultsFileName())
	if err != nil {
		log.Fatalf("failed creating file: %s", err)
	}
	csvwriter = csv.NewWriter(csvFile)

	header = []string{"kex", "auth", "ClientHello", "ClientKEMCiphertext", "Certificate", "Finished", "Total"}

	csvwriter.Write(header)
	csvwriter.Flush()
	csvFile.Close()
}

func kemtlsInitCSVServer() {
	csvFile, err := os.Create(getServerResultsFileName())
	if err != nil {
		log.Fatalf("failed creating file: %s", err)
	}
	csvwriter := csv.NewWriter(csvFile)

	header := []string{"kex", "auth", "timingFullProtocol", "timingWriteServerHello", "timingReadKEMCiphertext"}

	csvwriter.Write(header)
	csvwriter.Flush()
	csvFile.Close()

	csvFile, err = os.Create(getServerSizesResultsFileName())
	if err != nil {
		log.Fatalf("failed creating file: %s", err)
	}
	csvwriter = csv.NewWriter(csvFile)

	header = []string{"kex", "auth", "ServerHello", "EncryptedExtensions", "Certificate", "CertificateRequest", "ServerKEMCiphertext", "Finished", "Total"}

	csvwriter.Write(header)
	csvwriter.Flush()
	csvFile.Close()
}



func kemtlsSaveCSV(timingsFullProtocol []float64, timingsSendAppData []float64, timingsProcessServerHello []float64, timingsWriteClientHello []float64, timingsWriteKEMCiphertext []float64, kexAlgo string, authAlgo string, hs int, sizes map[string]uint32) {
	csvFile, err := os.OpenFile(getClientResultsFileName(), os.O_APPEND|os.O_WRONLY, os.ModeAppend)
	if err != nil {
		log.Fatalf("failed opening file: %s", err)
	}

	csvwriter := csv.NewWriter(csvFile)

	for i := 0; i < hs; i++ {
		arrayStr := []string{
			kexAlgo, authAlgo,
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

	csvFile, err = os.OpenFile(getClientSizesResultsFileName(), os.O_APPEND|os.O_WRONLY, os.ModeAppend)
	if err != nil {
		log.Fatalf("failed opening file: %s", err)
	}

	csvwriter = csv.NewWriter(csvFile)

	totalSizes := sizes["ClientHello"] + sizes["ClientKEMCiphertext"] + sizes["Certificate"] + sizes["Finished"]

	arrayStr := []string{
		kexAlgo, authAlgo, 
		fmt.Sprintf("%d", sizes["ClientHello"]),
		fmt.Sprintf("%d", sizes["ClientKEMCiphertext"]),
		fmt.Sprintf("%d", sizes["Certificate"]),
		fmt.Sprintf("%d", sizes["Finished"]),
		fmt.Sprintf("%d", totalSizes),
	}

	if err := csvwriter.Write(arrayStr); err != nil {
		log.Fatalln("error writing record to file", err)
	}
	csvwriter.Flush()
	csvFile.Close()
}

func kemtlsSaveCSVServer(timingsFullProtocol []float64, timingsWriteServerHello []float64, timingsReadKEMCiphertext []float64, kexAlgo string, authAlgo string, hs int, sizes map[string]uint32) {
	csvFile, err := os.OpenFile(getServerResultsFileName(), os.O_APPEND|os.O_WRONLY, os.ModeAppend)
	if err != nil {
		log.Fatalf("failed opening file: %s", err)
	}

	csvwriter := csv.NewWriter(csvFile)

	for i := 0; i < hs; i++ {
		arrayStr := []string{
			kexAlgo, authAlgo,
			fmt.Sprintf("%f", timingsFullProtocol[i]),
			fmt.Sprintf("%f", timingsWriteServerHello[i]),
			fmt.Sprintf("%f", timingsReadKEMCiphertext[i])}

		if err := csvwriter.Write(arrayStr); err != nil {
			log.Fatalln("error writing record to file", err)
		}
		csvwriter.Flush()
	}
	csvFile.Close()

	csvFile, err = os.OpenFile(getServerSizesResultsFileName(), os.O_APPEND|os.O_WRONLY, os.ModeAppend)
	if err != nil {
		log.Fatalf("failed opening file: %s", err)
	}

	csvwriter = csv.NewWriter(csvFile)

	totalSizes := sizes["ServerHello"] + sizes["EncryptedExtensions"] + sizes["Certificate"] + sizes["CertificateRequest"] + sizes["ServerKEMCiphertext"] + sizes["Finished"]

	arrayStr := []string{
		kexAlgo, authAlgo,
		fmt.Sprintf("%d", sizes["ServerHello"]),
		fmt.Sprintf("%d", sizes["EncryptedExtensions"]),
		fmt.Sprintf("%d", sizes["Certificate"]),
		fmt.Sprintf("%d", sizes["CertificateRequest"]),
		fmt.Sprintf("%d", sizes["ServerKEMCiphertext"]),
		fmt.Sprintf("%d", sizes["Finished"]),
		fmt.Sprintf("%d", totalSizes),
	}

	if err := csvwriter.Write(arrayStr); err != nil {
		log.Fatalln("error writing record to file", err)
	}
	csvwriter.Flush()
	csvFile.Close()
}
