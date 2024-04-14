package main

import (
	"crypto/kem"
	"crypto/rand"
	"encoding/csv"
	"fmt"
	"os"
	"time"
)


type benchmarkResult struct {
	kemName string
	publicKeySize int
	ciphertextSize int
	nistLevel int
	keygenAvg float64
	keygenStdev float64
	encapsAvg float64
	encapsStdev float64
	decapsAvg float64
	decapsStdev float64	
}


func main() {
	reps := 100	
	var measurements []float64
	var benchmarkResults []benchmarkResult
	var elapsedMs float64
	var start, finish time.Time
	var elapsed time.Duration
	
	for kexName, _ := range hsKEXAlgorithms {

		kexCurveId, err := nameToCurveID(kexName)
		if err != nil {
			panic(err)
		}

		kemId := kem.ID(kexCurveId)

		publicKey, privateKey, err := kem.GenerateKey(rand.Reader, kemId)
		if err != nil {
			panic(err)
		}
		_, ciphertext, err := kem.Encapsulate(rand.Reader, publicKey)
		if err != nil {
			panic(err)
		}

		// Keygen benchmark
		for i := 0; i < reps; i++ {
			start = time.Now()
			_, _, err = kem.GenerateKey(rand.Reader, kemId)
			finish = time.Now()
			if err != nil {
				panic(err)
			}			
			elapsed = finish.Sub(start)
			elapsedMs = float64(elapsed) / float64(time.Millisecond)
			measurements = append(measurements, elapsedMs)
		}
		kgAvg, kgStdev := computeStats(measurements)


		// Encapsulation benchmark
		for i := 0; i < reps; i++ {
			start = time.Now()
			_, _, err = kem.Encapsulate(rand.Reader, publicKey)
			if err != nil {
				panic(err)
			}
			finish = time.Now()
			elapsed = finish.Sub(start)
			elapsedMs = float64(elapsed) / float64(time.Millisecond)
			measurements = append(measurements, elapsedMs)
		}
		encAvg, encStdev := computeStats(measurements)
		
		// Decapsulation benchmark
		for i := 0; i < reps; i++ {
			start = time.Now()
			_, err = kem.Decapsulate(privateKey, ciphertext)
			if err != nil {
				panic(err)
			}
			finish = time.Now()
			elapsed = finish.Sub(start)
			elapsedMs = float64(elapsed) / float64(time.Millisecond)
			measurements = append(measurements, elapsedMs)
		}

		decAvg, decStdev := computeStats(measurements)


		kemDetails, err := kem.GetKemDetails(kemId)
		if err != nil {
			panic(err)
		}

		result := benchmarkResult{
			nistLevel: kemDetails.ClaimedNISTLevel,
			kemName: kexName,
			publicKeySize: kemDetails.PublicKeySize,
			ciphertextSize: kemDetails.CiphertextSize,
			keygenAvg: kgAvg,
			keygenStdev: kgStdev,
			encapsAvg: encAvg,
			encapsStdev: encStdev,
			decapsAvg: decAvg,
			decapsStdev: decStdev,
		}
		
		benchmarkResults = append(benchmarkResults, result)
	}

	saveBenchmarkCsv(benchmarkResults)
}

func saveBenchmarkCsv(benchmarkResults []benchmarkResult) {
	csvFile, err := os.Create("csv/kem_benchmark.csv")
	if err != nil {
		// log.Fatalf("failed creating file: %s", err)
		panic(err)
	}
	csvwriter := csv.NewWriter(csvFile)

	header := []string{"NIST Level", "KEM name", "Public key size", "Ciphertext size", "Keygen Avg", "Keygen Stdev", "Encapsulation Avg", "Encapsulation Stdev", "Decapsulation Avg", "Decapsulation Stdev"}
	if err := csvwriter.Write(header); err != nil {
		panic(err)
	}
	csvwriter.Flush()

	for _, r := range benchmarkResults {
		arrayStr := []string{
			fmt.Sprintf("%d", r.nistLevel), 
			r.kemName, 
			fmt.Sprintf("%d", r.publicKeySize), 
			fmt.Sprintf("%d", r.ciphertextSize),
			fmt.Sprintf("%f", r.keygenAvg),
			fmt.Sprintf("%f", r.keygenStdev),
			fmt.Sprintf("%f", r.encapsAvg),
			fmt.Sprintf("%f", r.encapsStdev),
			fmt.Sprintf("%f", r.decapsAvg),
			fmt.Sprintf("%f", r.decapsStdev)}

		if err := csvwriter.Write(arrayStr); err != nil {
			// log.Fatalln("error writing record to file", err)
			panic(err)
		}
		csvwriter.Flush()
	}
	csvFile.Close()
}