package main

import (
	"bufio"
	"crypto"
	"crypto/kem"
	"crypto/liboqs_sig"
	"crypto/rand"
	"encoding/csv"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"time"
)

// Flags
var (
	reps = flag.Int("reps", 10, "Repetition count for each algorithm benchmark")
)


// Types
type kemBenchmarkResult struct {
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

type signatureBenchmarkResult struct {
	signatureName string
	publicKeySize int
	signatureSize int
	nistLevel int
	signAvg float64
	signStdev float64
	verifyAvg float64
	verifyStdev float64	
}

// Maps and Slices
var classicKEMIdMap = map[string]kem.ID {
	"KEM_P256": kem.KEM_P256, "KEM_P384": kem.KEM_P384, "KEM_P521": kem.KEM_P521,
}

var classicKEMAlgorithms = []string{
	"KEM_P256", "KEM_P384", "KEM_P521",
}

var benchmarkKEMAlgorithms = []string {	 
	"KEM_P256", "P256_Kyber512", "P256_HQC_128", "P256_BIKE_L1", "P256_Classic_McEliece_348864",
	"KEM_P384",	"P384_Kyber768", "P384_HQC_192", "P384_BIKE_L3", "P384_Classic_McEliece_460896",
	"KEM_P521", "P521_Kyber1024", "P521_BIKE_L5", "P521_Classic_McEliece_6688128",
}

var benchmarkSignatureAlgorithms = []string {	 
	"P256_Dilithium2", "P256_Falcon512",
	"P384_Dilithium3",
	"P521_Dilithium5", "P521_Falcon1024",
}

func contains(s []string, e string) bool {
	for _, a := range s {
			if a == e {
					return true
			}
	}
	return false
}

func benchmarkSignatures() {

	var measurements []float64
	var benchmarkResults []signatureBenchmarkResult
	var elapsedMs float64
	var start, finish time.Time
	var elapsed time.Duration

	file, err := os.Open("tests_files/handshake_transcript_hash.txt")
	if err != nil {
		panic(err)
	}

	scanner := bufio.NewScanner(file)
	scanner.Scan()
	handshakeToBeSignedData, err := hex.DecodeString(scanner.Text())
	if err != nil {
		panic(err)
	}

	for _, sigName := range benchmarkSignatureAlgorithms {

		sigId, err := liboqs_sig.NameToSigID(sigName)
		if err != nil {
			panic(err)
		}

		pub, priv, err := liboqs_sig.GenerateKey(sigId)
		if err != nil {
			panic(err)
		}
		
		hash, err := liboqs_sig.HashFromSig(sigId)
		if err != nil {
			panic(err)
		}
		
		signOpts := crypto.SignerOpts(hash)		
		signature, err := priv.Sign(rand.Reader, handshakeToBeSignedData, signOpts)
		if err != nil {
			panic(err)
		}

		// Signing benchmark
		measurements = nil
		for i := 0; i < *reps; i++ {
			start = time.Now()
			_, err := priv.Sign(rand.Reader, handshakeToBeSignedData, signOpts)
			if err != nil {
				panic(err)
			}
			finish = time.Now()			
			elapsed = finish.Sub(start)
			elapsedMs = float64(elapsed) / float64(time.Millisecond)
			measurements = append(measurements, elapsedMs)
		}

		sigAvg, sigStdev := computeStats(measurements)

		// Verify benchmark
		measurements = nil
		for i := 0; i < *reps; i++ {
			start = time.Now()
			ok, err := pub.Verify(handshakeToBeSignedData, signature)
			if err != nil {
				panic(err)
			}
			if !ok {
				panic("Verification failed.")
			}
			finish = time.Now()			
			elapsed = finish.Sub(start)
			elapsedMs = float64(elapsed) / float64(time.Millisecond)
			measurements = append(measurements, elapsedMs)
		}

		verAvg, verStdev := computeStats(measurements)

		
		secLevel := getSecurityLevel(sigName)		
		pubBytes := pub.MarshalBinary();

		result := signatureBenchmarkResult{
			signatureName: sigName,
			nistLevel: secLevel,
			signatureSize: len(signature),
			publicKeySize: len(pubBytes),
			signAvg: sigAvg,
			signStdev: sigStdev,
			verifyAvg: verAvg,
			verifyStdev: verStdev,
		}

		benchmarkResults = append(benchmarkResults, result)
	}
	saveBenchmarkSignaturesCsv(benchmarkResults)	
}

func benchmarkKEMs() {
	var measurements []float64
	var benchmarkResults []kemBenchmarkResult
	var elapsedMs float64
	var start, finish time.Time
	var elapsed time.Duration

	for _, kemName := range benchmarkKEMAlgorithms {

		isClassicKEM := contains(classicKEMAlgorithms, kemName)

		var kemId kem.ID
		if isClassicKEM {
			kemId = classicKEMIdMap[kemName]
		} else {
			kemCurveId, err := nameToCurveID(kemName)
			if err != nil {
				panic(err)
			}
			kemId = kem.ID(kemCurveId)
		}

		publicKey, privateKey, err := kem.GenerateKey(rand.Reader, kemId)
		if err != nil {
			panic(err)
		}
		_, ciphertext, err := kem.Encapsulate(rand.Reader, publicKey)
		if err != nil {
			panic(err)
		}

		// Keygen benchmark
		measurements = nil
		for i := 0; i < *reps; i++ {
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
		measurements = nil
		for i := 0; i < *reps; i++ {
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
		measurements = nil
		for i := 0; i < *reps; i++ {
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

		result := kemBenchmarkResult{
			nistLevel: kemDetails.ClaimedNISTLevel,
			kemName: kemName,
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

	saveBenchmarkKEMsCsv(benchmarkResults)

}

func main() {

	flag.Parse()	
	benchmarkSignatures()
	// benchmarkKEMs()
}

func saveBenchmarkKEMsCsv(benchmarkResults []kemBenchmarkResult) {
	csvFile, err := os.Create("csv/kem_benchmark.csv")
	if err != nil {
		// log.Fatalf("failed creating file: %s", err)
		panic(err)
	}
	csvwriter := csv.NewWriter(csvFile)

	header := []string{"NIST Level", "KEM name", "Public key size", "Ciphertext size", "Total transmitted bytes", "Keygen Avg", "Keygen Stdev", "Encapsulation Avg", "Encapsulation Stdev", "Decapsulation Avg", "Decapsulation Stdev"}
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
			fmt.Sprintf("%d", r.publicKeySize + r.ciphertextSize),
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

func saveBenchmarkSignaturesCsv(benchmarkResults []signatureBenchmarkResult) {
	csvFile, err := os.Create("csv/signature_benchmark.csv")
	if err != nil {		
		panic(err)
	}
	csvwriter := csv.NewWriter(csvFile)

	header := []string{"NIST Level", "Signature name", "Public key size", "Signature size", "Total transmitted bytes", "Sign Avg", "Sign Stdev", "Verify Avg", "Verify Stdev"}
	if err := csvwriter.Write(header); err != nil {
		panic(err)
	}
	csvwriter.Flush()

	for _, r := range benchmarkResults {
		arrayStr := []string{
			fmt.Sprintf("%d", r.nistLevel), 
			r.signatureName, 
			fmt.Sprintf("%d", r.publicKeySize), 
			fmt.Sprintf("%d", r.signatureSize),
			fmt.Sprintf("%d", r.publicKeySize + r.signatureSize),
			fmt.Sprintf("%f", r.signAvg),
			fmt.Sprintf("%f", r.signStdev),
			fmt.Sprintf("%f", r.verifyAvg),
			fmt.Sprintf("%f", r.verifyStdev)}

		if err := csvwriter.Write(arrayStr); err != nil {
			// log.Fatalln("error writing record to file", err)
			panic(err)
		}
		csvwriter.Flush()
	}
	csvFile.Close()
}