package main

import (
	"crypto/liboqs_sig"
	"crypto/x509"
	"log"

	// For readHybridRootFile
	"bufio"
	"os"
	"strconv"

	// For Hybrid Root CA
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/asn1"
	"encoding/hex"

	"regexp"
	"fmt"
	"io"
)

// Development utility only
// Remove later
func countFileLines() {

	file, err := os.Open("hybrid_root_ca.txt")
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	r := bufio.NewReader(file)
	max_count := 0
	count := 0

	for {
		if c, _, err := r.ReadRune(); err != nil {
			if err == io.EOF {
				break
			} else {
				log.Fatal(err)
			}
		} else {
			if string(c) == "\n" {
				if count > max_count {
					max_count = count
				}

				count = 0

			} else {
				count = count + 1
			}
		}
	}

	fmt.Println(max_count)
}

func constructHybridRoot(rootAlgo string, securityLevel int) (*x509.Certificate, *liboqs_sig.PrivateKey) {

	/* ------------------------------ Reading file ------------------------------ */
	var rootData []string
	var rootFileName string

	reLevel1 := regexp.MustCompile(`P256`)
	reLevel3 := regexp.MustCompile(`P384`)
	reLevel5 := regexp.MustCompile(`P521`)

	
	if !((securityLevel == 1 && reLevel1.MatchString(rootAlgo)) || 
	   	 (securityLevel == 3 && reLevel3.MatchString(rootAlgo)) ||
		 	 (securityLevel == 5 && reLevel5.MatchString(rootAlgo))) {
		panic("Root CA algorithm does not match the security level of the server certificate")
	}

	rootFileName = "root_ca/hybrid_root_ca_" + rootAlgo + ".txt"

	file, err := os.Open(rootFileName)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)

	// Resizing scanner's capacity due to P521_RainbowVClassic certificates
	const maxCapacity = 3862673
	buf := make([]byte, maxCapacity)
	scanner.Buffer(buf, maxCapacity)

	for scanner.Scan() {
		rootData = append(rootData, scanner.Text())
	}

	if err := scanner.Err(); err != nil {
		log.Fatal(err)
	}

	rootSigIDString := rootData[0]

	curve := rootData[1]
	curve = curve

	oidBytesString := rootData[2]
	rootPrivClassic := rootData[3]
	rootPrivPqc := rootData[4]
	rootPubClassic := rootData[5]
	rootPubPqc := rootData[6]
	rootCACertString := rootData[7]

	/* ---------------------------- Decoding Strings ---------------------------- */

	rootSigIDInt, err := strconv.ParseUint(rootSigIDString, 16, 16)
	if err != nil {
		panic(err)
	}

	rootSigID := liboqs_sig.ID(rootSigIDInt)

	rootCACertBytes, err := hex.DecodeString(rootCACertString)
	if err != nil {
		panic(err)
	}

	rootCACert, err := x509.ParseCertificate(rootCACertBytes)
	if err != nil {
		panic(err)
	}

	/* -------------------------- Classic Priv Parsing -------------------------- */

	privBytes, err := hex.DecodeString(rootPrivClassic)
	if err != nil {
		panic(err)
	}

	oidBytes, err := hex.DecodeString(oidBytesString)
	if err != nil {
		panic(err)
	}

	namedCurveOID := new(asn1.ObjectIdentifier)
	if _, err := asn1.Unmarshal(oidBytes, namedCurveOID); err != nil {
		panic(err)
	}

	classicPriv, err := x509.ParseECPrivateKeyWithOID(namedCurveOID, privBytes)
	if err != nil {
		panic(err)
	}

	/* --------------------------- Classic Pub Parsing -------------------------- */

	classicPub := new(ecdsa.PublicKey)
	classicPub.Curve, _ = liboqs_sig.ClassicFromSig(rootSigID)

	classicBytes, err := hex.DecodeString(rootPubClassic)
	if err != nil {
		panic(err)
	}

	classicPub.X, classicPub.Y = elliptic.Unmarshal(classicPub.Curve, classicBytes)
	if classicPub.X == nil {
		panic("error in unmarshal ecdsa public key")
	}

	/* ------------------ Instantiating Public and Private Key ------------------ */

	rootPQCPubBytes, err := hex.DecodeString(rootPubPqc)
	if err != nil {
		panic(err)
	}

	rootPQCPrivBytesc, err := hex.DecodeString(rootPrivPqc)
	if err != nil {
		panic(err)
	}

	rootCAPub := liboqs_sig.ConstructPublicKey(rootSigID, classicPub, rootPQCPubBytes)
	rootCAPriv := liboqs_sig.ConstructPrivateKey(rootSigID, classicPriv, rootPQCPrivBytesc, rootCAPub)

	return rootCACert, rootCAPriv
}
