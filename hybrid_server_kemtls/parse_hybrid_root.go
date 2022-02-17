package main

import (
	"crypto/x509"
	"fmt"
	"log"
	"crypto/liboqs_sig"

	// For readHybridRootFile
	"bufio"
	"os"
	"strconv"

	// For Hybrid Root CA
	"encoding/hex"
	"encoding/asn1"
	"crypto/ecdsa"
	"crypto/elliptic"
)


func constructHybridRoot() (*x509.Certificate, *liboqs_sig.PrivateKey) {

	/* ------------------------------ Reading file ------------------------------ */
	var rootData []string

	// JP - TODO: Fix that if we change the directory for the hybrid root CA generation
	file, err := os.Open("hybrid_root_ca.txt")
	if err != nil {
			log.Fatal(err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	
	// optionally, resize scanner's capacity for lines over 64K

	// const maxCapacity = longLineLen  // your required line length
	// buf := make([]byte, maxCapacity)
	// scanner.Buffer(buf, maxCapacity)

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
	fmt.Println("---")
	fmt.Println(rootSigIDString)
	fmt.Println("---")
	
	rootSigIDInt, err := strconv.ParseUint(rootSigIDString, 16, 16)
	if err != nil {
		panic(err)
	}

	rootSigID := liboqs_sig.ID(rootSigIDInt)
	fmt.Println(rootSigID)


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

	classicPriv, err := x509.ParseECPrivateKeyGambiarra(namedCurveOID, privBytes)
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


	classicPub.X, classicPub.Y =	elliptic.Unmarshal(classicPub.Curve, classicBytes)
	if classicPub.X == nil {
		panic("error in unmarshal ecdsa public key")
	}	

	/* ------------------ Instantiating Public and Private Key ------------------ */

	rootCAPub := new(liboqs_sig.PublicKey)
	rootCAPub.SigId = rootSigID
	rootCAPub.Classic = classicPub
	rootCAPub.Pqc, err = hex.DecodeString(rootPubPqc)
	if err != nil {
		panic(err)
	}

	rootCAPriv := new(liboqs_sig.PrivateKey)
	rootCAPriv.SigId = rootSigID
	rootCAPriv.Classic = classicPriv
	rootCAPriv.Pqc, err = hex.DecodeString(rootPrivPqc)
	if err != nil {
		panic(err)
	}

	rootCAPriv.HybridPub = rootCAPub

	return rootCACert, rootCAPriv
}