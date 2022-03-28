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
)

func constructHybridRoot(rootFamily string, securityLevel int) (*x509.Certificate, *liboqs_sig.PrivateKey) {

	/* ------------------------------ Reading file ------------------------------ */
	var rootData []string
	var rootFileName string
	var algList []string

	dilithiumAlg := []string{"P256_Dilithium2", "", "P384_Dilithium3", "", "P521_Dilithium5"}
	falconAlg := []string{"P256_Falcon512", "", "P256_Falcon512", "", "P521_Falcon1024"}

	if rootFamily == "dilithium" {
		algList = dilithiumAlg
	} else if rootFamily == "falcon" {
		algList = falconAlg
	} else {
		panic("Unknown Root CA algorithm family")
	}

	if securityLevel == 1 || securityLevel == 3 || securityLevel == 5 {
		rootFileName = "root_ca/hybrid_root_ca_" + algList[securityLevel-1] + ".txt"
	} else {
		panic("Unknown security level")
	}

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
