package main

import (
	"bufio"
	"crypto/elliptic"
	"crypto/liboqs_sig"
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"flag"
	"log"
	"os"
	"strconv"
)

var (
	rootAlgo = flag.String("algo", "P256", "Root CA Algorithm")
)

func generateHybridRoot(rootCAAlgo interface{}, curve elliptic.Curve) {
	/* ---------------------------- Root Certificate ---------------------------- */

	rootKeyUsage := x509.KeyUsageCertSign

	rootCACertBytes, rootCAPriv, err := createCertificate(rootCAAlgo, nil, nil, true, true, "server", rootKeyUsage, nil, "127.0.0.1")
	if err != nil {
		panic(err)
	}

	/* --------------------------- Private Key Marshal -------------------------- */

	priv, ok := rootCAPriv.(*liboqs_sig.PrivateKey)
	if !ok {
		panic("Root CA private key is not liboqs_sig.PrivateKey")
	}

	oid, ok := x509.OidFromNamedCurve(curve)
	if !ok {
		panic("x509: unknown curve while marshaling to PKCS#8")
	}

	oidBytes, err := asn1.Marshal(oid)
	if err != nil {
		panic("x509: failed to marshal curve OID: " + err.Error())
	}

	var curveString string

	switch curve {
	case elliptic.P256():
		curveString = "P256"
	case elliptic.P384():
		curveString = "P384"
	case elliptic.P521():
		curveString = "P521"
	}

	privClassic, privPqc, pub := liboqs_sig.GetPrivateKeyMembers(priv)
	pubClassic, pubPqc := liboqs_sig.GetPublicKeyMembers(pub)

	rootPrivBytes, err := x509.MarshalECPrivateKey(privClassic)
	if err != nil {
		panic("x509: failed to marshal EC private key while building PKCS#8: " + err.Error())
	}

	/* --------------------------- Public Key Marshal --------------------------- */

	classicPubBytes := elliptic.Marshal(pubClassic.Curve, pubClassic.X, pubClassic.Y)

	/* ----------------------------- Writing to File ---------------------------- */

	sigIDString := strconv.FormatInt(int64(priv.SigId), 16)

	rootCAData := []string{sigIDString, curveString, hex.EncodeToString(oidBytes), hex.EncodeToString(rootPrivBytes), hex.EncodeToString(privPqc), hex.EncodeToString(classicPubBytes), hex.EncodeToString(pubPqc), hex.EncodeToString(rootCACertBytes)}
	fileName := "root_ca/hybrid_root_ca_" + *rootAlgo + ".txt"
	file, err := os.OpenFile(fileName, os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Fatalf("failed creating file: %s", err)
	}

	datawriter := bufio.NewWriter(file)

	for _, data := range rootCAData {
		_, _ = datawriter.WriteString(data + "\n")
	}

	datawriter.Flush()
	file.Close()
}

func main() {

	flag.Parse()
	
	rootLiboqsID, err := nameToSigID(*rootAlgo)
	if err != nil {
		panic(err)
	}
		
	curve, _ := liboqs_sig.ClassicFromSig(rootLiboqsID)
	generateHybridRoot(rootLiboqsID, curve)
}
