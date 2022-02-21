package main

// go run generate_hybrid_root.go hybrid_server_kemtls.go client_stats_pqtls.go

import (
	"bufio"
	"log"
	"os"
	"crypto/elliptic"
	"crypto/liboqs_sig"
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"strconv"
	// tests "tls_tests/hybrid_server_kemtls"
)

func generateRoot(rootCAAlgo interface{}, curve elliptic.Curve) {
	/* ---------------------------- Root Certificate ---------------------------- */

	rootKeyUsage := x509.KeyUsageCertSign

	rootCACertBytes, rootCAPriv, err := createCertificate(rootCAAlgo, nil, nil, true, true, "server", rootKeyUsage, nil)
	if err != nil {
		panic(err)
	}

	/* --------------------------- Private Key Marshal -------------------------- */

	priv, ok := rootCAPriv.(*liboqs_sig.PrivateKey)
	if !ok {
		panic("Aqui")
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


	rootPrivBytes, err := x509.MarshalECPrivateKeyWithOID(priv.Classic, nil)

	if err != nil {
		panic("x509: failed to marshal EC private key while building PKCS#8: " + err.Error())
	}

/* --------------------------- Public Key Marshal --------------------------- */

	pub := priv.HybridPub

	classicPubBytes := elliptic.Marshal(pub.Classic.Curve, pub.Classic.X, pub.Classic.Y)

	/* ----------------------------- Writing to File ---------------------------- */

	sigIDString := strconv.FormatInt(int64(priv.SigId), 16)

	rootCAData := []string{sigIDString, curveString, hex.EncodeToString(oidBytes), hex.EncodeToString(rootPrivBytes), hex.EncodeToString(priv.Pqc), hex.EncodeToString(classicPubBytes), hex.EncodeToString(pub.Pqc), hex.EncodeToString(rootCACertBytes)}
 
	
	file, err := os.OpenFile("hybrid_root_ca.txt", os.O_CREATE|os.O_WRONLY, 0644) 
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

	rootCAAlgo := liboqs_sig.P256_Dilithium2
	curve, _ := liboqs_sig.ClassicFromSig(rootCAAlgo)
	// rootCAAlgo := liboqs_sig.P384_Dilithium3
	// rootCAAlgo := liboqs_sig.P521_Dilithium5

	generateRoot(rootCAAlgo, curve)

} 