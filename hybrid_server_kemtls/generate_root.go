package main

// go run generate_root.go hybrid_server_kemtls.go stats_pqtls.go stats_kemtls.go plot_functions.go parse_hybrid_root.go

import (
	"bufio"
	"crypto/elliptic"
	"crypto/liboqs_sig"
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"encoding/pem"
	"flag"
	"log"
	"os"
	"strconv"
)

var (
	rootAlgo = flag.String("algo", "P256", "Root CA Algorithm")
	hybrid = flag.Bool("hybrid", false, "Hybrid Root Certificate Authority")
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
	fileName := "hybrid_root_ca_" + *rootAlgo + ".txt"
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

func generateClassicRoot(rootCACurve elliptic.Curve) {
	rootKeyUsage := x509.KeyUsageCertSign

	rootCACertBytes, rootCAPriv, err := createCertificate(rootCACurve, nil, nil, true, true, "server", rootKeyUsage, nil, "127.0.0.1")
	if err != nil {
		panic(err)
	}

	// Writing certificate to PEM file

	certFileName := "root_cert_" + *rootAlgo + ".pem"
	keyFileName := "root_key_" + *rootAlgo + ".pem"

	certOut, err := os.Create(certFileName)
	if err != nil {
		log.Fatalf("Failed to open cert.pem for writing: %v", err)
	}
	if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: rootCACertBytes}); err != nil {
		log.Fatalf("Failed to write data to cert.pem: %v", err)
	}
	if err := certOut.Close(); err != nil {
		log.Fatalf("Error closing cert.pem: %v", err)
	}
	log.Print("wrote cert.pem\n")

	keyOut, err := os.OpenFile(keyFileName, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		log.Fatalf("Failed to open key.pem for writing: %v", err)
		return
	}
	privBytes, err := x509.MarshalPKCS8PrivateKey(rootCAPriv)
	if err != nil {
		log.Fatalf("Unable to marshal private key: %v", err)
	}
	if err := pem.Encode(keyOut, &pem.Block{Type: "PRIVATE KEY", Bytes: privBytes}); err != nil {
		log.Fatalf("Failed to write data to key.pem: %v", err)
	}
	if err := keyOut.Close(); err != nil {
		log.Fatalf("Error closing key.pem: %v", err)
	}
	log.Print("wrote key.pem\n")
}

func main() {

	flag.Parse()

	if *hybrid {
		rootSigInterface := nameToHybridSigID(*rootAlgo)

		rootSigID, ok := rootSigInterface.(liboqs_sig.ID)
		if !ok {
			panic("Not a Liboqs Hybrid Signature")
		}

		curve, _ := liboqs_sig.ClassicFromSig(rootSigID)
		generateHybridRoot(rootSigID, curve)
	} else {
		var rootAlgoCurve elliptic.Curve

		switch *rootAlgo {
		case "P256":
			rootAlgoCurve = elliptic.P256()
		case "P384":
			rootAlgoCurve = elliptic.P384()
		case "P521":
			rootAlgoCurve = elliptic.P521()
		}

		generateClassicRoot(rootAlgoCurve)
	}
}
