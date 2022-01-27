package main

import (
	"circl/sign"
	circlSchemes "circl/sign/schemes"
	"crypto/kem"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"flag"
	"fmt"
	"log"
	"math/big"
	"net"
	"sort"
	"strings"
	"time"
)

var (
	kexAlgo    = flag.String("kex", "Kyber512X25519", "KEX Algorithm")
	authAlgo   = flag.String("auth", "Kyber512X25519", "Authentication Algorithm")
	IPserver   = flag.String("ip", "127.0.0.1", "IP of the KEMTLS Server")
	tlspeer    = flag.String("tlspeer", "server", "KEMTLS Peer: client or server")
	handshakes = flag.Int("handshakes", 1, "Number of Handshakes desired")
)

// The Root CA certificate and key were generated with the following program, available in the
// crypto/tls directory:
//
//	go run generate_cert.go -ecdsa-curve P256 -host 127.0.0.1 -ca true

/*var rootCertPEMP256 = `-----BEGIN CERTIFICATE-----
MIIBijCCATGgAwIBAgIRALM63nKUutZeH12Fk/5tChgwCgYIKoZIzj0EAwIwEjEQ
MA4GA1UEChMHQWNtZSBDbzAeFw0yMTA0MTkxMTAyMzhaFw0yMjA0MTkxMTAyMzha
MBIxEDAOBgNVBAoTB0FjbWUgQ28wWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAR4
n0U8wpgVD81/HGgNbUW/8ZoLUT1nSUvZpntvzZ9nCLFWjf6X/zOO+Zpw9ci+Ob/H
Db8ikQZ9GR1L8GStT7fjo2gwZjAOBgNVHQ8BAf8EBAMCAoQwEwYDVR0lBAwwCgYI
KwYBBQUHAwEwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQU3bt5t8hhnxTne+C/
lqWvK7ytdMAwDwYDVR0RBAgwBocEfwAAATAKBggqhkjOPQQDAgNHADBEAiAmR2b0
Zf/yqBQWNjcb5BkEMXXB+HUYbUXWal0cQf8tswIgIN5sngQOABJiFfoJo6PCB2+V
Uf8DiE3gx/2Z4bZugww=
-----END CERTIFICATE-----
`*/

var rootCertPEMED25519Dilithim3 = `-----BEGIN CERTIFICATE-----
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
itnRGPI7iFbEZ5Gs26gi0syPZlZS5T7z4ArdAA==
-----END CERTIFICATE-----
`


/*var rootKeyPEMP256 = `-----BEGIN EC PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQggzl0gcTDyAi7edv5
1aPR0dlDog4XCJdftcdPCjI1xpmhRANCAAR4n0U8wpgVD81/HGgNbUW/8ZoLUT1n
SUvZpntvzZ9nCLFWjf6X/zOO+Zpw9ci+Ob/HDb8ikQZ9GR1L8GStT7fj
-----END EC PRIVATE KEY-----
`*/

var rootKeyPEMED25519Dilithium3 = `-----BEGIN PRIVATE KEY-----
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
Gc+k3PnMPWO2K04jlw==
-----END PRIVATE KEY-----
`

//CIRCL
//var hsAlgorithms = map[string]tls.CurveID{"Kyber512X25519": tls.Kyber512X25519, "Kyber768X448": tls.Kyber768X448, "Kyber1024X448": tls.Kyber1024X448,
//	"SIKEp434X25519": tls.SIKEp434X25519, "SIKEp503X448": tls.SIKEp503X448, "SIKEp751X448": tls.SIKEp751X448}

//LIBOQS 
var hsAlgorithms = map[string]tls.CurveID{
	"Kyber512": tls.OQS_Kyber512, "P256_Kyber512": tls.P256_Kyber512, 
	"Kyber768": tls.OQS_Kyber768, "P384_Kyber768": tls.P384_Kyber768,
	"Kyber1024": tls.OQS_Kyber1024, "P521_Kyber1024": tls.P521_Kyber1024, 
	"LightSaber_KEM":     tls.LightSaber_KEM, "P256_LightSaber_KEM": tls.P256_LightSaber_KEM,
	"Saber_KEM": tls.Saber_KEM, "P384_Saber_KEM": tls.P384_Saber_KEM, 
	"FireSaber_KEM": tls.FireSaber_KEM, "P521_FireSaber_KEM": tls.P521_FireSaber_KEM,
	"NTRU_HPS_2048_509":  tls.NTRU_HPS_2048_509, "P256_NTRU_HPS_2048_509":  tls.P256_NTRU_HPS_2048_509,
	"NTRU_HPS_2048_677":  tls.NTRU_HPS_2048_677, "P384_NTRU_HPS_2048_677":  tls.P384_NTRU_HPS_2048_677,
	"NTRU_HPS_4096_821":  tls.NTRU_HPS_4096_821, "P521_NTRU_HPS_4096_821":  tls.P521_NTRU_HPS_4096_821,
	"NTRU_HPS_4096_1229": tls.NTRU_HPS_4096_1229, "P521_NTRU_HPS_4096_1229": tls.P521_NTRU_HPS_4096_1229,
	"NTRU_HRSS_701": tls.NTRU_HRSS_701, "P384_NTRU_HRSS_701":      tls.P384_NTRU_HRSS_701,
	"NTRU_HRSS_1373": tls.NTRU_HRSS_1373, "P521_NTRU_HRSS_1373":     tls.P521_NTRU_HRSS_1373,						
}

//sort and returns sorted keys
func sortAlgorithmsMap() (keys []string) {
	//sort the map of algorithms
	output := make([]string, 0, len(hsAlgorithms))
	for k, _ := range hsAlgorithms {
		output = append(output, k)
	}
	sort.Strings(output)

	//or return a specific ordering (PQC-only then hybrid interleaved together)
	output2 := []string{"Kyber512", "P256_Kyber512", "Kyber768", "P384_Kyber768",
	"Kyber1024", "P521_Kyber1024", "LightSaber_KEM", "P256_LightSaber_KEM",
	"Saber_KEM", "P384_Saber_KEM", "FireSaber_KEM", "P521_FireSaber_KEM",
	"NTRU_HPS_2048_509", "P256_NTRU_HPS_2048_509",
	"NTRU_HPS_2048_677", "P384_NTRU_HPS_2048_677",
	"NTRU_HPS_4096_821", "P521_NTRU_HPS_4096_821",
	"NTRU_HPS_4096_1229", "P521_NTRU_HPS_4096_1229",
	"NTRU_HRSS_701", "P384_NTRU_HRSS_701", "NTRU_HRSS_1373", "P521_NTRU_HRSS_1373",	
	}

	return output2
}

func nameToCurveID(name string) (tls.CurveID, error) {
	curveID, prs := hsAlgorithms[name]
	if !prs {
		fmt.Println("Algorithm not found. Available algorithms: ")
		for name, _ := range hsAlgorithms {
			fmt.Println(name)
		}
		return 0, errors.New("ERROR: Algorithm not found")
	}
	return curveID, nil
}

func createCertificate(pubkeyAlgo interface{}, signer *x509.Certificate, signerPrivKey interface{}, isCA bool, isSelfSigned bool) ([]byte, interface{}, error) {

	var _validFor time.Duration = 86400000000000 // JP: TODO:
	var _host string = "127.0.0.1"
	var keyUsage x509.KeyUsage
	var commonName string

	var pub, priv interface{}
	var err error

	var certDERBytes []byte

	if isCA {
		if isSelfSigned {
			commonName = "Root CA"
		}
		commonName = "Intermediate CA"
	} else {
		commonName = "Server"
	}

	if curveID, ok := pubkeyAlgo.(tls.CurveID); ok {
		kemID := kem.ID(curveID)

		pub, priv, err = kem.GenerateKey(rand.Reader, kemID)
		if err != nil {
			return nil, nil, err
		}

		keyUsage = x509.KeyUsageKeyEncipherment // or |=

	} else if scheme, ok := pubkeyAlgo.(sign.Scheme); ok {
		pub, priv, err = scheme.GenerateKey()

		if err != nil {
			log.Fatalf("Failed to generate private key: %v", err)
		}

		keyUsage = x509.KeyUsageDigitalSignature
	}

	notBefore := time.Now()

	notAfter := notBefore.Add(_validFor)

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		log.Fatalf("Failed to generate serial number: %v", err)
	}

	certTemplate := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: commonName,
		},
		NotBefore: notBefore,
		NotAfter:  notAfter,

		KeyUsage:              keyUsage,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	hosts := strings.Split(_host, ",")
	for _, h := range hosts {
		if ip := net.ParseIP(h); ip != nil {
			certTemplate.IPAddresses = append(certTemplate.IPAddresses, ip)
		} else {
			certTemplate.DNSNames = append(certTemplate.DNSNames, h)
		}
	}

	if isCA {
		certTemplate.IsCA = true
		certTemplate.KeyUsage |= x509.KeyUsageCertSign
	}

	if isSelfSigned {
		certDERBytes, err = x509.CreateCertificate(rand.Reader, &certTemplate, &certTemplate, pub, priv)
	} else {
		certDERBytes, err = x509.CreateCertificate(rand.Reader, &certTemplate, signer, pub, signerPrivKey)
	}

	if err != nil {
		return nil, nil, err
	}

	return certDERBytes, priv, nil
}

func initCAs(rootCACert *x509.Certificate, rootCAPriv interface{}) (*x509.Certificate, interface{}) {

	/* ----------------------------- Intermediate CA ---------------------------- */

	intCAScheme := circlSchemes.ByName("Ed25519-Dilithium3") // or Ed25519-Dilithium3
	if intCAScheme == nil {
		log.Fatalf("No such Circl scheme: %s", intCAScheme)
	}

	intCACertBytes, intCAPriv, err := createCertificate(intCAScheme, rootCACert, rootCAPriv, true, false)
	if err != nil {
		panic(err)
	}

	intCACert, err := x509.ParseCertificate(intCACertBytes)
	if err != nil {
		panic(err)
	}

	return intCACert, intCAPriv
}

func initServer(curveID tls.CurveID, intCACert *x509.Certificate, intCAPriv interface{}) *tls.Config {
	hybridCert := new(tls.Certificate)
	var err error

	certBytes, certPriv, err := createCertificate(curveID, intCACert, intCAPriv, false, false)
	if err != nil {
		panic(err)
	}

	hybridCert.Certificate = append(hybridCert.Certificate, certBytes)
	hybridCert.PrivateKey = certPriv
	// hybridCert.SupportedSignatureAlgorithms = []tls.SignatureScheme{tls.Ed25519}

	hybridCert.Leaf, err = x509.ParseCertificate(hybridCert.Certificate[0])
	if err != nil {
		panic(err)
	}

	/* ------------------------------ Configuration ----------------------------- */

	cfg := &tls.Config{
		MinVersion:    tls.VersionTLS10,
		MaxVersion:    tls.VersionTLS13,
		KEMTLSEnabled: true,
	}

	hybridCert.Certificate = append(hybridCert.Certificate, intCACert.Raw)

	cfg.Certificates = make([]tls.Certificate, 1)
	cfg.Certificates[0] = *hybridCert

	return cfg
}

func initClient(rootCA *x509.Certificate) *tls.Config {

	ccfg := &tls.Config{
		MinVersion:                 tls.VersionTLS10,
		MaxVersion:                 tls.VersionTLS13,
		InsecureSkipVerify:         false,
		SupportDelegatedCredential: false,

		KEMTLSEnabled: true,
	}

	ccfg.RootCAs = x509.NewCertPool()

	ccfg.RootCAs.AddCert(rootCA)

	return ccfg
}

func newLocalListener(ip string, port string) net.Listener {
	ln, err := net.Listen("tcp", ip+":"+port)
	if err != nil {
		ln, err = net.Listen("tcp6", "[::1]:0")
	}
	if err != nil {
		log.Fatal(err)
	}
	return ln
}

type timingInfo struct {
	serverTimingInfo tls.CFEventTLS13ServerHandshakeTimingInfo
	clientTimingInfo tls.CFEventTLS13ClientHandshakeTimingInfo
}

func (ti *timingInfo) eventHandler(event tls.CFEvent) {
	switch e := event.(type) {
	case tls.CFEventTLS13ServerHandshakeTimingInfo:
		ti.serverTimingInfo = e
	case tls.CFEventTLS13ClientHandshakeTimingInfo:
		ti.clientTimingInfo = e
	}
}

func testConnHybrid(clientMsg, serverMsg string, clientConfig, serverConfig *tls.Config, peer string, ipserver string, port string) (timingState timingInfo, isDC bool, err error) {
	clientConfig.CFEventHandler = timingState.eventHandler
	serverConfig.CFEventHandler = timingState.eventHandler

	bufLen := len(clientMsg)
	if len(serverMsg) > len(clientMsg) {
		bufLen = len(serverMsg)
	}
	buf := make([]byte, bufLen)
	if peer == "server" {
		ln := newLocalListener(ipserver, port)
		defer ln.Close()
		for {

			//			fmt.Println("Server Awaiting connection...")
			//			fmt.Println(ln.Addr().String())

			serverConn, err := ln.Accept()
			if err != nil {
				fmt.Print(err)
			}
			server := tls.Server(serverConn, serverConfig)
			if err := server.Handshake(); err != nil {
				fmt.Printf("Handshake error %v", err)
			}

			//server read client hello
			n, err := server.Read(buf)
			if err != nil || n != len(clientMsg) {
				fmt.Print(err)
			}

			//server responds
			server.Write([]byte(serverMsg))
			if n != len(serverMsg) || err != nil {
				//error
				fmt.Print(err)
			}
			/*fmt.Println("   Server")
			fmt.Printf("   | Receive Client Hello     %v \n", timingState.serverTimingInfo.ProcessClientHello)
			fmt.Printf("   | Write Server Hello       %v \n", timingState.serverTimingInfo.WriteServerHello)
			fmt.Printf("   | Write Server Enc Exts    %v \n", timingState.serverTimingInfo.WriteEncryptedExtensions)
			fmt.Printf("<--| Write Server Certificate %v \n", timingState.serverTimingInfo.WriteCertificate)

			fmt.Println("   Server")
			fmt.Printf("-->| Receive KEM Ciphertext     %v \n", timingState.serverTimingInfo.ReadKEMCiphertext)
			fmt.Printf("   | Receive Client Finished    %v \n", timingState.serverTimingInfo.ReadClientFinished)
			fmt.Printf("<--| Write Server Finished      %v \n", timingState.serverTimingInfo.WriteServerFinished)

			fmt.Printf("Server Total time: %v \n", timingState.serverTimingInfo.FullProtocol)*/
			/*if server.ConnectionState().DidKEMTLS {
				fmt.Println("Server Success using kemtls")
			}*/
		}
	}
	if peer == "client" {

		client, err := tls.Dial("tcp", ipserver+":"+port, clientConfig)
		if err != nil {
			fmt.Print(err)
		}
		defer client.Close()

		client.Write([]byte(clientMsg))

		_, err = client.Read(buf)

		/*fmt.Println("Client")
		fmt.Printf("|--> Write Client Hello       |%v| \n", timingState.clientTimingInfo.WriteClientHello)

		fmt.Println("Client")
		fmt.Printf("-->| Process Server Hello       |%v| \n", timingState.clientTimingInfo.ProcessServerHello)
		fmt.Printf("   | Receive Server Enc Exts    |%v| \n", timingState.clientTimingInfo.ReadEncryptedExtensions)
		fmt.Printf("   | Receive Server Certificate |%v| \n", timingState.clientTimingInfo.ReadCertificate)
		fmt.Printf("   | Write KEM Ciphertext       |%v| \n", timingState.clientTimingInfo.WriteKEMCiphertext)
		fmt.Printf("<--| Write Client Finished      |%v| \n", timingState.clientTimingInfo.WriteClientFinished)

		fmt.Println("Client")
		fmt.Printf("-->| Process Server Finshed       |%v| \n", timingState.clientTimingInfo.ReadServerFinished)
		fmt.Printf("Client Total time: |%v| \n", timingState.clientTimingInfo.FullProtocol)
*/
		/*if client.ConnectionState().DidKEMTLS {
			log.Println("Client Success using kemtls")
		}*/
	}

	return timingState, true, nil
}
