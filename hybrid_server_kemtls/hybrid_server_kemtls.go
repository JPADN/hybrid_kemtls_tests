package main

import (
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

var rootCertPEMP256 = `-----BEGIN CERTIFICATE-----
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
`

var rootKeyPEMP256 = `-----BEGIN EC PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQggzl0gcTDyAi7edv5
1aPR0dlDog4XCJdftcdPCjI1xpmhRANCAAR4n0U8wpgVD81/HGgNbUW/8ZoLUT1n
SUvZpntvzZ9nCLFWjf6X/zOO+Zpw9ci+Ob/HDb8ikQZ9GR1L8GStT7fj
-----END EC PRIVATE KEY-----
`

var hsAlgorithms = map[string]tls.CurveID{"Kyber512X25519": tls.Kyber512X25519, "Kyber768X448": tls.Kyber768X448, "Kyber1024X448": tls.Kyber1024X448,
	"SIKEp434X25519": tls.SIKEp434X25519, "SIKEp503X448": tls.SIKEp503X448, "SIKEp751X448": tls.SIKEp751X448}

//sort and returns sorted keys
func sortAlgorithmsMap() (keys []string) {
	//sort the map of algorithms
	output := make([]string, 0, len(hsAlgorithms))
	for k, _ := range hsAlgorithms {
		output = append(output, k)
	}
	sort.Strings(output)
	return output
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

func createHybridCertificate(curveID tls.CurveID, signer *x509.Certificate, signerPrivKey interface{}) ([]byte, *kem.PrivateKey, error) {

	var _validFrom string
	var _validFor time.Duration
	var _host string = "127.0.0.1"

	kemID := kem.ID(curveID)

	hyPub, hyPriv, err := kem.GenerateKey(rand.Reader, kemID)
	if err != nil {
		return nil, nil, err
	}

	/* ----------------- Copied from crypto/tls/generate_cert.go ---------------- */

	// keyUsage := x509.KeyUsageDigitalSignature
	keyUsage := x509.KeyUsageKeyEncipherment // or |=

	var notBefore time.Time
	if len(_validFrom) == 0 {
		notBefore = time.Now()
	} else {
		notBefore, err = time.Parse("Jan 2 15:04:05 2006", _validFrom)
		if err != nil {
			log.Fatalf("Failed to parse creation date: %v", err)
		}
	}

	notAfter := notBefore.Add(_validFor)

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		log.Fatalf("Failed to generate serial number: %v", err)
	}

	hybridTemplate := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: "Hybrid Leaf Certificate",
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
			hybridTemplate.IPAddresses = append(hybridTemplate.IPAddresses, ip)
		} else {
			hybridTemplate.DNSNames = append(hybridTemplate.DNSNames, h)
		}
	}

	/* ----------------------------------- End ---------------------------------- */

	derBytes, err := x509.CreateCertificate(rand.Reader, &hybridTemplate, signer, hyPub, signerPrivKey)
	if err != nil {
		return nil, nil, err
	}

	return derBytes, hyPriv, nil
}

func initServer(curveID tls.CurveID) *tls.Config {
	rootCertP256 := new(tls.Certificate)
	hybridCert := new(tls.Certificate)
	var err error

	/* ---------------------------- Root Certificate ---------------------------- */

	*rootCertP256, err = tls.X509KeyPair([]byte(rootCertPEMP256), []byte(rootKeyPEMP256))
	if err != nil {
		panic(err)
	}

	rootCertP256.Leaf, err = x509.ParseCertificate(rootCertP256.Certificate[0])
	if err != nil {
		panic(err)
	}

	/* ------------------------- Hybrid Leaf Certificate ------------------------ */

	certBytes, certPriv, err := createHybridCertificate(curveID, rootCertP256.Leaf, rootCertP256.PrivateKey)
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

	// The root certificates for the peer.
	cfg.RootCAs = x509.NewCertPool()

	x509Root, err := x509.ParseCertificate(rootCertP256.Certificate[0])
	if err != nil {
		panic(err)
	}
	cfg.RootCAs.AddCert(x509Root)

	cfg.Certificates = make([]tls.Certificate, 1)
	cfg.Certificates[0] = *hybridCert

	return cfg
}

func initClient() *tls.Config {
	ccfg := &tls.Config{
		MinVersion:                 tls.VersionTLS10,
		MaxVersion:                 tls.VersionTLS13,
		InsecureSkipVerify:         true, // Setting it to true due to the fact that it doesn't contain any IP SANs
		SupportDelegatedCredential: false,

		KEMTLSEnabled: true,
	}

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
			if err != nil || n != len(clientMsg) || string(buf[:n]) != clientMsg {
				fmt.Print(err)
			}

			//server responds
			server.Write([]byte(serverMsg))
			if n != len(serverMsg) || err != nil || string(buf[:n]) != serverMsg {
				//error
			}
			fmt.Println("   Server")
			fmt.Printf("   | Receive Client Hello     %v \n", timingState.serverTimingInfo.ProcessClientHello)
			fmt.Printf("   | Write Server Hello       %v \n", timingState.serverTimingInfo.WriteServerHello)
			fmt.Printf("   | Write Server Enc Exts    %v \n", timingState.serverTimingInfo.WriteEncryptedExtensions)
			fmt.Printf("<--| Write Server Certificate %v \n", timingState.serverTimingInfo.WriteCertificate)

			fmt.Println("   Server")
			fmt.Printf("-->| Receive KEM Ciphertext     %v \n", timingState.serverTimingInfo.ReadKEMCiphertext)
			fmt.Printf("   | Receive Client Finished    %v \n", timingState.serverTimingInfo.ReadClientFinished)
			fmt.Printf("<--| Write Server Finished      %v \n", timingState.serverTimingInfo.WriteServerFinished)

			fmt.Printf("Server Total time: %v \n", timingState.serverTimingInfo.FullProtocol)
			if server.ConnectionState().DidKEMTLS {
				fmt.Println("Server Success using kemtls")
			}
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

		fmt.Println("Client")
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

		if client.ConnectionState().DidKEMTLS {
			log.Println("Client Success using kemtls")
		}
	}

	return timingState, true, nil
}
