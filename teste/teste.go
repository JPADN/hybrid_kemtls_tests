package main

import (
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"crypto/kem"
	"crypto/rand"
	"fmt"
	"log"
	"net"
	"time"
	"math/big"
	"strings"
)

// These test cert and keys were generated with the following program, available in the
// crypto/tls directory:
//
//	go run generate_cert.go -ecdsa-curve P256 -host 127.0.0.1 -ca

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

var hsAlgorithms = []tls.CurveID{tls.Kyber512X25519}  // , tls.Kyber768X448, tls.Kyber1024X448, tls.SIKEp434X25519, tls.SIKEp503X448, tls.SIKEp751X448

// /home/jpadn/projects/labsec/go_stuff/go-kemtls-hybrid-kems/bin/go run generate_cert.go -host localhost -ca true -ed25519 true
// openssl x509 -in hybridCert.pem -text -noout

func createHybridCertificate(signer *x509.Certificate, signerPrivKey interface{}) ([]byte, *kem.PrivateKey, error) {

	var _validFrom string
	var _validFor time.Duration
	var _host string = "127.0.0.1"

	hyPub, hyPriv, err := kem.GenerateKey(rand.Reader, kem.Kyber512X25519)
	if err != nil {
		return nil, nil, err
	}

	/* ------------------------------------ . ----------------------------------- */
	// keyUsage := x509.KeyUsageDigitalSignature
	keyUsage := x509.KeyUsageKeyEncipherment  // or |=

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
	/* ------------------------------------ . ----------------------------------- */

	derBytes, err := x509.CreateCertificate(rand.Reader, &hybridTemplate, signer, hyPub, signerPrivKey)
	if err != nil {
		return nil, nil, err
	}

	return derBytes, hyPriv, nil
}
/* ----------------------------------- End ---------------------------------- */

func initServer() *tls.Config {
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

	certBytes, certPriv, err := createHybridCertificate(rootCertP256.Leaf, rootCertP256.PrivateKey)
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

func newLocalListener() net.Listener {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
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

func testConnWithDC(clientMsg, serverMsg string, clientConfig, serverConfig *tls.Config, peer string) (timingState timingInfo, dcUsed bool, kemtlsUsed bool, cconnState, sconnState tls.ConnectionState, err error) {
	clientConfig.CFEventHandler = timingState.eventHandler
	serverConfig.CFEventHandler = timingState.eventHandler

	ln := newLocalListener()
	defer ln.Close()

	serverCh := make(chan *tls.Conn, 1)
	var serverErr error
	go func() {
		serverConn, err := ln.Accept()
		if err != nil {
			serverErr = err
			serverCh <- nil
			return
		}
		server := tls.Server(serverConn, serverConfig)
		if err := server.Handshake(); err != nil {
			serverErr = fmt.Errorf("handshake error: %v", err)
			serverCh <- nil
			return
		}
		serverCh <- server
	}()

	client, err := tls.Dial("tcp", ln.Addr().String(), clientConfig)
	if err != nil {
		return timingState, false, false, cconnState, sconnState, err
	}
	defer client.Close()

	server := <-serverCh
	if server == nil {
		return timingState, false, false, cconnState, sconnState, err
	}

	bufLen := len(clientMsg)
	if len(serverMsg) > len(clientMsg) {
		bufLen = len(serverMsg)
	}
	buf := make([]byte, bufLen)

	client.Write([]byte(clientMsg))
	n, err := server.Read(buf)
	if err != nil || n != len(clientMsg) || string(buf[:n]) != clientMsg {
		return timingState, false, false, cconnState, sconnState, fmt.Errorf("Server read = %d, buf= %q; want %d, %s", n, buf, len(clientMsg), clientMsg)
	}

	server.Write([]byte(serverMsg))
	n, err = client.Read(buf)
	if n != len(serverMsg) || err != nil || string(buf[:n]) != serverMsg {
		return timingState, false, false, cconnState, sconnState, fmt.Errorf("Client read = %d, %v, data %q; want %d, nil, %s", n, err, buf, len(serverMsg), serverMsg)
	}

	if peer == "client" {
		if server.ConnectionState().DidKEMTLS && client.ConnectionState().DidKEMTLS {
			return timingState, true, true, client.ConnectionState(), server.ConnectionState(), nil
		}
	}

	return timingState, false, false, cconnState, sconnState, nil
}

func main() {
	serverMsg := "hello, client"
	clientMsg := "hello, server"

	for _, curveId := range hsAlgorithms {

		serverConfig := initServer()
		clientConfig := initClient()
		
		// Select here the algorithm to be used in the KEX
		serverConfig.CurvePreferences = []tls.CurveID{curveId}
		clientConfig.CurvePreferences = []tls.CurveID{curveId}
		
		fmt.Printf("------------- KEMTLS -------------\n\n")

		ts, dc, kemtls, _, _, err := testConnWithDC(clientMsg, serverMsg, clientConfig, serverConfig, "client")

		fmt.Println("Client")
		fmt.Printf("|--> Write Client Hello       %v \n", ts.clientTimingInfo.WriteClientHello)
		fmt.Println("   Server")
		fmt.Printf("   | Receive Client Hello     %v \n", ts.serverTimingInfo.ProcessClientHello)
		fmt.Printf("   | Write Server Hello       %v \n", ts.serverTimingInfo.WriteServerHello)
		fmt.Printf("   | Write Server Enc Exts    %v \n", ts.serverTimingInfo.WriteEncryptedExtensions)
		fmt.Printf("<--| Write Server Certificate %v \n", ts.serverTimingInfo.WriteCertificate)

		fmt.Println("Client")
		fmt.Printf("-->| Process Server Hello       %v \n", ts.clientTimingInfo.ProcessServerHello)
		fmt.Printf("   | Receive Server Enc Exts    %v \n", ts.clientTimingInfo.ReadEncryptedExtensions)
		fmt.Printf("   | Receive Server Certificate %v \n", ts.clientTimingInfo.ReadCertificate)
		fmt.Printf("   | Write KEM Ciphertext       %v \n", ts.clientTimingInfo.WriteKEMCiphertext)
		fmt.Printf("<--| Write Client Finished      %v \n", ts.clientTimingInfo.WriteClientFinished)

		fmt.Println("   Server")
		fmt.Printf("-->| Receive KEM Ciphertext     %v \n", ts.serverTimingInfo.ReadKEMCiphertext)
		fmt.Printf("   | Receive Client Finished    %v \n", ts.serverTimingInfo.ReadClientFinished)
		fmt.Printf("<--| Write Server Finished      %v \n", ts.serverTimingInfo.WriteServerFinished)

		fmt.Println("Client")
		fmt.Printf("-->| Process Server Finshed       %v \n", ts.clientTimingInfo.ReadServerFinished)
		fmt.Printf("Client Total time: %v \n", ts.clientTimingInfo.FullProtocol)
		fmt.Printf("Server Total time: %v \n", ts.serverTimingInfo.FullProtocol)

		if err != nil {
			log.Println("")
			log.Println(err.Error())
		} else if !dc && !kemtls {
			log.Println("")
			log.Println("Failure while trying to use kemtls with dcs")
		} else {
			log.Println("")
			// log.Println("Success using kemtls (kem: kyber512, kemSig: kyber512) with dc")
			/* -------------------------------- Modified -------------------------------- */
			log.Println("Success using kemtls with dc")
			/* ----------------------------------- End ---------------------------------- */
		}
	}
}
