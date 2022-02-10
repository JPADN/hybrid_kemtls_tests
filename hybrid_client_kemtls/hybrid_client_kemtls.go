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
	"strings"
	"time"
)

var (
	kexAlgo   = flag.String("kex", "Kyber512X25519", "KEX Algorithm")
	authAlgo  = flag.String("auth", "Kyber512X25519", "Authentication Algorithm")
	
	hsAlgorithms = map[string]tls.CurveID {"Kyber512X25519": tls.Kyber512X25519, "Kyber768X448": tls.Kyber768X448, "Kyber1024X448": tls.Kyber1024X448,
																				 "SIKEp434X25519": tls.SIKEp434X25519, "SIKEp503X448": tls.SIKEp503X448, "SIKEp751X448": tls.SIKEp751X448}
)

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

func createCertificate(pubkeyAlgo interface{}, signer *x509.Certificate, signerPrivKey interface{}, isCA bool, isSelfSigned bool, peer string) ([]byte, interface{}, error) {

	var _validFor time.Duration = 86400000000000  // JP: TODO:
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
		commonName = peer		
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

	var certTemplate x509.Certificate

	if peer == "client" {
		certTemplate = x509.Certificate{
			SerialNumber: serialNumber,
			Subject: pkix.Name{
				CommonName: commonName,
			},
			NotBefore: notBefore,
			NotAfter:  notAfter,

			KeyUsage:              keyUsage,
			ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
			BasicConstraintsValid: true,
		}

	} else {	

		certTemplate = x509.Certificate{
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

func initCAs() (*x509.Certificate, *x509.Certificate, interface{}){
	/* ---------------------------- Root Certificate ---------------------------- */

	rootCAScheme := circlSchemes.ByName("Ed448-Dilithium4")  // or Ed25519-Dilithium3
	if rootCAScheme == nil {
		log.Fatalf("No such Circl scheme: %s", rootCAScheme)
	}

	rootCACertBytes, rootCAPriv, err := createCertificate(rootCAScheme, nil, nil, true, true, "server")
	if err != nil {
		panic(err)
	}

	rootCACert, err := x509.ParseCertificate(rootCACertBytes)
	if err != nil {
		panic(err)
	}
	
	/* ----------------------------- Intermediate CA ---------------------------- */

	intCAScheme := circlSchemes.ByName("Ed448-Dilithium4")  // or Ed25519-Dilithium3
	if intCAScheme == nil {
		log.Fatalf("No such Circl scheme: %s", intCAScheme)
	}

	intCACertBytes, intCAPriv, err := createCertificate(intCAScheme, rootCACert, rootCAPriv, true, false, "server")
	if err != nil {
		panic(err)
	}

	intCACert, err := x509.ParseCertificate(intCACertBytes)
	if err != nil {
		panic(err)
	}

	return rootCACert, intCACert, intCAPriv
}



func initServer(curveID tls.CurveID, intCACert *x509.Certificate, intCAPriv interface{}, rootCA *x509.Certificate) *tls.Config {
	hybridCert := new(tls.Certificate)
	var err error

	certBytes, certPriv, err := createCertificate(curveID, intCACert, intCAPriv, false, false, "server")
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
		InsecureSkipVerify:         false,
		SupportDelegatedCredential: true,
		ClientAuth:                 tls.RequireAndVerifyClientCert,

		KEMTLSEnabled: true,
	}

	hybridCert.Certificate = append(hybridCert.Certificate, intCACert.Raw)

	cfg.Certificates = make([]tls.Certificate, 1)
	cfg.Certificates[0] = *hybridCert

	cfg.ClientCAs = x509.NewCertPool()
	
	cfg.ClientCAs.AddCert(rootCA)

	return cfg
}

func initClient(curveID tls.CurveID, intCACert *x509.Certificate, intCAPriv interface{}, rootCA *x509.Certificate) *tls.Config {
	
	hybridCert := new(tls.Certificate)
	var err error

	certBytes, certPriv, err := createCertificate(curveID, intCACert, intCAPriv, false, false, "client")
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

	ccfg := &tls.Config{
		MinVersion:                 tls.VersionTLS10,
		MaxVersion:                 tls.VersionTLS13,
		InsecureSkipVerify:         false,
		SupportDelegatedCredential: false,

		KEMTLSEnabled: true,
	}

	hybridCert.Certificate = append(hybridCert.Certificate, intCACert.Raw)

	ccfg.Certificates = make([]tls.Certificate, 1)
	ccfg.Certificates[0] = *hybridCert

	ccfg.RootCAs = x509.NewCertPool()
	
	ccfg.RootCAs.AddCert(rootCA)

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

	if peer == "server" {
		if server.ConnectionState().DidKEMTLS && client.ConnectionState().DidKEMTLS {
			return timingState, true, true, client.ConnectionState(), server.ConnectionState(), nil
		}
	}

	return timingState, false, false, cconnState, sconnState, nil
}

func main() {
	flag.Parse()

	kexCurveID, err := nameToCurveID(*kexAlgo)
	if err != nil {
		log.Fatal(err)
	}
	authCurveID, err := nameToCurveID(*authAlgo)
	if err != nil {
		log.Fatal(err)
	}

	serverMsg := "hello, client"
	clientMsg := "hello, server"

	rootCACert, intCACert, intCAPriv := initCAs();

	serverConfig := initServer(authCurveID, intCACert, intCAPriv, rootCACert)
	clientConfig := initClient(authCurveID, intCACert, intCAPriv, rootCACert)
	
	// Select here the algorithm to be used in the KEX
	serverConfig.CurvePreferences = []tls.CurveID{kexCurveID}
	clientConfig.CurvePreferences = []tls.CurveID{kexCurveID}

	fmt.Printf("Starting KEMTLS Handshake:\n\nKEX Algorithm: %s (0x%x)\nAuth Algorithm: %s (0x%x)\n\n", 
							*kexAlgo, kem.ID(kexCurveID),
							*authAlgo, kem.ID(authCurveID))
	

	ts, _, kemtls, _, _, err := testConnWithDC(clientMsg, serverMsg, clientConfig, serverConfig, "server")

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
	fmt.Printf("<--| Write Certificate          %v \n", ts.clientTimingInfo.WriteCertificate)

	fmt.Println("   Server")
	fmt.Printf("-->| Receive KEM Ciphertext         %v \n", ts.serverTimingInfo.ReadKEMCiphertext)
	fmt.Printf("   | Receive Client Certificate     %v \n", ts.serverTimingInfo.ReadCertificate)
	fmt.Printf("<--| Write KEM Ciphertext           %v \n", ts.serverTimingInfo.WriteKEMCiphertext)

	fmt.Println("Client")
	fmt.Printf("-->| Process KEM Ciphertext     %v \n", ts.clientTimingInfo.ReadKEMCiphertext)
	fmt.Printf("<--| Write Client Finished      %v \n", ts.clientTimingInfo.WriteClientFinished)

	fmt.Println("   Server")
	fmt.Printf("-->| Process Client Finished    %v \n", ts.serverTimingInfo.ReadClientFinished)
	fmt.Printf("<--| Write Server Finished      %v \n", ts.serverTimingInfo.WriteServerFinished)

	fmt.Println("Client")
	fmt.Printf("-->| Process Server Finished    %v \n", ts.clientTimingInfo.ReadServerFinished)

	fmt.Printf("Client Total time: %v \n", ts.clientTimingInfo.FullProtocol)
	fmt.Printf("Server Total time: %v \n", ts.serverTimingInfo.FullProtocol)

	if err != nil {
		log.Println("")
		log.Println(err.Error())
	} else if !kemtls {
		log.Println("")
		log.Println("Failure while trying to use kemtls")
	} else {
		log.Println("")
		log.Println("Success using kemtls")
		fmt.Println("\n===========================================================\n")
	}
}
