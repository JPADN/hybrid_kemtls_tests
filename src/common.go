package main

import (
	"crypto/ecdsa"
	"crypto/kem"
	"crypto/liboqs_sig"
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
	"net/http"
	"regexp"
	"strings"
	"time"
)

// Command line flags
var (
	kex = flag.String("kex", "", "Key Exchange algorithm")
	auth = flag.String("authserver", "", "Authentication algorithm")
	rootCert = flag.String("rootcert", "", "Path to the root CA certificate PEM file")
	rootKey = flag.String("rootkey", "", "Path to the root CA private key PEM file")
	hybridRootFamily = flag.String("hybridroot", "", "Hybrid Root CA Algorithm family name")
	IPserver   = flag.String("ipserver", "", "IP of the KEMTLS/TLS Server")
	IPclient   = flag.String("ipclient", "", "IP of the KEMTLS/TLS Client Auth Certificate")
	handshakes = flag.Int("handshakes", 1, "Number of Handshakes desired")
	clientAuth = flag.Bool("clientauth", false, "Client authentication")
	pqtls      = flag.Bool("pqtls", false, "PQTLS")
	classic    = flag.Bool("classic", false, "TLS with classic algorithms")
	cachedCert = flag.Bool("cachedcert", false, "KEMTLS PDK or TLS(cached) server cert.")
	isHTTP = flag.Bool("http", false, "HTTP server")
	classicMcEliece = flag.Bool("classicmceliece", false, "Classic McEliece tests")
)

var (
	hsKEXAlgorithms = map[string]tls.CurveID{		
		// "P256_BIKE_L1": tls.P256_BIKE_L1, "P384_BIKE_L3": tls.P384_BIKE_L3, "P521_BIKE_L5": tls.P521_BIKE_L5,
		// "P256_HQC_128": tls.P256_HQC_128, "P384_HQC_192": tls.P384_HQC_192, "P521_HQC_256": tls.P521_HQC_256,
		"P256_Kyber512": tls.P256_Kyber512, "P384_Kyber768": tls.P384_Kyber768, "P521_Kyber1024": tls.P521_Kyber1024,
	}

	hsHybridSignatureAlgorithms = map[string]liboqs_sig.ID{  // TODO
		"P256_Dilithium2": liboqs_sig.P256_Dilithium2,
		"P384_Dilithium3": liboqs_sig.P384_Dilithium3,
		"P521_Dilithium5": liboqs_sig.P521_Dilithium5,
	}

	// Algorithms to be used in the handshake tests
	testsKEXAlgorithms = []string{
		// "P256_HQC_128", "P256_BIKE_L1", 
		// "P384_HQC_192", "P384_BIKE_L3", 
		// "P521_HQC_256","P521_BIKE_L5",
		"P256_Kyber512", "P384_Kyber768", "P521_Kyber1024",
	}

	testsSignatureAlgorithms = []string{  // TODO
		"P256_Dilithium2",
		"P384_Dilithium3",
		"P521_Dilithium5",
	}

	classicMcElieceAlgorithms = map[int]string {
		1: "Classic_McEliece1", 3: "Classic_McEliece3", 5: "Classic_McEliece5",  // TODO
	}

	clientHSMsg = "hello, server"
	serverHSMsg = "hello, client"	
)

// Initialize client TLS configuration and certificate chain
func initClientAndAuth(k, kAuth string) (*tls.Config, error) {
	var clientConfig *tls.Config
	
	kexCurveID, err := nameToCurveID(k)
	if err != nil {
		return nil, err
	}	
	
	securityLevelNum := getSecurityLevel(k)
	
	rootCertX509, intCACert, intCAPriv := constructChain(securityLevelNum)	

	if *pqtls || *classic {
		var reLevel1, reLevel3, reLevel5 *regexp.Regexp

		//want same levels for the algos
		reLevel1 = regexp.MustCompile(`P256`)
		reLevel3 = regexp.MustCompile(`P384`)
		reLevel5 = regexp.MustCompile(`P521`)
				
		securityLevelKauthNum := getSecurityLevel(kAuth)

		// auth in the same level
		if securityLevelNum != securityLevelKauthNum {
			return nil, nil
		}

		//only hybrids
		if !reLevel1.MatchString(k) && !reLevel3.MatchString(k) && !reLevel5.MatchString(k) {
			return nil, nil
		}
		if !reLevel1.MatchString(kAuth) && !reLevel3.MatchString(kAuth) && !reLevel5.MatchString(kAuth) {
			return nil, nil
		}

		authSig := nameToSigID(kAuth)
		clientConfig = initClient(authSig, intCACert, intCAPriv, rootCertX509)
	} else {
		authCurveID, err := nameToCurveID(kAuth)
		if err != nil {
			return nil, err
		}	

		clientConfig = initClient(authCurveID, intCACert, intCAPriv, rootCertX509)
	}

	clientConfig.CurvePreferences = []tls.CurveID{kexCurveID}

	return clientConfig, nil
}

// Construct Certificate Authority chain (Root CA and Intermediate CA)
func constructChain(securityLevel int) (rootCertX509 *x509.Certificate, intCACert *x509.Certificate, intCAPriv interface{}) {

	var intCAAlgo, rootPriv interface{}

	rootCertX509, rootPriv = constructHybridRoot(*hybridRootFamily, securityLevel)

	switch securityLevel {
	case 1:
		intCAAlgo = liboqs_sig.P256_Dilithium2
	case 3:
		intCAAlgo = liboqs_sig.P384_Dilithium3
	case 5:
		intCAAlgo = liboqs_sig.P521_Dilithium5
	}

	intCACertBytes, intCAPriv, err := createCertificate(intCAAlgo, rootCertX509, rootPriv, true, false, "server", x509.KeyUsageCertSign, nil, "127.0.0.1")
	if err != nil {
		panic(err)
	}

	intCACert, err = x509.ParseCertificate(intCACertBytes)
	if err != nil {
		panic(err)
	}

	return rootCertX509, intCACert, intCAPriv
}

func getSecurityLevel(k string) (level int) {
	reLevel1 := regexp.MustCompile(`P256`)
	reLevel3 := regexp.MustCompile(`P384`)
	reLevel5 := regexp.MustCompile(`P521`)

	if reLevel1.MatchString(k) {
		return 1
	} else if reLevel3.MatchString(k) {
		return 3
	} else if reLevel5.MatchString(k) {			
		return 5
	} else {
		panic("Error when recovering NIST security level number.")
	}	
}

func nameToCurveID(name string) (tls.CurveID, error) {
	curveID, prs := hsKEXAlgorithms[name]	
	if prs {
		return curveID, nil
	}
	return 0, errors.New("Error: key exchange algorithm not found")
}

func nameToSigID(name string) (liboqs_sig.ID, error) {
	sigId, prs := hsHybridSignatureAlgorithms[name]
	if prs {
		return sigId, nil
	}	
	return 0, errors.New("Error: signature algorithm not found")
}

func curveIDToName(cID tls.CurveID) (name string, e error) {
	for n, id := range hsKEXAlgorithms {
		if id == cID {
			return n, nil
		}
	}
	return "0", errors.New("Error: key exchange algorithm not found")
}

func sigIDToName(sigID interface{}) (name string, e error) {
	lID := sigID.(liboqs_sig.ID)
	
	for n, id := range hsHybridSignatureAlgorithms {
		if id == lID {
			return n, nil
		}
	}

	return "0", errors.New("Error: signature algorithm not found")
}

// Creates a certificate with the algorithm specified by pubkeyAlgo, signed by signer with signerPrivKey
func createCertificate(pubkeyAlgo interface{}, signer *x509.Certificate, signerPrivKey interface{}, isCA bool, isSelfSigned bool, peer string, keyUsage x509.KeyUsage, extKeyUsage []x509.ExtKeyUsage, hostName string) ([]byte, interface{}, error) {

	var _validFor time.Duration

	if isCA {
		_validFor = 8760 * time.Hour // 1 year
	} else {
		_validFor = 240 * time.Hour // 10 days
	}

	//fix for testing remotely.
	if hostName == "0.0.0.0" {
		hostName = "34.116.197.232" //"34.116.206.139"
	}

	var _host string = hostName
	var commonName string

	var pub, priv interface{}
	var err error

	var certDERBytes []byte

	if isCA {
		if isSelfSigned {
			commonName = "Root CA"
		} else {
			commonName = "Intermediate CA"
		}
	} else {
		commonName = peer
	}

	if curveID, ok := pubkeyAlgo.(tls.CurveID); ok { // Hybrid KEMTLS
		kemID := kem.ID(curveID)

		pub, priv, err = kem.GenerateKey(rand.Reader, kemID)
		if err != nil {
			return nil, nil, err
		}
	} else if scheme, ok := pubkeyAlgo.(liboqs_sig.ID); ok { // Liboqs Hybrid Signature
		pub, priv, err = liboqs_sig.GenerateKey(scheme)

		if err != nil {
			log.Fatalf("Failed to generate private key: %v", err)
		}
	}

	notBefore := time.Now()
	notAfter := notBefore.Add(_validFor)
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		log.Fatalf("Failed to generate serial number: %v", err)
	}

	var certTemplate x509.Certificate

	certTemplate = x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: commonName,
		},
		NotBefore: notBefore,
		NotAfter:  notAfter,

		KeyUsage:              keyUsage,
		ExtKeyUsage:           extKeyUsage,
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

// Initialize Server's TLS configuration
func initServer(certAlgo interface{}, intCACert *x509.Certificate, intCAPriv interface{}, rootCA *x509.Certificate) *tls.Config {
	var err error
	var cfg *tls.Config
	var serverKeyUsage x509.KeyUsage

	cfg = &tls.Config{
		MinVersion:                 tls.VersionTLS10,
		MaxVersion:                 tls.VersionTLS13,
		InsecureSkipVerify:         false,
		SupportDelegatedCredential: false,
	}

	if *pqtls {
		cfg.PQTLSEnabled = true
		serverKeyUsage = x509.KeyUsageDigitalSignature
	} else if *classic {
		serverKeyUsage = x509.KeyUsageDigitalSignature
	} else {
		cfg.KEMTLSEnabled = true
		serverKeyUsage = x509.KeyUsageKeyAgreement
	}

	if *clientAuth {
		cfg.ClientAuth = tls.RequireAndVerifyClientCert
	}

	serverExtKeyUsage := []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}

	certBytes, certPriv, err := createCertificate(certAlgo, intCACert, intCAPriv, false, false, "server", serverKeyUsage, serverExtKeyUsage, *IPserver)
	if err != nil {
		panic(err)
	}

	hybridCert := new(tls.Certificate)

	hybridCert.Certificate = append(hybridCert.Certificate, certBytes)
	hybridCert.PrivateKey = certPriv

	hybridCert.Leaf, err = x509.ParseCertificate(hybridCert.Certificate[0])
	if err != nil {
		panic(err)
	}

	hybridCert.Certificate = append(hybridCert.Certificate, intCACert.Raw)

	cfg.Certificates = make([]tls.Certificate, 1)
	cfg.Certificates[0] = *hybridCert

	if *clientAuth {
		cfg.ClientCAs = x509.NewCertPool()
		cfg.ClientCAs.AddCert(rootCA)
	}

	return cfg
}

// Initializes Client's TLS configuration
func initClient(certAlgo interface{}, intCACert *x509.Certificate, intCAPriv interface{}, rootCA *x509.Certificate) *tls.Config {
	var clientKeyUsage x509.KeyUsage

	ccfg := &tls.Config{
		MinVersion:                 tls.VersionTLS10,
		MaxVersion:                 tls.VersionTLS13,
		InsecureSkipVerify:         false,
		SupportDelegatedCredential: false,
	}

	if *pqtls {
		ccfg.PQTLSEnabled = true
		clientKeyUsage = x509.KeyUsageDigitalSignature
	} else {
		ccfg.KEMTLSEnabled = true
		clientKeyUsage = x509.KeyUsageKeyAgreement
	}

	if *clientAuth {

		hybridCert := new(tls.Certificate)
		var err error

		clientExtKeyUsage := []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}

		certBytes, certPriv, err := createCertificate(certAlgo, intCACert, intCAPriv, false, false, "client", clientKeyUsage, clientExtKeyUsage, *IPclient)
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

		hybridCert.Certificate = append(hybridCert.Certificate, intCACert.Raw)
		ccfg.Certificates = make([]tls.Certificate, 1)
		ccfg.Certificates[0] = *hybridCert
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

// Performs the Test connections in the server side or the client side
func testConnHybrid(clientMsg, serverMsg string, tlsConfig *tls.Config, peer string, ipserver string, port string) (timingState timingInfo, cconnState tls.ConnectionState, err error, success bool) {	
	tlsConfig.CFEventHandler = timingState.eventHandler
	
	if peer == "server" {

		handshakeSizes := make(map[string]uint32)
		
		var timingsFullProtocol []float64
		var timingsWriteServerHello []float64
		var timingsWriteCertVerify []float64
		var timingsReadKEMCiphertext []float64		
		
		buf := make([]byte, len(clientMsg))

		countConnections := 0

		ln := newLocalListener(ipserver, port)
		defer ln.Close()

		ignoreFirstConn := false
		
		if *cachedCert {
			ignoreFirstConn = true
		}
		
		for {

			serverConn, err := ln.Accept()
			if err != nil {
				fmt.Print(err)
				fmt.Print("error 1 %v", err)
			}
			server := tls.Server(serverConn, tlsConfig)
			if err := server.Handshake(); err != nil {
				fmt.Printf("Handshake error %v", err)
			}			

			//server read client hello
			n, err := server.Read(buf)
			if err != nil || n != len(clientMsg) {
				fmt.Print(err)
				fmt.Print("error 2 %v", err)
			}

			//server responds
			n, err = server.Write([]byte(serverMsg))
			if n != len(serverMsg) || err != nil {
				//error
				fmt.Print(err)
				fmt.Print("error 3 %v", err)
			}

			if ignoreFirstConn {
				ignoreFirstConn = false
				continue				
			}		

			countConnections++

			cconnState = server.ConnectionState()			

			if *pqtls || *classic {

				if (*pqtls && cconnState.DidPQTLS) || *classic {
										
					if *clientAuth {
						if !cconnState.DidClientAuthentication {
							fmt.Println("Server unsuccessful TLS with mutual authentication")
							continue
						}
					}

					timingsFullProtocol = append(timingsFullProtocol, float64(timingState.serverTimingInfo.FullProtocol)/float64(time.Millisecond))
					timingsWriteServerHello = append(timingsWriteServerHello, float64(timingState.serverTimingInfo.WriteServerHello)/float64(time.Millisecond))
					timingsWriteCertVerify = append(timingsWriteCertVerify, float64(timingState.serverTimingInfo.WriteCertificateVerify)/float64(time.Millisecond))

					if countConnections == *handshakes {
						var kAuth string
						var err error

						kKEX, e := curveIDToName(tlsConfig.CurvePreferences[0])
						if e != nil {
							fmt.Print("4 %v", err)
						}

						if *classic {							
							priv, _ := tlsConfig.Certificates[0].PrivateKey.(*ecdsa.PrivateKey)
							kAuth, err = sigIDToName(priv.PublicKey.Curve)							
						} else {							
							priv, _ := tlsConfig.Certificates[0].PrivateKey.(*liboqs_sig.PrivateKey)
							kAuth, err = sigIDToName(priv.SigId)
						}
						
						if err != nil {
							fmt.Print("5 %v", err)
						}

						handshakeSizes["ServerHello"] = cconnState.ServerHandshakeSizes.ServerHello
						handshakeSizes["EncryptedExtensions"] = cconnState.ServerHandshakeSizes.EncryptedExtensions
						handshakeSizes["Certificate"] = cconnState.ServerHandshakeSizes.Certificate
						handshakeSizes["CertificateRequest"] = cconnState.ServerHandshakeSizes.CertificateRequest
						handshakeSizes["CertificateVerify"] = cconnState.ServerHandshakeSizes.CertificateVerify
						handshakeSizes["Finished"] = cconnState.ServerHandshakeSizes.Finished

						//kAuth := tlsConfig.Certificates[0].Leaf.PublicKeyAlgorithm.String()
						tlsSaveCSVServer(timingsFullProtocol, timingsWriteServerHello, timingsWriteCertVerify, kKEX, kAuth, countConnections, handshakeSizes)
						countConnections = 0
						timingsFullProtocol = nil
						timingsWriteCertVerify = nil
						timingsWriteServerHello = nil
					}
				} else {
					fmt.Println("Server unsuccessful TLS")
					continue
				}
			} else {
				if cconnState.DidKEMTLS {

					if *clientAuth {
						if !cconnState.DidClientAuthentication {
							fmt.Println("Server unsuccessful KEMTLS with mutual authentication")
							continue
						}
					}

					timingsFullProtocol = append(timingsFullProtocol, float64(timingState.serverTimingInfo.FullProtocol)/float64(time.Millisecond))
					timingsWriteServerHello = append(timingsWriteServerHello, float64(timingState.serverTimingInfo.WriteServerHello)/float64(time.Millisecond))
					timingsReadKEMCiphertext = append(timingsReadKEMCiphertext, float64(timingState.serverTimingInfo.ReadKEMCiphertext)/float64(time.Millisecond))

					if countConnections == *handshakes {
						kKEX, e := curveIDToName(tlsConfig.CurvePreferences[0])
						if e != nil {
							fmt.Print("4 %v", err)
						}

						handshakeSizes["ServerHello"] = cconnState.ServerHandshakeSizes.ServerHello
						handshakeSizes["EncryptedExtensions"] = cconnState.ServerHandshakeSizes.EncryptedExtensions
						handshakeSizes["Certificate"] = cconnState.ServerHandshakeSizes.Certificate
						handshakeSizes["CertificateRequest"] = cconnState.ServerHandshakeSizes.CertificateRequest
						handshakeSizes["ServerKEMCiphertext"] = cconnState.ServerHandshakeSizes.ServerKEMCiphertext
						handshakeSizes["Finished"] = cconnState.ServerHandshakeSizes.Finished

						kemtlsSaveCSVServer(timingsFullProtocol, timingsWriteServerHello, timingsReadKEMCiphertext, kKEX, countConnections, handshakeSizes)
						countConnections = 0
						timingsFullProtocol = nil
						timingsReadKEMCiphertext = nil
						timingsWriteServerHello = nil
					}

				} else {
					fmt.Println("Server unsuccessful KEMTLS")
					continue
				}
			}
		}
	}

	if peer == "client" {

		buf := make([]byte, len(serverMsg))

		client, err := tls.Dial("tcp", ipserver+":"+port, tlsConfig)
		if err != nil {
			fmt.Print(err)
		}
		defer client.Close()

		client.Write([]byte(clientMsg))

		_, err = client.Read(buf)		

		cconnState = client.ConnectionState()

		if *pqtls && !cconnState.DidPQTLS {
			log.Println("Client unsuccessful PQTLS")
			return timingState, cconnState, nil, false
		}

		if *clientAuth && !cconnState.DidClientAuthentication {					
			if *pqtls {
				log.Println("Client unsuccessful PQTLS with mutual authentication")	
			} else {
				log.Println("Client unsuccessful KEMTLS with mutual authentication")	
			}
			return timingState, cconnState, nil, false				
		}

		if !*pqtls && !cconnState.DidKEMTLS {
			log.Println("Client unsuccessful KEMTLS")
			return timingState, cconnState, nil, false
		}		
	}

	return timingState, cconnState, nil, true
}

func launchHTTPSServer(serverConfig *tls.Config, port string) {
	http.Handle("/", http.FileServer(http.Dir("./static")))
	
	addr := ":"+ port

	server := &http.Server{
		Addr: addr, 
		Handler: nil,
		TLSConfig: serverConfig,
	}

	err := server.ListenAndServeTLS("", "")
	
	if err != nil {
			log.Fatal("ListenAndServe: ", err)
	}
}