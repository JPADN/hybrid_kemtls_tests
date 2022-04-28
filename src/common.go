package main

import (
	"circl/sign"
	"crypto/elliptic"
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
	IPserver   = flag.String("ipserver", "", "IP of the KEMTLS/PQTLS Server")
	IPclient   = flag.String("ipclient", "", "IP of the KEMTLS/PQTLS Client Auth Certificate")
	handshakes = flag.Int("handshakes", 1, "Number of Handshakes desired")
	clientAuth = flag.Bool("clientauth", false, "Client authentication")
	pqtls      = flag.Bool("pqtls", false, "PQTLS")
	classic    = flag.Bool("classic", false, "TLS with classic algorithms")
	cachedCert = flag.Bool("cachedcert", false, "KEMTLS PDK or PQTLS(cached) server cert.")
	isHTTP = flag.Bool("http", false, "HTTP server")
	classicMcEliece = flag.Bool("classicmceliece", false, "Classic McEliece tests")
)

var (

	// CIRCL Algorithms
	// hsAlgorithms = map[string]tls.CurveID{"Kyber512X25519": tls.Kyber512X25519, "Kyber768X448": tls.Kyber768X448, "Kyber1024X448": tls.Kyber1024X448,
	// 	"SIKEp434X25519": tls.SIKEp434X25519, "SIKEp503X448": tls.SIKEp503X448, "SIKEp751X448": tls.SIKEp751X448}

	// Liboqs Algorithms
	hsKEXAlgorithms = map[string]tls.CurveID{
		"P256": tls.CurveP256, "P384": tls.CurveP384, "P521": tls.CurveP256,
		"Kyber512": tls.OQS_Kyber512, "P256_Kyber512": tls.P256_Kyber512,
		"Kyber768": tls.OQS_Kyber768, "P384_Kyber768": tls.P384_Kyber768,
		"Kyber1024": tls.OQS_Kyber1024, "P521_Kyber1024": tls.P521_Kyber1024,
		"LightSaber_KEM": tls.LightSaber_KEM, "P256_LightSaber_KEM": tls.P256_LightSaber_KEM,
		"Saber_KEM": tls.Saber_KEM, "P384_Saber_KEM": tls.P384_Saber_KEM,
		"FireSaber_KEM": tls.FireSaber_KEM, "P521_FireSaber_KEM": tls.P521_FireSaber_KEM,
		"NTRU_HPS_2048_509": tls.NTRU_HPS_2048_509, "P256_NTRU_HPS_2048_509": tls.P256_NTRU_HPS_2048_509,
		"NTRU_HPS_2048_677": tls.NTRU_HPS_2048_677, "P384_NTRU_HPS_2048_677": tls.P384_NTRU_HPS_2048_677,
		"NTRU_HPS_4096_821": tls.NTRU_HPS_4096_821, "P521_NTRU_HPS_4096_821": tls.P521_NTRU_HPS_4096_821,
		"NTRU_HPS_4096_1229": tls.NTRU_HPS_4096_1229, "P521_NTRU_HPS_4096_1229": tls.P521_NTRU_HPS_4096_1229,
		"NTRU_HRSS_701": tls.NTRU_HRSS_701, "P384_NTRU_HRSS_701": tls.P384_NTRU_HRSS_701,
		"NTRU_HRSS_1373": tls.NTRU_HRSS_1373, "P521_NTRU_HRSS_1373": tls.P521_NTRU_HRSS_1373,
		"P256_Classic-McEliece-348864": tls.P256_Classic_McEliece_348864,
	}

	// Liboqs Algorithms
	hsHybridAuthAlgorithms = map[string]liboqs_sig.ID{
		"P256_Dilithium2": liboqs_sig.P256_Dilithium2, "P256_Falcon512": liboqs_sig.P256_Falcon512,
		"P384_Dilithium3": liboqs_sig.P384_Dilithium3,
		"P521_Dilithium5": liboqs_sig.P521_Dilithium5, "P521_Falcon1024": liboqs_sig.P521_Falcon1024,
	}

	hsClassicAuthAlgorithms = map[string]elliptic.Curve{
		"P256": elliptic.P256(), "P384": elliptic.P384(), "P521": elliptic.P521(),
	}

	// Algorithms to be used in the handshake tests
	testsKEXAlgorithms = []string{
		"Kyber512", "P256_Kyber512", "Kyber768", "P384_Kyber768",
		"Kyber1024", "P521_Kyber1024", "LightSaber_KEM", "P256_LightSaber_KEM",
		"Saber_KEM", "P384_Saber_KEM", "FireSaber_KEM", "P521_FireSaber_KEM",
		"NTRU_HPS_2048_509", "P256_NTRU_HPS_2048_509",
		"NTRU_HPS_2048_677", "P384_NTRU_HPS_2048_677",
		"NTRU_HPS_4096_821", "P521_NTRU_HPS_4096_821",
		"NTRU_HPS_4096_1229", "P521_NTRU_HPS_4096_1229",
		"NTRU_HRSS_701", "P384_NTRU_HRSS_701", "NTRU_HRSS_1373", "P521_NTRU_HRSS_1373",
	}

	testsAuthAlgorithms = []string{
		"P256_Dilithium2", "P256_Falcon512",
		"P384_Dilithium3",
		"P521_Dilithium5", "P521_Falcon1024",
	}
	
	// Classic algorithms (for both KEX and Auth) to be used in the handshake tests
	testsClassicAlgorithms = []string {
		"P256","P384", "P521",
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
func constructChain(secNum int) (rootCertX509 *x509.Certificate, intCACert *x509.Certificate, intCAPriv interface{}) {

	var intCAAlgo, rootPriv interface{}

	if *hybridRootFamily != "" {
		rootCertX509, rootPriv = constructHybridRoot(*hybridRootFamily, secNum)

		intCAAlgo = rootPriv.(*liboqs_sig.PrivateKey).SigId
	} else {
		tempRootCertTLS, err := tls.LoadX509KeyPair(*rootCert, *rootKey)
		if err != nil {
			panic(err)
		}

		rootCertX509, err = x509.ParseCertificate(tempRootCertTLS.Certificate[0])
		if err != nil {
			panic(err)
		}

		rootPriv = tempRootCertTLS.PrivateKey
		
		intCAAlgo = rootPriv.(*ecdsa.PrivateKey).Curve
	}

	// intCACert, intCAPriv = initCAs(rootCertX509, rootPriv, intCAAlgo)

	intKeyUsage := x509.KeyUsageCertSign

	intCACertBytes, intCAPriv, err := createCertificate(intCAAlgo, rootCertX509, rootPriv, true, false, "server", intKeyUsage, nil, "127.0.0.1")
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
	// want same levels for the algos
	reLevel1 := regexp.MustCompile(`P256`)
	reLevel3 := regexp.MustCompile(`P384`)
	reLevel5 := regexp.MustCompile(`P521`)

	if reLevel1.MatchString(k) || k == "Kyber512" || k == "LightSaber_KEM" || k == "NTRU_HPS_2048_509" {
		return 1
	} else {
		if reLevel3.MatchString(k) || k == "Kyber768" || k == "Saber_KEM" || k == "NTRU_HPS_2048_677" || k == "NTRU_HRSS_701" {
			return 3
		} else {
			if reLevel5.MatchString(k) || k == "Kyber1024" || k == "FireSaber_KEM" || k == "NTRU_HPS_4096_821" || k == "NTRU_HPS_4096_1229" || k == "NTRU_HRSS_1373" {
				return 5
			} else {
				panic("Error when recovering NIST security level number.")
			}
		}
	}
}

func nameToCurveID(name string) (tls.CurveID, error) {
	curveID, prs := hsKEXAlgorithms[name]
	if !prs {
		fmt.Println("Algorithm not found. Available algorithms: ")
		for name, _ := range hsKEXAlgorithms {
			fmt.Println(name)
		}
		return 0, errors.New("ERROR: Algorithm not found")
	}
	return curveID, nil
}

func nameToSigID(name string) interface{} {
	var sigId interface{}
	var prs bool

	if *classic {
		sigId, prs = hsClassicAuthAlgorithms[name]
		if prs {
			return sigId
		}
	} else {
		sigId, prs = hsHybridAuthAlgorithms[name]
		if prs {
			return sigId
		}
	}
	panic("Algorithm not found")
}

func curveIDToName(cID tls.CurveID) (name string, e error) {
	for n, id := range hsKEXAlgorithms {
		if id == cID {
			return n, nil
		}
	}
	return "0", errors.New("ERROR: Algorithm not found")
}

func sigIDToName(sigID interface{}) (name string, e error) {

	if *classic {
		sigEC := sigID.(elliptic.Curve)
		for n, id := range hsClassicAuthAlgorithms {
			if id == sigEC {
				return n, nil
			}
		}
	} else {
		lID := sigID.(liboqs_sig.ID)
		
		for n, id := range hsHybridAuthAlgorithms {
			if id == lID {
				return n, nil
			}
		}
	}
	return "0", errors.New("ERROR: Auth Algorithm not found")
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

	} else if scheme, ok := pubkeyAlgo.(sign.Scheme); ok { // CIRCL Signature
		pub, priv, err = scheme.GenerateKey()

		if err != nil {
			log.Fatalf("Failed to generate private key: %v", err)
		}
	} else if scheme, ok := pubkeyAlgo.(liboqs_sig.ID); ok { // Liboqs Hybrid Signature
		pub, priv, err = liboqs_sig.GenerateKey(scheme)

		if err != nil {
			log.Fatalf("Failed to generate private key: %v", err)
		}
	} else if scheme, ok := pubkeyAlgo.(elliptic.Curve); ok {  // ECDSA
		privECDSA, err := ecdsa.GenerateKey(scheme, rand.Reader)
		if err != nil {
			log.Fatalf("Failed to generate private key: %v", err)
		}

		pub = &privECDSA.PublicKey

		priv = privECDSA
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
	} else if *classic {
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
							fmt.Println("Server unsuccessful PQTLS with mutual authentication")
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
						pqtlsSaveCSVServer(timingsFullProtocol, timingsWriteServerHello, timingsWriteCertVerify, kKEX, kAuth, countConnections, handshakeSizes)
						countConnections = 0
						timingsFullProtocol = nil
						timingsWriteCertVerify = nil
						timingsWriteServerHello = nil
					}
				} else {
					fmt.Println("Server unsuccessful PQTLS")
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

		if *pqtls {
			if cconnState.DidPQTLS {

				if *clientAuth {

					if cconnState.DidClientAuthentication {
						log.Println("Client Success using PQTLS with mutual authentication")
					} else {
						log.Println("Client unsuccessful PQTLS with mutual authentication")
						return timingState, cconnState, nil, false
					}

				} else {
					log.Println("Client Success using PQTLS")
				}
			} else {
				log.Println("Client unsuccessful PQTLS")
				return timingState, cconnState, nil, false
			}
		} else if *classic {
			if *clientAuth {
				if cconnState.DidClientAuthentication {
					log.Println("Client Success using TLS with mutual authentication")
				} else {
					log.Println("Client unsuccessful TLS with mutual authentication")
					return timingState, cconnState, nil, false
				}			
			} else {
				log.Println("Client Success using TLS")
			}
		} else {
			if cconnState.DidKEMTLS {
				if *clientAuth {

					if cconnState.DidClientAuthentication {
						log.Println("Client Success using KEMTLS with mutual authentication")
					} else {
						log.Println("Client unsuccessful KEMTLS with mutual authentication")
						return timingState, cconnState, nil, false		
					}

				} else {
					log.Println("Client Success using KEMTLS")
				}

			} else {
				log.Println("Client unsuccessful KEMTLS")
				return timingState, cconnState, nil, false
			}
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