package main

//run with /.../go-kemtls/bin/go run launch_servers.go hybrid_server_kemtls.go

import (
	"crypto/tls"
	"flag"
	"fmt"
	"log"
	"sync"
	"crypto/x509"
)

/*var (
	kexAlgo    = flag.String("kex", "Kyber512X25519", "KEX Algorithm")
	authAlgo   = flag.String("auth", "Kyber512X25519", "Authentication Algorithm")
	IPserver   = flag.String("ip", "127.0.0.1", "IP of the KEMTLS Server")
	tlspeer    = flag.String("tlspeer", "server", "KEMTLS Peer: client or server")
	handshakes = flag.Int("handshakes", 1, "Number of Handshakes desired")
)*/

var wg sync.WaitGroup

//wrapper function to start a server in each port
func startServerHybrid(serverMsg string, serverConfig *tls.Config, ipserver string, port string) {
	//defer wg.Done()
	go testConnHybrid(serverMsg, serverMsg, serverConfig, serverConfig, "server", ipserver, port)
}

func launchKEMTLSServer() {
	fmt.Println("Starting servers...")

	flag.Parse()

	port := 4433

	keys := sortAlgorithmsMap()

	rootCertHybrid := new(tls.Certificate)
	var err error

	*rootCertHybrid, err = tls.X509KeyPair([]byte(rootCert), []byte(rootKey))
	if err != nil {
		panic(err)
	}

	rootCertHybrid.Leaf, err = x509.ParseCertificate(rootCertHybrid.Certificate[0])
	if err != nil {
		panic(err)
	}

	// Creating intermediate CA to sign the Server Certificate
	intCACert, intCAPriv := initCAs(rootCertHybrid.Leaf, rootCertHybrid.PrivateKey)

	//for each algo
	for _, k := range keys {
		strport := fmt.Sprintf("%d", port)
		kexCurveID, err := nameToCurveID(k)
		if err != nil {
			log.Fatal(err)
		}
		/* auth is the same here
		authCurveID, err := nameToCurveID(*authAlgo)
		if err != nil {
			log.Fatal(err)
		}*/
		authCurveID := kexCurveID

		serverConfig := initServer(authCurveID, intCACert, intCAPriv, rootCertHybrid.Leaf)
		
		// Select here the algorithm to be used in the KEX
		serverConfig.CurvePreferences = []tls.CurveID{kexCurveID}

		serverMsg := "hello, client"

		wg.Add(1)
		//start
		fmt.Println("Starting " + k + " Hybrid KEMTLS server at " + *IPserver + ":" + strport + "...")
		startServerHybrid(serverMsg, serverConfig, *IPserver, strport)

		port++
	}
	wg.Wait() //endless but required
}

func main() {
	launchKEMTLSServer()
}
