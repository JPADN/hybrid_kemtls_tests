package main

import (
	"crypto/kem"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"

	// "fmt"
	"log"
	"math/big"
	"net"
	"strings"
	"time"
)

var rootCertPEMP256 = `-----BEGIN CERTIFICATE-----
MIIDHDCCAgSgAwIBAgIRAJvDMLTPlQ+oSdmnBVBIoAgwDQYJKoZIhvcNAQELBQAw
EjEQMA4GA1UEAxMHUm9vdCBDQTAeFw0yMjAxMTMxNDIxMTBaFw0yMzAxMTMxNDIx
MTBaMBIxEDAOBgNVBAMTB1Jvb3QgQ0EwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAw
ggEKAoIBAQDLaxBTZ7Uxb+NwKNjHwsCYUgciyt0q6avOWRPFOhLDAqon9iRVLWAZ
jhN2d8T8bCxcuvh5K/W2OrzFDofIvRx/qXACk4CkfLUOdwfJJsdu+QAYN67YLwcn
SgXfPHM5eNwjC/eEpduVIhLF56QTq0Ce0Zmml24sG8eCz3LvC5mwjzgGKUmoVy0V
mVqEKnMyVZYmDVQaHC/R/p5EtwVBUy2WxnKLQ6l/hiO1dbuZebnowIYrkaoWBpMe
hTNfldiDpGAXRadevGudys0/6Cs/KSYLsFiDsLIVrO2Z9Cb7f3/AJGUyrB6KghHk
aLEO8KFJDg2kuI1LxdFVAVCFQU5IcWWvAgMBAAGjbTBrMA4GA1UdDwEB/wQEAwIC
pDATBgNVHSUEDDAKBggrBgEFBQcDATAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQW
BBSoM7cjeWSkZC1sY78iJ3GNTFsu0TAUBgNVHREEDTALgglsb2NhbGhvc3QwDQYJ
KoZIhvcNAQELBQADggEBAI/ZCyTO47yew5Ele9bRSVSFu+QPr9mqmzilGbjT+lFT
pt3NLSaq5F7CEpBGnNNKDAt+7sgWMvCGMh+jzOaGMipiw2r1DjTzjvwfAdQ2jMGT
qECkCSk8SrbMX2J7NTKrMyfZtBh0SK8cMaOiFvr/vChvsKru4hFcJ1hMEN6txtaG
tWTHYpMFaad856TJLi9OA0b/usFfTbSm9AjctLBUkKsF06MS0Ynf30M4X5zza8Kx
HUhjUVmQWYB6+/2IuktGic3A4jjQuSod7yg+8yKknEKOnXyp9a/4AAGPopEBElEv
Ql0x73eMoerrQjCxezxhInnhjLRbTaCO8hvDKm9RzMU=
-----END CERTIFICATE-----
`

var rootKeyPEMP256 = `-----BEGIN PRIVATE KEY-----
MIIEwAIBADANBgkqhkiG9w0BAQEFAASCBKowggSmAgEAAoIBAQDLaxBTZ7Uxb+Nw
KNjHwsCYUgciyt0q6avOWRPFOhLDAqon9iRVLWAZjhN2d8T8bCxcuvh5K/W2OrzF
DofIvRx/qXACk4CkfLUOdwfJJsdu+QAYN67YLwcnSgXfPHM5eNwjC/eEpduVIhLF
56QTq0Ce0Zmml24sG8eCz3LvC5mwjzgGKUmoVy0VmVqEKnMyVZYmDVQaHC/R/p5E
twVBUy2WxnKLQ6l/hiO1dbuZebnowIYrkaoWBpMehTNfldiDpGAXRadevGudys0/
6Cs/KSYLsFiDsLIVrO2Z9Cb7f3/AJGUyrB6KghHkaLEO8KFJDg2kuI1LxdFVAVCF
QU5IcWWvAgMBAAECggEBAIoMMpwnuXO/dx5a2iNXK9UzddxKyCWjRxFWqnAipTDq
0gckqCuWC63MGbFAPtL/pmuYB6BUEQCGhC1HWycEEB8jIfzdlWQLreQPK517T8Uj
/shwoZvc7oHfXnTNVXUfbGXsbSH8XTSsVwkv1s3yXnxpyligVAhjIdbIajuIJ9kF
Yw+6J2ErOncTsI+aZktgUIORwQrSXQUVDNbRvI48F6wFSnQL7nydvsXgH7TdJ/ob
z1fQSUhcEcEtAkSKaqZM4pyMJyR89CvBHD5o/LAQAB5AyhC+56rJHXIY2s+Cihbf
zhr46Y/m+ui6ZQ9m2outNH/uPOFnoYgPlp9OVZW6WkECgYEA28kx95l8z8EOf87L
OV7EWzjGKqK0j6nLWwuxdomhfNuojQFnc5PLtjjP3s4lpVnRcAQoW8q9tCsNiuod
l55JgJVoUcRADgSz80d8DYSmOBw3v030LaD5kCDIonCvbUp1Ypk5DG8b9oi+I01G
Lzj2qcX8ttC6p1GN0C5IS7/t1KkCgYEA7O92I9SWj+B9pA3tSz7AG2KX7Okw7B2B
XuvDNPi1jB9m+4S2UneMruY3uzJySFHaeNXjAKeUJWVxDa9Y5mLEejHpGewmcANK
PYEhM81dJYZLN47JSwxUddY9yxWpIUF6ZT1iMPogZekMBo0gVqZv8CWJ6vlHg+ZL
+i/xLT3lBpcCgYEA1P6uRd2hb1UQ0BuAJyEH+b+TjE4R3ggW4yz51n6a2X2mYsAx
mXhpuzZjfPEa2puotH3S/uID5k6y2ST5eK4VXV9tsZAW4377RZDJT/B1hXsTK3pI
YM/YCy06QvIhkDDQgbUr7DjhSJJMcbm5gpoZsX4F4sV1niES5eV0erSNr8ECgYEA
2MXdmLqPZeNGECqNyCIJMQTrat2O3PfBvU6Gspg5wZGZbtTk2l52YC5RHvvwgyog
cB2AKsEnUW+WF6ct9tq2V/YCBq2AHUtlSRAziGmDpylO9+2zTO5i98yjjIKs0rhN
ewLGK3ks2xB06CmGRMDR+SzfGhQn0g2JxcTHK1VNjNECgYEAl32ch3CaV0sQEkhg
0BySyJNjnL2qVmk+MUCWN7Xf9FpW5RWhZDYmBNd2nQ5xWZoCaFp4rakaHF9IZccc
J5901uA1xFjHeKIcS96OaG6uCKlsdAikkD6Z+HetwKl1n4SS4DN0ctXV0oCk3Asw
bY5ea3uTCYiCn3gb9SiibpuLqFc=
-----END PRIVATE KEY-----
`

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

func main() {
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


	hybridCert.Leaf, err = x509.ParseCertificate(hybridCert.Certificate[0])
	if err != nil {
		panic(err)
	}

	/* --------------------------------- Testing -------------------------------- */

	pk, ok := hybridCert.Leaf.PublicKey.(*kem.PublicKey)
	if !ok {
		fmt.Println("ERROR PUB KEY")
	}

	sk, ok := hybridCert.PrivateKey.(*kem.PrivateKey)
	if !ok {
		fmt.Println("ERROR PRIV KEY")
	}

	ss, ct, err := kem.Encapsulate(rand.Reader, pk)
	if err != nil {
		panic(err)
	}

	fmt.Printf("%02x\n\n", ss)

	ss2, err := kem.Decapsulate(sk, ct)
	if err != nil {
		panic(err)
	}

	fmt.Printf("%02x\n\n", ss2)

}