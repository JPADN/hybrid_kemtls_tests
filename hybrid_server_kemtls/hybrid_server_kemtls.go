package main

import (
	"circl/sign"
	circlSchemes "circl/sign/schemes"
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
	"strings"
	"time"
)

var (
	intCAAlgo = flag.String("intca", "P256_Dilithium2", "Intermediate CA Signature Algorithm")

	IPserver   = flag.String("ipserver", "34.116.206.139", "IP of the KEMTLS/PQTLS Server")
	IPclient   = flag.String("ipclient", "35.247.220.72", "IP of the KEMTLS/PQTLS Client Auth Certificate")
	handshakes = flag.Int("handshakes", 1, "Number of Handshakes desired")

	clientAuth = flag.Bool("clientauth", false, "Client authentication")

	pqtls      = flag.Bool("pqtls", false, "PQTLS")
	hybridRoot = flag.Bool("hybridroot", true, "Root CA with hybrid algorithm")

	cachedCert = flag.Bool("cachedCert", false, "KEMTLS PDK or PQTLS(cached) server cert.")
)

var (

	// CIRCL
	// hsAlgorithms = map[string]tls.CurveID{"Kyber512X25519": tls.Kyber512X25519, "Kyber768X448": tls.Kyber768X448, "Kyber1024X448": tls.Kyber1024X448,
	// 	"SIKEp434X25519": tls.SIKEp434X25519, "SIKEp503X448": tls.SIKEp503X448, "SIKEp751X448": tls.SIKEp751X448}

	// Liboqs
	hsKEXAlgorithms = map[string]tls.CurveID{
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
	}

	hsHybridAuthAlgorithms = map[string]liboqs_sig.ID{
		"P256_Dilithium2": liboqs_sig.P256_Dilithium2, "P256_Falcon512": liboqs_sig.P256_Falcon512, "P256_RainbowIClassic": liboqs_sig.P256_RainbowIClassic,
		"P384_Dilithium3": liboqs_sig.P384_Dilithium3, "P384_RainbowIIIClassic": liboqs_sig.P384_RainbowIIIClassic,
		"P521_Dilithium5": liboqs_sig.P521_Dilithium5, "P521_Falcon1024": liboqs_sig.P521_Falcon1024, "P521_RainbowVClassic": liboqs_sig.P521_RainbowVClassic,
	}
)

var rootCert = `-----BEGIN CERTIFICATE-----
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
Z9w8PiSMZVRhH+OnQNhhtG3Rsh0A
-----END CERTIFICATE-----
`

var rootKey = `-----BEGIN PRIVATE KEY-----
MIIPYgIBADAMBgorBgEEAYLaSy0KBIIPTQSCD0ngOwT/raaToLEmJcK7dK3pLsuR
NFKGa2e7JLVMg21q9iYquDgF92FsKI3zxbqKFX3ipRJc3rF9QbdV0pgpzjPkARXv
M3wqgsF7D+8cReIitDMu4ty/hyWJevXJEDTJmVTjLQH9HvLhc0+QIOnSJ0CiKdtp
qt11yqBVjgVABIoIMMsKcxanop3A1WBGTRJBZJuF1AYgyhInTqjajjh0rhsQTM0o
HkuPDcltg8RZicQgKmwK1cRlkDe2pV0CQWom4ujBoz2L5JZFg9FudGKME8VAo9AE
sTCEgzdX0gYqCF24prxm2xawBiSQlaNi5iTRHesRDOM2Dhi7HrmotRmtY7XRqywP
jsmA1mSkNKNtDgDX61TI5dZy6gyoGRMoylg6YmwzI+ZyMCSXLhOr6UzVTLnQZIrV
MYWUFAtRdAN1G0IOoMmRKjElmBBqcgtmbNWMWRqhtaCqE+dNRIdgjYWFKgq7CQUt
mMChcx0EUOaQExUgQxGv5JpBREsbE7MmrJgwBdRAW+WhmrzJSTARoFd5pSop6xiR
A7Ohmjeao8mShsoK1WivnbjaDeGRk2qQduhNxDaJ5QJv61DPM2GWVholBBksgjFu
GNIUICNEcDgoM0eybJKgyMQwXeKhCeYNCbSFTCCSxTAmxmJtLlEXEDmLnekudKIK
UCLHjbQZLol6E1xSm+FRcyRY64yaQs3MycAQKhbMigNNA7PSmbkpSbBNSM20c6zF
aTzSotWOWw0Ms1fTAmJysoe1NESD0lyjo5vGnBEMUdmp2taGqWQNZGUxI5waUOZR
kNqhGWuv8IhN9JZkVdqpIsZWgpIadmwQjTmAtooES6NIjZkojLFlVjBpBiFs3Uo7
wzIHqrhN5ixypIrWdB1yzFjUk5hUqeNIGoqQhBtFFcZs3MRg4RTWW2wnAyADiwrU
8AhUwkJTTVaVo+t1UGSTHMG445hqZDyHyDRnciqYSF2aKRiTFZCuykKvpax17sa4
CLXK8SarK4VKVVGhTlhnjVHEHMctDdUJxRyyBeHKAj2mHEphWMZWkJoFqtxGLoB5
cclMLS3bIzJubGDVccXWLhOFkRoSCxEVsGuHm6s5m0c4TJuRgkylQ0DbUjpCM2sk
G7esFFEDAdlJbqpSLknTm+muZdLMQlB6yDSTopusZCWVRhkYnBabamd5JSC5hTva
6Vasnak2RYDUzcCNarfUjDMlDCFZiGJ2QAJLSbZQrBSyLUowohoxhlQxk2ioiTJ4
rgEFFhvACRmkXoagdtyygehJ4jayHD0PW5gxFSzMyMBsYTkPIrBlooaIJJCVBgZB
hQKVNtdNXDgptCUIpTTawww2lMYQKK02VjIACMuwYjZqmccMbLiWJex1TMLSWwWt
E20thVkPAiKpnBROTqgihsOYVApbcEZ6hmXGhJEA9pww6FgacVpCANkCmR3WUEWS
dOcCCDFO0eY4YzxVnrGKmwwunpXNGeMV4TpqlbpFc7m4XFkXcCy6Q0mNKkIOYKCh
XhDL0JyBygQTG9JYsBJpqtoWiYpSZSNI45JEKA1xYbC5LLvKY8pSiQqyoa16wiJc
eBULqOG7B8xXfFW48eH1HA17AgCvdoEP8kBdnpFpl/Lsas5KPdI9gjwzu/c9eioV
UFm2xa28PExhkXdRGcPPHimpL2B1re2Ka7xr+r2wTgjnuQW/Me3zkmWYZhR+IDvW
LxrM6a3vYvKZwxTuY5Wg3a5IhtUGfAeNsi+5AOJ5MxzaJIfTzkxVkQvEIKjrH5pu
0o6AWHCCgFjji5i4mxv2Gx7ZnVAU4TCndEyDlVrY/KIjvWRjJ2MpHRUsEg7wg30R
QnPkZ2O3kiedaAYntIW8i0EJLIfwGlKn00bQHz/9jD9yFXGrOK9yUpbX13sSl0t7
Fa9shYsyTlEVVqQnei8GQ8PQ3Iua4amqZbCGtbm7fA8hpLtZ3G/XCKhbNE0BN/xt
+Tc2EgPNDRHyFYO8H7HDdbw/P/kruGT5RzM+cMC4xkwXi54SWFacJBYzejvzOFKQ
CI7/EJLqBnlO6UGBaXXNfTX8O/VvKHWm31nb5HrgjwtX6BT6bHPoNlKRMX6u1mEY
sQIDzAlaBXaCyVICoh+15wOn2t/Ltjfeq25bKT0A43zrxerYpmqOovUB7JYSyxvU
kFx0UOI9DXoWfJqsBkStMFcAUtdBECoz0AG5Q4ToRmlNnVPyHHvhe4/Ti90aVzVJ
lAMhZ/3yau7DZ2lDv/xdU1lLLQiuObkS+kyE3aKCscS1zlXp+L8N9lAQ+yU12+zG
FMiVqSnG4b1V1D0vBTzLbaPIGxVcVb6JrgsA6EU/x7o+Yn99z6cjcnUksbEhqLnC
EgR/ID3dESyMwaESCzHdXk7LrdUgnv7pPF7hUEt0ALWpcf8dqwQ8DhgHUhXdZcPI
+AtIitIKXH9iIseEJG3GLvIo91104OZoSomI17lfZYaZf0j2h3dLc/Yr8QrEjUZB
YluvXWzteVVs1rX3VJo5NiHw7HoXMpRnMo7GTiuSemXx1ObEIPelBcFSZYYzTqtY
g9UvFkD0L3W9AEBCbN0sjzFKBhE1HRHBjJIuaLikyjG9kvynKOIlMYsZljDbxFnO
bmUTOBVuykQla7GCUXyK7PHEYHJFvHwMdpfUxyP7HzzBwkDSh8+i/07+9kCrHO3i
59BAvlr6bn8EKaR25csn4ayBME0sdKTMskqoG8SEnijf8Y4GkHOqTI3UlAQmvfE7
eWwnJhexWj+Kxo03MLzTz3G0yKlJ8uRYN9obMjBZ/dkji5DdY/XEbmaUaD0PHDGc
5TcX5c3uu7NTigaScA4mM3pH158Z0UO3mNoceO7Grnt6K53CDyArW3YWW5AIs1j9
sG995aYpFwjK8iJ5bX2W0XK6aR3FzTe6VBtUfDqWhmiyygEYzCioObIMjh1gJbXY
WHdQIsNsTpLD1p+mVXIkUV40BXjkKuurvT9E5PVYCdSFKfGiz8aKEz/Fc6S3f1h5
zMZB7qad26yEC5c8+6pm50FSRxRaNDsQfrICvzGXVxD0NG7EuH/2ZkDjNBhiw20/
pP34jH723C1vbI9HQCdp+jGK4b21GzFfxGjGgj1TLcYnD4lzuGruqKBbs33KZYV4
Y/8OqLJ1lBBAicm/QCX3+J79DLzb50cpXCyskGEv+fGMntng8mQwZG+SQGMzNQA6
0LETsooDQ/A0auqCYA1rUO3q1zxGG9xIlNhv9Y9BasJ3Jmsc1hJc2vuNbLE16RZK
pAqqS7wn+wIIHSxX0OuH+PZdlZqebhVJo/hhqYucOFG4lDnzo7s879UGVM/tWHlc
P65sRS7/VRAPtwxKpywp80pvO4GmTVvcK38YArBDegibS+/7v+rHVZLxmvybKLxF
PWbwAxtDtqQtmIfO5+81PPNR1hXuYQeCNwUvc4D96VKk6k9o90z/pOGKW/7if81z
1N2JBNoQyo9Bmnf/OqnTK0wyX0f/gRAUetKolMcLIq+hzy4dX5UXYoH6dbB9EHSA
q2lwUy6OKJQU2wQ/iDwkxc7ZSyHCujfEK5fYin0F+ou9pGHwBzhnuhDkq7Jl6Ii8
tNm7+LiZvorM+yD41CWEuwMReI9nX4ATU8wRsyQv7ceoLVsgvfm14zT6Hv6J9AtW
kCO2jQJNv6CePd2wSeXMpEVppQSgDtIxuJn8tD8e6jcjAUEoRvX+47TYQJW6+fLm
J2P6EA/wDmO2g8jt/U1WULBZ/dFVdXZNpNqE2yTLWVEjiq5VdaQHtzGJesaE7VZQ
7AxY/8a6zDHvw0SAO/FVVfmTU/TZAxD6KnkaNKIA+NDSnURVM4uhg1W7zWVkn/WC
9pm21XMqk72QQxaUrq1b4mHD8sDF8iSTIgsv+2XvAFvvC8iQdgfRr3sOAiqNUQKP
DznL+aN1xfEVo4ceQZ8E4e3vgq9CZcEpzBDXwA9dbMthwfLRUqNOki7SxHu7TAkw
666GL36Gh2KzcIJmT7y7of2b/lmdSjWtFWUwltt9o4IQ61dAC369UkfkoVp3rTh4
G/DqrZUJtLAwQqi37vL7L+f1g2BQsC8cdYCvU1rqTiFqjTDFnZToUvoSyCangE/k
uo/IkSnmrX4skmOReCSTERmlPScjEvN4hP5UZ5FX8M3TItY+yCEEDILxTvHVvRwP
SPgPkoRLBuRQ9gz3zR3kGDFMyqOUqA6/vr8Z5YkNFGMooA4953BjNf+xqg8HhhjY
I1fYPRmgae2ggdGOtI6/HGGeFNXX9uwNYM3i2w9AHQ7efG6QtFvccj1636uksSXz
kMoBF4l1gau+AenUobA5mY3k9CF+QQXDTZ81Tb7/Rqu6SQnzw/wifobqxu+ukQyx
BGVOFvrs5Xbu7oELZ4OS1sbvdY0BXVWS3TaVG/mXJQl1C5HiWO98BexyryctCqTl
mEKAU4es2TdoVMCWYlJ8Cq6NOZorb/P38NJSYcpZQVh8aKTNCLL+lvoz/97Wy+/T
zp2dgPVMBLWBFhxHyvdqjYAnV1KgaIcUFhRCnGln4Ec7DS1AH1gHqvhjgxrwQgJz
8XNLqoquU4cJgZ5CvU7nlBDPn6+TD1jxLf1N+fhmWQQNtvwKCuqU3JjcOnCxrq++
Ub6aJO+oqRLfZ+Yy4Cn5DCpjAwsbEZ+ogWkxwciRrPJ6dbSHWvC/HRNRR/McKccs
vdFyPJ0+DFhuWem7ySwxZUc65thXhOy9WqzAKhX0d0iMQ6aCYKUaUjuUu1cWIJOZ
UAUTmHlf5zR45I5FdQp/gQX7A0gRLU9JKkKqLJ2UyZTs62q6TakXnzqvxdrXklde
YaV6kiw1IsH4ws0WYnMoyJVASHSVUEVukQmQVNdyjBLJx/t0aw/h9DIyDI8h5Xcv
AEgHbCSPs0mVlSD+BDR0am/Kf36hLjejZzVUi3ORixiQhqOtJ/X12ChjUdrbYufC
YNXBDTVgwxlTuQgYoZ9kv6wz35WWvquzaMwB01BVXYizrI/y8JJXoj6B5zeRjc4i
SdcDVIh7s3CMnnnFvNEZ/Xz1ecwg++8vJX2xq503Lue0clEXtxLsbuUBMuWexldO
YJF6BrF+QZ0QRV/bDhWicWjyxBMv+MHwFLcj6STZpeHADVfDK4tz3fTcVhi2kciV
OFvBcTjebqIlDm4kQIrQNeHeKAQ8iI0SXqKIOVuZF+D1CgsMYdUA18mm6Mph0goY
1x4d1bromzPXMhnEincZyB6ryNjR23tyPldGP3a0LewaP2BrPOH1JO5a96RIgREq
dY3NFBWu
-----END PRIVATE KEY-----
`

//sort and returns sorted keys
func sortAlgorithmsMap() (KEXkeys []string, Authkeys []string) {
	// // sort the map of algorithms
	// output := make([]string, 0, len(hsKEXAlgorithms))
	// for k, _ := range hsKEXAlgorithms {
	// 	output = append(output, k)
	// }
	// sort.Strings(output)

	// or return a specific ordering (PQC-only then hybrid interleaved together)

	outputKEX := []string{
		"Kyber512", "P256_Kyber512", "Kyber768", "P384_Kyber768",
		"Kyber1024", "P521_Kyber1024", "LightSaber_KEM", "P256_LightSaber_KEM",
		"Saber_KEM", "P384_Saber_KEM", "FireSaber_KEM", "P521_FireSaber_KEM",
		"NTRU_HPS_2048_509", "P256_NTRU_HPS_2048_509",
		"NTRU_HPS_2048_677", "P384_NTRU_HPS_2048_677",
		"NTRU_HPS_4096_821", "P521_NTRU_HPS_4096_821",
		"NTRU_HPS_4096_1229", "P521_NTRU_HPS_4096_1229",
		"NTRU_HRSS_701", "P384_NTRU_HRSS_701", "NTRU_HRSS_1373", "P521_NTRU_HRSS_1373",
	}

	outputAuth := []string{
		"P256_Dilithium2", "P256_Falcon512", //"P256_RainbowIClassic",
		"P384_Dilithium3",                    //"P384_RainbowIIIClassic",
		"P521_Dilithium5", "P521_Falcon1024", //"P521_RainbowVClassic",
	}

	return outputKEX, outputAuth
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

func nameToHybridSigID(name string) interface{} {
	sigId, prs := hsHybridAuthAlgorithms[name]
	if prs {
		return sigId
	}

	intCAScheme := circlSchemes.ByName(name) // or Ed25519-Dilithium3
	if intCAScheme != nil {
		return intCAScheme
	}

	panic("Algorithm not found")
}

func CurveIDToName(cID tls.CurveID) (name string, e error) {
	for n, id := range hsKEXAlgorithms {
		if id == cID {
			return n, nil
		}
	}
	return "0", errors.New("ERROR: Algorithm not found")
}

func authIDToName(lID liboqs_sig.ID) (name string, e error) {
	for n, id := range hsHybridAuthAlgorithms {
		if id == lID {
			return n, nil
		}
	}
	return "0", errors.New("ERROR: Auth Algorithm not found")
}

func createCertificate(pubkeyAlgo interface{}, signer *x509.Certificate, signerPrivKey interface{}, isCA bool, isSelfSigned bool, peer string, keyUsage x509.KeyUsage, extKeyUsage []x509.ExtKeyUsage, hostName string) ([]byte, interface{}, error) {

	var _validFor time.Duration

	if isCA {
		_validFor = 8760 * time.Hour // 1 year
	} else {
		_validFor = 240 * time.Hour // 10 days
	}

	//fix for testing remotely.
	if hostName == "0.0.0.0" {
		hostName = "34.116.206.139"
	}

	var _host string = hostName //"127.0.0.1" // 34.116.206.139 server //  35.247.220.72 client
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

func initCAs(rootCACert *x509.Certificate, rootCAPriv, intCAAlgo interface{}) (*x509.Certificate, interface{}) {

	intKeyUsage := x509.KeyUsageCertSign

	intCACertBytes, intCAPriv, err := createCertificate(intCAAlgo, rootCACert, rootCAPriv, true, false, "server", intKeyUsage, nil, "127.0.0.1")
	if err != nil {
		panic(err)
	}

	intCACert, err := x509.ParseCertificate(intCACertBytes)
	if err != nil {
		panic(err)
	}

	return intCACert, intCAPriv
}

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

func testConnHybrid(clientMsg, serverMsg string, clientConfig, serverConfig *tls.Config, peer string, ipserver string, port string) (timingState timingInfo, isDC bool, cconnState tls.ConnectionState, err error) {
	clientConfig.CFEventHandler = timingState.eventHandler
	serverConfig.CFEventHandler = timingState.eventHandler

	bufLen := len(clientMsg)
	if len(serverMsg) > len(clientMsg) {
		bufLen = len(serverMsg)
	}
	buf := make([]byte, bufLen)
	if peer == "server" {
		var timingsFullProtocol []float64
		var timingsWriteServerHello []float64
		var timingsWriteCertVerify []float64
		var timingsReadKEMCiphertext []float64

		countConnections := 0

		ln := newLocalListener(ipserver, port)
		defer ln.Close()

		for {

			serverConn, err := ln.Accept()
			if err != nil {
				fmt.Print(err)
				fmt.Print("error 1 %v", err)
			}
			server := tls.Server(serverConn, serverConfig)
			if err := server.Handshake(); err != nil {
				fmt.Printf("Handshake error %v", err)
			}
			countConnections++

			//server read client hello
			n, err := server.Read(buf)
			if err != nil || n != len(clientMsg) {
				fmt.Print(err)
				fmt.Print("error 2 %v", err)
			}

			//server responds
			server.Write([]byte(serverMsg))
			if n != len(serverMsg) || err != nil {
				//error
				fmt.Print(err)
				fmt.Print("error 3 %v", err)
			}

			if *pqtls {

				if server.ConnectionState().DidPQTLS {

					if *clientAuth {
						if !server.ConnectionState().DidClientAuthentication {
							panic("Server unsuccessful PQTLS with mutual authentication")
						}
					}

					timingsFullProtocol = append(timingsFullProtocol, float64(timingState.serverTimingInfo.FullProtocol)/float64(time.Millisecond))
					timingsWriteServerHello = append(timingsWriteServerHello, float64(timingState.serverTimingInfo.WriteServerHello)/float64(time.Millisecond))
					timingsWriteCertVerify = append(timingsWriteCertVerify, float64(timingState.serverTimingInfo.WriteCertificateVerify)/float64(time.Millisecond))

					if countConnections == *handshakes {
						kKEX, e := CurveIDToName(serverConfig.CurvePreferences[0])
						if e != nil {
							fmt.Print("4 %v", err)
						}
						priv, _ := serverConfig.Certificates[0].PrivateKey.(*liboqs_sig.PrivateKey)
						kAuth, err := authIDToName(priv.SigId)
						if e != nil {
							fmt.Print("5 %v", err)
						}
						//kAuth := serverConfig.Certificates[0].Leaf.PublicKeyAlgorithm.String()
						pqtlsSaveCSVServer(timingsFullProtocol, timingsWriteServerHello, timingsWriteCertVerify, kKEX, kAuth, countConnections)
						countConnections = 0
						timingsFullProtocol = nil
						timingsWriteCertVerify = nil
						timingsWriteServerHello = nil
					}
				} else {
					panic("Server unsuccessful PQTLS")
				}
			} else {
				if server.ConnectionState().DidKEMTLS {

					if *clientAuth {
						if !server.ConnectionState().DidClientAuthentication {
							panic("Server unsuccessful PQTLS with mutual authentication")
						}
					}

					timingsFullProtocol = append(timingsFullProtocol, float64(timingState.serverTimingInfo.FullProtocol)/float64(time.Millisecond))
					timingsWriteServerHello = append(timingsWriteServerHello, float64(timingState.serverTimingInfo.WriteServerHello)/float64(time.Millisecond))
					timingsReadKEMCiphertext = append(timingsReadKEMCiphertext, float64(timingState.serverTimingInfo.ReadKEMCiphertext)/float64(time.Millisecond))

					if countConnections == *handshakes {
						kKEX, e := CurveIDToName(serverConfig.CurvePreferences[0])
						if e != nil {
							fmt.Print("4 %v", err)
						}

						kemtlsSaveCSVServer(timingsFullProtocol, timingsWriteServerHello, timingsReadKEMCiphertext, kKEX, countConnections)
						countConnections = 0
						timingsFullProtocol = nil
						timingsReadKEMCiphertext = nil
						timingsWriteServerHello = nil
					}

				} else {
					panic("Server unsuccessful KEMTLS")
				}
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

		if *pqtls {
			if client.ConnectionState().DidPQTLS {

				if *clientAuth {

					if client.ConnectionState().DidClientAuthentication {
						log.Println("Client Success using PQTLS with mutual authentication")
					} else {
						panic("Client unsuccessful PQTLS with mutual authentication")
					}

				} else {
					log.Println("Client Success using PQTLS")
				}
			} else {
				panic("Client unsuccessful PQTLS")
			}

		} else {
			if client.ConnectionState().DidKEMTLS {
				if *clientAuth {

					if client.ConnectionState().DidClientAuthentication {
						log.Println("Client Success using KEMTLS with mutual authentication")
					} else {
						panic("Client unsuccessful KEMTLS with mutual authentication")
					}

				} else {
					log.Println("Client Success using KEMTLS")
				}

			} else {
				panic("Client unsuccessful KEMTLS")
			}
		}
	}

	return timingState, true, cconnState, nil
}
