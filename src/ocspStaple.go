package main

import (
	"time"
	"encoding/asn1"
	"crypto/x509"
	"crypto/x509/pkix"		
	"io"
)

const (
	responseStatus  int    = 0 // Good
	version_default int    = 1
	name            string = "ResponderID"
	certStatus      int    = 0 // Good
	byName          string = "OCSP Responder"
)

// RFC 6960
type ocspResponse struct {
	ResponseStatus int
	ResponseBytes  responseBytes
}

type responseBytes struct {
	ResponseType asn1.ObjectIdentifier
	Response     []byte
}

type basicOCSPResponse struct {
	ResponseData  responseData
	SignatureAlgo pkix.AlgorithmIdentifier
	Signature     asn1.BitString 				// Be computed on the hash of the DER encoding of ResponseData
	Certs         []x509.Certificate  				// Optional
}

type extension struct {
	ExtensionType int
	ExtensionData []byte
}

type responseData struct {
	Version            int
	ResponderID        responderID
	ProducedAt         time.Time
	Responses          []singleResponse
	ResponseExtensions []extension 				// Optional
}

type responderID struct {
	ByName pkix.Name
}

type singleResponse struct {
	CertID     asn1.ObjectIdentifier
	CertStatus int
	ThisUpdate time.Time
	NextUpdate time.Time
}

// Creates a new OCSP response as it is defined in RFC 6960 
//
// The OCSP response is signed by priv which should be the private key from Server Responder. In 
// this case, the server responder will be the intermediate CA
//
// The hash and signature algorithm are the same from Certificate

func createOCSPResponse(rand io.Reader, template *x509.Certificate, priv interface{}) ([]byte, error) {

	s := singleResponse{
		CertID:     asn1.ObjectIdentifier{1, 1, 1, 1, 1, 1, 1, 1},
		CertStatus: 0,
		ThisUpdate: time.Now().AddDate(2022, 05, 16),
		NextUpdate: time.Now().AddDate(2023, 05, 16),
	}

	name := pkix.Name{
		Country:       []string{"Br"},
		Organization:  []string{"Labsec Responder"},
		Locality:      []string{"Santa Catarina"},
		StreetAddress: []string{"Delfino Conti - Trindade"},
		PostalCode:    []string{"88040370"},
	}

	id := responderID{ByName: name}

	// message wich will be signed
	r := responseData{
		Version:     version_default,
		ResponderID: id,
		ProducedAt:  time.Now().AddDate(2022, 05, 16),
		Responses:   []singleResponse{s},
	}

	responseDataContents, err := asn1.Marshal(r)
	if err != nil {
		return nil, err
	}

	signature, signatureAlgorithm, err := x509.SignFromParams(rand, template.SignatureAlgorithm, responseDataContents, priv)
	if err != nil {
		return nil, err
	}

	encodedSignature := asn1.BitString{BitLength: len(signature) * 8, Bytes: signature}

	basic := basicOCSPResponse{
		ResponseData:  r,
		SignatureAlgo: signatureAlgorithm,
		Signature:     encodedSignature,
		Certs:         []x509.Certificate{},
	}

	
	basicContents, err := asn1.Marshal(basic)
	if err != nil {
		return nil, err
	}

	respBytes := responseBytes{
		ResponseType: asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 1, 1},
		Response:     basicContents,
	}

	
	ocspResp := ocspResponse{
		ResponseStatus: responseStatus,
		ResponseBytes:  respBytes,
	}

	ocspRespContents, err := asn1.Marshal(ocspResp)
	if err != nil {
		return nil, err
	}

	return ocspRespContents, err
}
