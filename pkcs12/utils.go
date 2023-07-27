package pkcs12

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"strings"
)

// decodeCertificate decodes a certificate from a PEM formated byte array.
// Given data must contain exactly one certificate.
func decodeCertificate(raw []byte) (*x509.Certificate, error) {
	certList, err := decodePemCertificates([]byte(raw))
	if err != nil {
		return nil, err
	}
	if len(certList) != 1 {
		return nil, fmt.Errorf("cert_pem must contains exactly one certificate")
	}
	return x509.ParseCertificate(certList[0])
}

// decodePemCertificates decodes all certificates from a PEM formated byte array.
func decodePemCertificates(raw []byte) ([][]byte, error) {
	var certList [][]byte
	for {
		block, rest := pem.Decode(raw)
		if block == nil {
			break
		}
		if block.Type == "CERTIFICATE" {
			certList = append(certList, block.Bytes)
		}
		// ignore non-certificates
		raw = rest
	}
	return certList, nil
}

// decodePemCA decodes CA certificates from given PEM data
func decodePemCA(raw []byte) ([]*x509.Certificate, error) {
	var caList []*x509.Certificate
	var certList [][]byte
	certList, err := decodePemCertificates(raw)
	if err != nil {
		return caList, err
	}
	for _, c := range certList {
		c1, err := x509.ParseCertificate(c)
		if err != nil {
			return caList, err
		}
		caList = append(caList, c1)
	}
	return caList, nil
}

// decodePrivateKeyFromPem decodes a private key from the given PEM formated byte array.
// It must contain excatly one private key. It must not contain any other certificate.
func decodePrivateKeyFromPem(raw []byte) (crypto.PrivateKey, error) {
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, fmt.Errorf("data does not contain a PrivateKey")
	}
	privateKey, err := parsePrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("faild reading private key: %s", err)
	}
	return privateKey, nil
}

func parsePrivateKey(der []byte) (crypto.PrivateKey, error) {
	if key, err := x509.ParsePKCS1PrivateKey(der); err == nil {
		return key, nil
	}
	if key, err := x509.ParsePKCS8PrivateKey(der); err == nil {
		switch key := key.(type) {
		case *rsa.PrivateKey, *ecdsa.PrivateKey:
			return key, nil
		default:
			return nil, fmt.Errorf("found unknown private key type in PKCS#8 wrapping")
		}
	}
	if key, err := x509.ParseECPrivateKey(der); err == nil {
		return key, nil
	}
	return nil, fmt.Errorf("failed to parse private key")
}

func hashForState(value string) string {
	if value == "" {
		return ""
	}
	hash := sha1.Sum([]byte(strings.TrimSpace(value)))
	return hex.EncodeToString(hash[:])
}
