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
func decodeCertificates(raw []byte) ([]*x509.Certificate, error) {
	certList, err := decodePemCertificates([]byte(raw))
	if err != nil {
		return nil, err
	}

	list := []*x509.Certificate{}
	for _, v := range certList {
		c, err := x509.ParseCertificate(v)
		if err != nil {
			return nil, err
		}
		list = append(list, c)
	}
	return list, nil
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

// decodePrivateKeysFromPem decodes a private keys from the given PEM formated byte array.
func decodePrivateKeysFromPem(raw, password []byte) ([]crypto.PrivateKey, error) {
	var keys []crypto.PrivateKey
	for {
		block, rest := pem.Decode(raw)
		if block == nil {
			break
		}

		blockRaw := block.Bytes
		if x509.IsEncryptedPEMBlock(block) {
			if len(password) == 0 {
				return keys, fmt.Errorf("cannot decrypt PEM Block. Please provide a password for the private key")
			}
			decrypted, err := x509.DecryptPEMBlock(block, password)
			if err != nil {
				return keys, fmt.Errorf("cannot decrypt PEM Block: %s", err)
			}
			blockRaw = decrypted
		}

		switch block.Type {
		case "RSA PRIVATE KEY":
			key, err := x509.ParsePKCS1PrivateKey(blockRaw)
			if err != nil {
				return keys, err
			}
			keys = append(keys, key)
		case "PRIVATE KEY":
			key, err := x509.ParsePKCS8PrivateKey(blockRaw)
			if err != nil {
				return keys, nil
			}
			switch key := key.(type) {
			case *rsa.PrivateKey, *ecdsa.PrivateKey:
				keys = append(keys, key)
			default:
				return nil, fmt.Errorf("found unknown private key type in PKCS#8 wrapping")
			}
		case "EC PRIVATE KEY":
			key, err := x509.ParseECPrivateKey(blockRaw)
			if err != nil {
				return keys, nil
			}
			keys = append(keys, key)
		}
		raw = rest
	}

	return keys, nil
}

func hashForState(value string) string {
	if value == "" {
		return ""
	}
	hash := sha1.Sum([]byte(strings.TrimSpace(value)))
	return hex.EncodeToString(hash[:])
}
