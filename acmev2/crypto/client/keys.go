package client

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
)

//KeyInstanceCert holds the keys for the client (used in certs)
type KeyInstanceCert struct {
	PrivateKey crypto.PrivateKey
	PublicKey  crypto.PublicKey

	PrivateKeyPEM *bytes.Buffer
	PublicKeyPEM  *bytes.Buffer
}

//CreateRSAInstance creates a KeyInstance ...
func (k *KeyInstanceCert) CreateRSAInstance() {
	privateKey, _ := rsa.GenerateKey(rand.Reader, 4096)
	k.PrivateKey = privateKey //implicit durch compiler (*k).PrivateKey
	publicKey := privateKey.PublicKey
	k.PublicKey = publicKey

	privKeyPEM := new(bytes.Buffer)
	pem.Encode(privKeyPEM, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	})
	k.PrivateKeyPEM = privKeyPEM

	publicKeyPEM := new(bytes.Buffer)
	pem.Encode(publicKeyPEM, &pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: x509.MarshalPKCS1PublicKey(&publicKey),
	})
	k.PublicKeyPEM = publicKeyPEM

}
