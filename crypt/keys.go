package crypt

import (
	"crypto/md5"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
)

var fixedRSAKeyLength = 2048

/*	MoatCailin uses 2048-bit RSA private and public keys for authentication
	between entry and exit servers, where it is not necessary to implement o
	bfuscation, due to being outside censored networks.
*/

// RSAPrivateKey represents a private 2048-bit RSA key in both byte forms
// and usable forms. Bytes in ANS.1 DER.
type RSAPrivateKey struct {
	privateKey      *rsa.PrivateKey
	privateKeyBytes []byte
}

// RSAPublicKey represents an RSA public key in both byte forms
// and usable forms. Bytes in PKIX.
type RSAPublicKey struct {
	publicKey      *rsa.PublicKey
	publicKeyBytes []byte
}

// GenRSAKeyPair generates from a cryptographically secure source
// an RSA keypair. Returns nil if facilities unavailable at runtime.
func GenRSAKeyPair() (*RSAPrivateKey, *RSAPublicKey) {

	privkey, err := rsa.GenerateKey(rand.Reader, fixedRSAKeyLength)
	if err != nil {
		log.Println("Error occurred when generating RSA private key.")
		return nil, nil
	}
	privbytes := x509.MarshalPKCS1PrivateKey(privkey)
	privateKey := &RSAPrivateKey{
		privateKey:      privkey,
		privateKeyBytes: privbytes,
	}

	pubkey := &privkey.PublicKey
	pubbytes := x509.MarshalPKCS1PublicKey(pubkey)
	publicKey := &RSAPublicKey{
		publicKey:      pubkey,
		publicKeyBytes: pubbytes,
	}

	return privateKey, publicKey

}

// Save the private key to a target path.
func (p *RSAPrivateKey) Save(outPath string) error {
	fullOutPath, err1 := filepath.Abs(outPath)
	f, err2 := os.Create(fullOutPath)
	defer f.Close()
	if err1 != nil || err2 != nil {
		return errors.New("the output path for the RSA private key is invalid")
	}

	keyBlock := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: p.privateKeyBytes,
	}
	encodedBlock := pem.EncodeToMemory(keyBlock)
	_, err := f.Write(encodedBlock)
	if err != nil {
		return errors.New("failure in saving the RSA private key")
	}

	return nil
}

// Save the public key to a target path. Returns error if failed.
func (p *RSAPublicKey) Save(outPath string) error {
	fullOutPath, err1 := filepath.Abs(outPath)
	f, err2 := os.Create(fullOutPath)
	defer f.Close()
	if err1 != nil || err2 != nil {
		return errors.New("the output path for the RSA public key is invalid")
	}

	keyBlock := &pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: p.publicKeyBytes,
	}
	encodedBlock := pem.EncodeToMemory(keyBlock)
	_, err := f.Write(encodedBlock)
	if err != nil {
		return errors.New("failure in saving the RSA public key")
	}

	return nil
}

// Fingerprint returns the RSA public key fingerprint commonly used
// to identify public keys.
func (p *RSAPublicKey) Fingerprint() string {
	h := md5.New()
	h.Write(p.publicKeyBytes)
	return hex.EncodeToString(h.Sum(nil))
}

// ReadPrivateKey parses an RSA private key from the target location.
// Returns error if failed.
func ReadPrivateKey(inPath string) (*RSAPrivateKey, error) {
	fullInPath, err1 := filepath.Abs(inPath)
	privPEM, err2 := ioutil.ReadFile(fullInPath)
	if err1 != nil || err2 != nil {
		return nil, errors.New("cannot open the private key file")
	}

	decodedPEM, _ := pem.Decode(privPEM)
	parsedPrivate, parseerr := x509.ParsePKCS1PrivateKey(decodedPEM.Bytes)
	if parseerr != nil {
		return nil, errors.New("cannot decode the private key file")
	}

	parsedPrivate.Precompute()
	parsedKey := &RSAPrivateKey{
		privateKey:      parsedPrivate,
		privateKeyBytes: decodedPEM.Bytes,
	}

	return parsedKey, nil
}

// ReadPublicKey parses an RSA public key from the target location.
// Returns error if failed.
func ReadPublicKey(inPath string) (*RSAPublicKey, error) {
	fullInPath, err1 := filepath.Abs(inPath)
	pubPEM, err2 := ioutil.ReadFile(fullInPath)
	if err1 != nil || err2 != nil {
		return nil, errors.New("cannot open the public key file")
	}

	decodedPEM, _ := pem.Decode(pubPEM)

	parsedPublic, parseerr := x509.ParsePKCS1PublicKey(decodedPEM.Bytes)
	if parseerr != nil {
		return nil, errors.New("cannot decode the public key file")
	}

	parsedKey := &RSAPublicKey{
		publicKey:      parsedPublic,
		publicKeyBytes: decodedPEM.Bytes,
	}

	return parsedKey, nil
}
