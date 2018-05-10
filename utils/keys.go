package utils

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
)

/*	MoatCailin uses P-256 ECDSA private and public keys for authentication
	between entry and exit servers, where it is not necessary to implement o
	bfuscation, due to being outside censored networks.
*/

// P256PrivateKey represents a private P-256 ECDSA key in both byte forms
// and usable forms. Bytes in ANS.1 DER.
type P256PrivateKey struct {
	privateKey      *ecdsa.PrivateKey
	privateKeyBytes []byte
}

// P256PublicKey represents a public P-256 ECDSA key in both byte forms
// and usable forms. Bytes in PKIX.
type P256PublicKey struct {
	publicKey      *ecdsa.PublicKey
	publicKeyBytes []byte
}

// GenECDSAP256KeyPair generates from a cryptographically secure source
// a P256 keypair. Returns nil if facilities unavailable at runtime.
func GenECDSAP256KeyPair() (*P256PrivateKey, *P256PublicKey) {

	privkey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Println("Error occurred when generating ECDSA private key.")
		return nil, nil
	}
	privbytes, err := x509.MarshalECPrivateKey(privkey)
	if err != nil {
		log.Println("Error occurred when marshalling ECDSA private key.")
		return nil, nil
	}
	privateKey := &P256PrivateKey{
		privateKey:      privkey,
		privateKeyBytes: privbytes,
	}

	pubkey := privkey.PublicKey
	pubbytes, err := x509.MarshalPKIXPublicKey(&pubkey)
	if err != nil {
		log.Println("Error occurred when marshalling ECDSA public key.")
		return privateKey, nil
	}
	publicKey := &P256PublicKey{
		publicKey:      &pubkey,
		publicKeyBytes: pubbytes,
	}

	return privateKey, publicKey

}

// Save the private key to a target path.
func (p *P256PrivateKey) Save(outPath string) error {
	fullOutPath, err1 := filepath.Abs(outPath)
	f, err2 := os.Create(fullOutPath)
	defer f.Close()
	if err1 != nil || err2 != nil {
		return errors.New("the output path for the ECDSA private key is invalid")
	}

	keyBlock := &pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: p.privateKeyBytes,
	}
	encodedBlock := pem.EncodeToMemory(keyBlock)
	_, err := f.Write(encodedBlock)
	if err != nil {
		return errors.New("failure in saving the ECDSA public key")
	}

	return nil
}

// Save the public key to a target path. Returns error if failed.
func (p *P256PublicKey) Save(outPath string) error {
	fullOutPath, err1 := filepath.Abs(outPath)
	f, err2 := os.Create(fullOutPath)
	defer f.Close()
	if err1 != nil || err2 != nil {
		return errors.New("the output path for the ECDSA public key is invalid")
	}

	keyBlock := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: p.publicKeyBytes,
	}
	encodedBlock := pem.EncodeToMemory(keyBlock)
	_, err := f.Write(encodedBlock)
	if err != nil {
		return errors.New("failure in saving the ECDSA public key")
	}

	return nil
}

// ReadPrivateKey parses an ECDSA private key from the target location.
// Returns error if failed.
func ReadPrivateKey(inPath string) (*P256PrivateKey, error) {
	fullInPath, err1 := filepath.Abs(inPath)
	privPEM, err2 := ioutil.ReadFile(fullInPath)
	if err1 != nil || err2 != nil {
		return nil, errors.New("cannot open the private key file")
	}

	decodedPEM, _ := pem.Decode(privPEM)
	parsedPrivate, parseerr := x509.ParseECPrivateKey(decodedPEM.Bytes)
	if parseerr != nil {
		return nil, errors.New("cannot decode the private key file")
	}

	parsedKey := &P256PrivateKey{
		privateKey:      parsedPrivate,
		privateKeyBytes: decodedPEM.Bytes,
	}

	return parsedKey, nil
}

// ReadPublicKey parses an ECDSA public key from the target location.
// Returns error if failed.
func ReadPublicKey(inPath string) (*P256PublicKey, error) {
	fullInPath, err1 := filepath.Abs(inPath)
	pubPEM, err2 := ioutil.ReadFile(fullInPath)
	if err1 != nil || err2 != nil {
		return nil, errors.New("cannot open the public key file")
	}

	decodedPEM, _ := pem.Decode(pubPEM)
	parsedPublic, parseerr := x509.ParsePKIXPublicKey(decodedPEM.Bytes)
	if parseerr != nil {
		return nil, errors.New("cannot decode the public key file")
	}

	switch parsedPublic := parsedPublic.(type) {
	case *ecdsa.PublicKey:
		log.Printf("Parsed public key: %v\n", parsedPublic)
		break
	default:
		return nil, errors.New("parsed PKIX public key is not ECDSA")
	}

	parsedKey := &P256PublicKey{
		publicKey:      parsedPublic.(*ecdsa.PublicKey),
		publicKeyBytes: decodedPEM.Bytes,
	}

	return parsedKey, nil
}
