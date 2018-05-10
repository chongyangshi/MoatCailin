package utils

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"os"
	"path"
	"strings"
	"testing"
)

// Adapted from https://sosedoff.com/2014/12/15/generate-random-hex-string-in-go.html
func randomHex(n int) string {
	bytes := make([]byte, n)
	rand.Read(bytes)
	return hex.EncodeToString(bytes)
}

func TestGenECDSAP256KeyPair(t *testing.T) {

	private, public := GenECDSAP256KeyPair()
	if private == nil || public == nil {
		t.Errorf("Cannot correctly generate private and public ECDSA P-256 keys.")
	}

	// Test key functions.
	randomBytes := make([]byte, 1024)
	rand.Read(randomBytes)
	r, s, signerr := ecdsa.Sign(rand.Reader, private.privateKey, randomBytes)
	if signerr != nil {
		t.Errorf("ECDSA private key cannot successfully sign hash.")
	}

	ver := ecdsa.Verify(public.publicKey, randomBytes, r, s)
	if !ver {
		t.Errorf("ECDSA private key cannot successfully verify hash.")
	}

	// Test key bytes.
	_, parserrr := x509.ParseECPrivateKey(private.privateKeyBytes)
	if parserrr != nil {
		t.Errorf("ECDSA private key bytes cannot be successfully parsed.")
	}
	_, parserrr = x509.ParsePKIXPublicKey(public.publicKeyBytes)
	if parserrr != nil {
		t.Errorf("ECDSA public key bytes cannot be successfully parsed.")
	}
}

func TestPrivateReadWrite(t *testing.T) {
	testPrivate, testPublic := GenECDSAP256KeyPair()
	pref := randomHex(16)
	savePathPrivate := path.Join(os.TempDir(), strings.Join([]string{string(pref[:]), "_PRIVATE.pem"}, ""))
	savePathPublic := path.Join(os.TempDir(), strings.Join([]string{string(pref[:]), "_PUBLIC.pem"}, ""))
	fmt.Println(savePathPrivate, savePathPublic)
	saveerr := testPrivate.Save(savePathPrivate)
	if saveerr != nil {
		t.Errorf("ECDSA private key cannot be successfully saved.")
	}
	saveerr = testPublic.Save(savePathPublic)
	if saveerr != nil {
		t.Errorf("ECDSA public key cannot be successfully saved.")
	}

	_, readerr := ReadPrivateKey(savePathPrivate)
	if readerr != nil {
		t.Errorf("Saved ECDSA private key cannot be successfully read.")
	}
	_, readerr = ReadPublicKey(savePathPublic)
	if readerr != nil {
		t.Errorf("Saved ECDSA public key cannot be successfully read.")
	}

	os.Remove(savePathPrivate)
	os.Remove(savePathPublic)
}

func TestInvalidSave(t *testing.T) {
	testPrivate, testPublic := GenECDSAP256KeyPair()
	invalidPath := path.Join(os.TempDir(), strings.Join([]string{randomHex(128), "INVALID.pem"}, ""))
	expectederr := testPrivate.Save(invalidPath)
	if expectederr == nil {
		t.Errorf("Private key save failure expected but did not occur.")
	}
	expectederr = testPublic.Save(invalidPath)
	if expectederr == nil {
		t.Errorf("Public key save failure expected but did not occur.")
	}
}

func TestInvalidRead(t *testing.T) {
	invalidPath := path.Join(os.TempDir(), strings.Join([]string{randomHex(128), "INVALID.pem"}, ""))
	_, expectederr := ReadPrivateKey(invalidPath)
	if expectederr == nil {
		t.Errorf("Private key read failure expected but did not occur.")
	}
	_, expectederr = ReadPublicKey(invalidPath)
	if expectederr == nil {
		t.Errorf("Public key read failure expected but did not occur.")
	}
}

func TestInvalidContentRead(t *testing.T) {
	validPath := path.Join(os.TempDir(), strings.Join([]string{randomHex(32), "_INVALIDCONTENT.pem"}, ""))

	// Write random garbage into it.
	f, _ := os.Open(validPath)
	f.Write([]byte(randomHex(1024)))
	f.Close()

	_, expectederr := ReadPrivateKey(validPath)
	if expectederr == nil {
		t.Errorf("Private key read content failure expected but did not occur.")
	}
	_, expectederr = ReadPublicKey(validPath)
	if expectederr == nil {
		t.Errorf("Public key read content failure expected but did not occur.")
	}

	os.RemoveAll(validPath)
}
