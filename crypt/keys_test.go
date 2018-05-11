package crypt

import (
	"crypto"
	"crypto/md5"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
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

func TestGenRSAKeyPair(t *testing.T) {

	private, public := GenRSAKeyPair()
	if private == nil || public == nil {
		t.Errorf("Cannot correctly generate private and public RSA 2048-bit keys.")
	}

	// Test key functions.
	randomBytes := make([]byte, 1024)
	rand.Read(randomBytes)
	hashed := sha256.Sum256(randomBytes)
	var sha256hash = hashed[:]
	sig, signerr := rsa.SignPKCS1v15(rand.Reader, private.privateKey, crypto.SHA256, sha256hash)
	if signerr != nil {
		t.Logf("%v", signerr)
		t.Errorf("RSA private key cannot successfully sign hash.")
	}

	err := rsa.VerifyPKCS1v15(public.publicKey, crypto.SHA256, sha256hash, sig)
	if err != nil {
		t.Logf("%v", signerr)
		t.Errorf("RSA private key cannot successfully verify hash.")
	}

	// Test key bytes.
	_, parserrr := x509.ParsePKCS1PrivateKey(private.privateKeyBytes)
	if parserrr != nil {
		t.Errorf("RSA private key bytes cannot be successfully parsed.")
	}
	_, parserrr = x509.ParsePKCS1PublicKey(public.publicKeyBytes)
	if parserrr != nil {
		t.Errorf("RSA public key bytes cannot be successfully parsed.")
	}
}

func TestReadWrite(t *testing.T) {
	testPrivate, testPublic := GenRSAKeyPair()
	pref := randomHex(16)
	savePathPrivate := path.Join(os.TempDir(), strings.Join([]string{string(pref[:]), "_PRIVATE.pem"}, ""))
	savePathPublic := path.Join(os.TempDir(), strings.Join([]string{string(pref[:]), "_PUBLIC.pem"}, ""))

	saveerr := testPrivate.Save(savePathPrivate)
	if saveerr != nil {
		t.Errorf("RSA private key cannot be successfully saved.")
	}
	saveerr = testPublic.Save(savePathPublic)
	if saveerr != nil {
		t.Errorf("RSA public key cannot be successfully saved.")
	}

	private, readerr := ReadPrivateKey(savePathPrivate)
	if readerr != nil {
		t.Errorf("Saved RSA private key cannot be successfully read.")
	}
	public, readerr := ReadPublicKey(savePathPublic)
	if readerr != nil {
		t.Errorf("Saved RSA public key cannot be successfully read.")
	}

	// Test key functions.
	randomBytes := make([]byte, 1024)
	rand.Read(randomBytes)
	hashed := sha256.Sum256(randomBytes)
	var sha256hash = hashed[:]
	sig, signerr := rsa.SignPKCS1v15(rand.Reader, private.privateKey, crypto.SHA256, sha256hash)
	if signerr != nil {
		t.Logf("%v", signerr)
		t.Errorf("RSA private key cannot successfully sign hash.")
	}

	err := rsa.VerifyPKCS1v15(public.publicKey, crypto.SHA256, sha256hash, sig)
	if err != nil {
		t.Logf("%v", signerr)
		t.Errorf("RSA private key cannot successfully verify hash.")
	}

	os.Remove(savePathPrivate)
	os.Remove(savePathPublic)
}

func TestInvalidSave(t *testing.T) {
	testPrivate, testPublic := GenRSAKeyPair()
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

func TestPubKeyFingerprint(t *testing.T) {
	_, testPublic := GenRSAKeyPair()
	MD5Bytes := md5.Sum(testPublic.publicKeyBytes)
	correctMD5 := hex.EncodeToString(MD5Bytes[:])

	if correctMD5 != testPublic.Fingerprint() {
		t.Errorf("Public key fingerprint incorrectly generated.")
	}
}
