package crypt

import (
	"bytes"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"net"
	"reflect"
	"testing"
)

var testPrivateKey = `
-----BEGIN RSA PRIVATE KEY-----
MIIEpgIBAAKCAQEAyXnMmC3ohIAI/3hf6cSVyu8B5f3zSHy+Fmo+AULB8+w4F/+C
Dhl0jtPEkKw1l+pIm+ZYDXkQYroJNTw3C/Bp6bLWJslEzUgD9XuWes9g6Pgjy8sr
q/Ec2YIHdRG57g5dUZWOzoGAI7NA42msBhUKtReRbHcIkz1NPbZELcRGn/G+PDzc
uDV93Ch4SuvUInjrWjQTBsYlWzjoZLgBOvg3/rDjylgJ60h6nONZmJh9CplpU5PY
HMJacckLz8c3F2HHmN9cxQrSCrblDiNlOI/alZ3LbAWcPApVYqANWcL5l2prfe2c
fV/13H62qf2zAzxbXlqmE+a79wIUjBaItSB2vQIDAQABAoIBAQCayZaj+/E9ithe
3W5ivQOQK1u8BQTZ1ex8cBc/BLjZ28uktEqI5omkCZJky8lI81fhXnCbuT0bfG4C
lkZ8R7I3N4xLtCnFxOQ1v0N3CsgbdDicI3Vj3hQaD0oHaRz9hc+wFETo5pk51Eev
78mXyqa1RmwVdsYByQEEvnlW6AqSadq5gY+aMYpgJxtruhFQekiU+r5h7DzTrGIQ
0QaPpT1VQUbiU0x2zEJoA/7Cm+FMNfdLwZTBp9L8yMXeeT2OcGtI9RMcDQWgBto9
r08WrcxyRzM/x2n3EYeMyoyUqDXHjL8KuuPO21mbx6rJpIueh0PzL/3XOS4dvWs3
IIHS1hbJAoGBAPvFigLvmpb8Xsd8lNSxmvyNdg4gGXupj12mlIV6PTabRc5n9Vtm
FURlW03X0fpA4gQWR3Vr+mOI0M1Ogh/t/kpxPp9GUi4THEOmJ60GSAok/Hs8HCEX
yS3+m7V7L/YUgmR2d8cgpWys6svRLTpGSOgwCHWII/3DVYUMjDA2yxVPAoGBAMzc
BPAdlxsiHybM/W+MoT1rLQZ0GWeGpFtxA0L3fZdIzatlkUA6k9w7TVEpjTr8R40X
q1beO5dCUGzBrwdxO0CVErOqjFYroBHHcLU080487wP8up/ZPeBZhbGdAHAqmQCn
7LGrw9aGLdw3rsFt9IFK/1bLe8c07VyPUEwXQ0gzAoGBAJ3cqkBVA9UPwE3Ma3VB
NzCLci5BKjlDg8Twocdfceo/SXG19T2tsEAGXU1duSb0b8KoRX32ijTGoEVaqHRk
wUDj6KPtb7G8AcjY8Z+nhJv3vOd4NRr60wWn0vHjn5roGSnsrgWJDrApa78IFReo
4iXTmDo5dneydnjJ+Uxxzrw5AoGBALTbITjixr5bl2jn3G6YltjkP7HM2Yi+I2ff
E+QRHr1qtrg0SNGNZXAuoomex2Jlyr1TQh7Ev5NAJkR9kYpeetL/SK15Sb/hb8WC
b4xqnMpbnR/GBPSOE8R3BELTuslLshwUJDCO1awUdXRPbGa0LgHfNiFoL3Sk01C9
7UPf3bRlAoGBAOtciEHnyDOTcBjUEdcuVvi2l9OqpWMmq8ZSn3qR0hLfx7L4r8T/
kyFJypbGSnPHiLhjqIBGYV1OHy392COzPH+k732MeEP8QFZAD7xsut2sqP1NuDA7
YwJi1faTqreASA5MqQlNMh6VCF5ykB23T1KWafzydLjuvjYd8jbafED0
-----END RSA PRIVATE KEY-----`

var testPublicKey = `
-----BEGIN RSA PUBLIC KEY-----
MIIBCgKCAQEAyXnMmC3ohIAI/3hf6cSVyu8B5f3zSHy+Fmo+AULB8+w4F/+CDhl0
jtPEkKw1l+pIm+ZYDXkQYroJNTw3C/Bp6bLWJslEzUgD9XuWes9g6Pgjy8srq/Ec
2YIHdRG57g5dUZWOzoGAI7NA42msBhUKtReRbHcIkz1NPbZELcRGn/G+PDzcuDV9
3Ch4SuvUInjrWjQTBsYlWzjoZLgBOvg3/rDjylgJ60h6nONZmJh9CplpU5PYHMJa
cckLz8c3F2HHmN9cxQrSCrblDiNlOI/alZ3LbAWcPApVYqANWcL5l2prfe2cfV/1
3H62qf2zAzxbXlqmE+a79wIUjBaItSB2vQIDAQAB
-----END RSA PUBLIC KEY-----`

func getTestPrivateKey() *RSAPrivateKey {
	decodedPEM, _ := pem.Decode([]byte(testPrivateKey))
	parsedPrivate, _ := x509.ParsePKCS1PrivateKey(decodedPEM.Bytes)
	return &RSAPrivateKey{
		privateKey:      parsedPrivate,
		privateKeyBytes: decodedPEM.Bytes,
	}
}

func getTestPublicKey() *RSAPublicKey {
	decodedPEM, _ := pem.Decode([]byte(testPublicKey))
	parsedPublic, _ := x509.ParsePKCS1PublicKey(decodedPEM.Bytes)
	return &RSAPublicKey{
		publicKey:      parsedPublic,
		publicKeyBytes: decodedPEM.Bytes,
	}
}

type DummyKeyStore struct{}

func (d DummyKeyStore) Store(pub *RSAPublicKey) {
	return
}

func (d DummyKeyStore) Retrieve(in string) *RSAPublicKey {
	public := getTestPublicKey()
	return public
}

var testPublic = getTestPublicKey()
var testPrivKey = getTestPrivateKey()
var testKeyStore = DummyKeyStore{}
var testProtocol = 1
var testRemote, _ = net.ResolveIPAddr("ip4", "8.8.8.8")
var randomTestSize = 2048

var testGenerator = S2SDataGenerator{
	keyStore: testKeyStore,
	privKey:  testPrivKey,
	pubKey:   testPublic,
}

func TestEncryptAndSign(t *testing.T) {

	// Craft some random bytes and encrypt it.
	randomBytes := make([]byte, randomTestSize)
	rand.Read(randomBytes)
	testS2SData := testGenerator.EncryptAndSign(randomBytes, testPublic.Identifier(), *testRemote, testProtocol)

	// Check the identifiers.
	if testS2SData.SourceIdentifier != testGenerator.pubKey.Identifier() {
		t.Errorf("Source identifier in the test S2S Payload mismatched.")
	}
	if testS2SData.DestinationIdentifier != testPublic.Identifier() {
		t.Errorf("Target identifier in the test S2S Payload mismatched.")
	}

	// Decrypt symmetric key to decrypt payload.
	key, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, testGenerator.privKey.privateKey, testS2SData.EncryptedKey, nil)
	if err != nil {
		t.Errorf("Error decrypting the test symmetric key.")
		t.Errorf("Decryption error: %v", err)
	}

	// Decrypt the payload now.
	block, _ := aes.NewCipher(key)
	gcm, _ := cipher.NewGCM(block)
	decryptedBytes, _ := gcm.Open(nil, testS2SData.PayloadNonce, testS2SData.ProxyPayload, nil)
	restoredPayload := S2SPayload{}
	err = restoredPayload.Unmarshal(decryptedBytes)
	if err != nil {
		t.Errorf("Corrupted inner payload detected.")
	}
	if bytes.Compare(restoredPayload.Layer4Payload, randomBytes) != 0 {
		t.Errorf("Improper decryption of the test payload.")
	}
	if !reflect.DeepEqual(*testRemote, restoredPayload.RemoteAddr) {
		t.Errorf("Remote address not successfully preserved.")
	}
	if restoredPayload.ProtocolID != testProtocol {
		t.Errorf("Wrapped packet protocol not successfully preserved.")
	}

	// Check the signature.
	payloadHash := sha256.Sum256(testS2SData.ProxyPayload)
	sigok := rsa.VerifyPSS(testPublic.publicKey, crypto.SHA256, payloadHash[:], testS2SData.PayloadSignature, nil)
	if sigok != nil {
		t.Errorf("Bad signature for the test S2S Payload.")
	}

}

func TestDecryptAndVerify(t *testing.T) {

	// Generate and encrypt a random key for AES-256.
	testKey := make([]byte, symmetricKeySize)
	rand.Read(testKey)
	encryptedTestKey, _ := rsa.EncryptOAEP(sha256.New(), rand.Reader, testPublic.publicKey, testKey, nil)

	// Generatea random payload.
	randomBytes := make([]byte, randomTestSize)
	rand.Read(randomBytes)

	// Wrap it and encrypt it.
	innerPayload, _ := S2SPayload{
		RemoteAddr:    *testRemote,
		ProtocolID:    testProtocol,
		Layer4Payload: randomBytes,
	}.Marshal()
	block, _ := aes.NewCipher(testKey)
	gcm, _ := cipher.NewGCM(block)
	nonce := make([]byte, gcm.NonceSize())
	rand.Read(nonce)
	testEncryptedPayload := gcm.Seal(innerPayload[:0], nonce, innerPayload, nil)

	// Sign it as well.
	payloadHash := sha256.Sum256(testEncryptedPayload)
	testSignature, _ := rsa.SignPSS(rand.Reader, testGenerator.privKey.privateKey, crypto.SHA256, payloadHash[:], nil)

	testS2SData := &S2SData{
		SourceIdentifier:      testGenerator.pubKey.Identifier(),
		DestinationIdentifier: testPublic.Identifier(),
		ProxyPayload:          testEncryptedPayload,
		PayloadSignature:      testSignature,
		EncryptedKey:          encryptedTestKey,
		PayloadNonce:          nonce,
	}

	// Verify decryption and verification.
	decryptedBytes, remote, proto, verification := testGenerator.DecryptAndVerify(testS2SData)
	if bytes.Compare(decryptedBytes, randomBytes) != 0 {
		t.Errorf("Improper decryption of the test S2S Payload.")
	}
	if verification != nil {
		t.Errorf("Unable to verify the encrypted test S2S Payload.")
		t.Errorf("Verification error: %v", verification)
	}
	if testRemote.String() != remote.String() {
		t.Errorf("Remote address not successfully preserved: %v instead of %v",
			remote.String(), testRemote.String())
	}
	if proto != testProtocol {
		t.Errorf("Wrapped packet protocol not successfully preserved.")
	}

}

func TestDecryptGCM(t *testing.T) {
	// Controlled decryption of random bytes.
	randomBytes := make([]byte, randomTestSize)
	rand.Read(randomBytes)
	testEncryptedPayload := testGenerator.EncryptAndSign(randomBytes, testPublic.Identifier(), *testRemote, testProtocol)
	testKey, _ := rsa.DecryptOAEP(sha256.New(), rand.Reader, testGenerator.privKey.privateKey, testEncryptedPayload.EncryptedKey, nil)
	testDecryptedPayload, err := decryptGCM(testEncryptedPayload.ProxyPayload, testKey, testEncryptedPayload.PayloadNonce)

	if err != nil {
		t.Errorf("Unable to decrypt random GCM-encrypted bytes.")
		t.Errorf("Error: %v", err)
	}
	unwrapped := S2SPayload{}
	unwrapped.Unmarshal(testDecryptedPayload)
	if bytes.Compare(unwrapped.Layer4Payload, randomBytes) != 0 {
		t.Errorf("Unable to correctly decrypt random GCM-encrypted bytes.")
		t.Errorf("Error: %v", err)
	}
}

func TestRekey(t *testing.T) {

	var rekeyTestGenerator = S2SDataGenerator{
		keyStore: testKeyStore,
		privKey:  testPrivKey,
		pubKey:   testPublic,
	}

	testCipherError := rekeyTestGenerator.getCipher()
	if testCipherError != nil {
		t.Errorf("Unable to correctly initialise test cipher.")
		t.Errorf("Error: %v", testCipherError)
	}
	originalKey := rekeyTestGenerator.currentKey

	for i := 0; i < maxNouncePerKey+1; i++ {
		err := rekeyTestGenerator.getCipher() // Force nounce reset.
		if err != nil {
			t.Errorf("Rekey error: %v", err)
			return
		}
	}

	if bytes.Compare(originalKey, rekeyTestGenerator.currentKey) == 0 {
		t.Errorf("Test cipher was not correctly rekeyed after reaching max nounce count.")
	}

	if len(rekeyTestGenerator.currentKey) != symmetricKeySize {
		t.Errorf("Test cipher was not correctly rekeyed with valid length.")
	}
}

func TestMarshalling(t *testing.T) {
	// Encrypt and marshal.
	randomBytes := make([]byte, randomTestSize)
	rand.Read(randomBytes)
	testS2SData := testGenerator.EncryptAndSign(randomBytes, testPublic.Identifier(), *testRemote, testProtocol)
	marhsalledPayload, err := testS2SData.Marshal()
	if err != nil {
		t.Errorf("Marshalling of test payload failed: %v", err)
	}

	// Unmarshal and decrypt.
	unmarshalledPayload := S2SData{}
	err = unmarshalledPayload.Unmarshal(marhsalledPayload)
	if err != nil {
		t.Errorf("Unmarshalling of marshalled test payload failed: %v", err)
	}

	if !reflect.DeepEqual(unmarshalledPayload, *testS2SData) {
		t.Errorf("Improper reconstruction of payload after marshalling.")
	}

}
