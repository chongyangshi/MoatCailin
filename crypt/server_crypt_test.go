package crypt

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
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

var testGenerator = S2SPayloadGenerator{
	keyStore: testKeyStore,
	privKey:  testPrivKey,
	pubKey:   testPublic,
}

func TestEncryptAndSign(t *testing.T) {

	// Craft some random bytes and encrypt it.
	randomBytes := make([]byte, 16)
	rand.Read(randomBytes)
	testS2SPayload := testGenerator.EncryptAndSign(randomBytes, testPublic.Identifier())

	// Check the identifiers.
	if testS2SPayload.SourceIdentifier != testGenerator.pubKey.Identifier() {
		t.Errorf("Source identifier in the test S2S Payload mismatched.")
	}
	if testS2SPayload.DestinationIdentifier != testPublic.Identifier() {
		t.Errorf("Target identifier in the test S2S Payload mismatched.")
	}

	// Decrypt payload to verify bytes.
	decryptedBytes, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, testGenerator.privKey.privateKey, testS2SPayload.ProxyPayload, nil)
	if err != nil {
		t.Errorf("Error decrypting the test S2S Payload.")
	}
	if bytes.Compare(decryptedBytes, randomBytes) != 0 {
		t.Errorf("Improper decryption of the test S2S Payload.")
	}

	// Check the signature.
	payloadHash := sha256.Sum256(testS2SPayload.ProxyPayload)
	sigok := rsa.VerifyPSS(testPublic.publicKey, crypto.SHA256, payloadHash[:], testS2SPayload.PayloadSignature, nil)
	if sigok != nil {
		t.Errorf("Bad signature for the test S2S Payload.")
	}

}

func TestDecryptAndVerify(t *testing.T) {

	// Craft some random bytes and encrypt it.
	randomBytes := make([]byte, 16)
	rand.Read(randomBytes)
	testPayload, _ := rsa.EncryptOAEP(sha256.New(), rand.Reader, testPublic.publicKey, randomBytes, nil)
	payloadHash := sha256.Sum256(testPayload)
	testSignature, _ := rsa.SignPSS(rand.Reader, testGenerator.privKey.privateKey, crypto.SHA256, payloadHash[:], nil)
	testS2SPayload := &S2SPayload{
		SourceIdentifier:      testGenerator.pubKey.Identifier(),
		DestinationIdentifier: testPublic.Identifier(),
		ProxyPayload:          testPayload,
		PayloadSignature:      testSignature,
	}

	// Verify decryption and verification.
	decryptedBytes, verification := testGenerator.DecryptAndVerify(testS2SPayload)
	if bytes.Compare(decryptedBytes, randomBytes) != 0 {
		t.Errorf("Improper decryption of the test S2S Payload.")
	}
	if verification != nil {
		t.Errorf("Unable to verify the encrypted test S2S Payload.")
	}

}
