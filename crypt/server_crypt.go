package crypt

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"errors"
	"fmt"
	"log"
)

/*
	Unobfuscated asymmetric cryptography for between entry and
	exit servers.
*/

// S2SPayload carries the encrypted payload along with a signature
// from the source server, intended for protocol-transparent
// transmission.
type S2SPayload struct {
	SourceIdentifier      string
	DestinationIdentifier string
	ProxyPayload          []byte
	PayloadSignature      []byte
}

// S2SPayloadGenerator creates S2SPayloads by encrypting payloads
// with the correct target public key and signing.
type S2SPayloadGenerator struct {
	keyStore PubKeyStore
	privKey  *RSAPrivateKey
	pubKey   *RSAPublicKey
}

// EncryptAndSign a payload for a defined destination server identifier,
// returns nil if invalid destination or signing error.
// Encryption in OAEP mode, and signed with PSS.
func (g S2SPayloadGenerator) EncryptAndSign(payload []byte, dest string) *S2SPayload {

	// Find the destination server public key.
	destinationPubKey := g.keyStore.Retrieve(dest)
	if destinationPubKey == nil {
		log.Printf("Cannot find public key for %v to encrypt the payload.\n", dest)
		return nil
	}

	// Encrypt the payload for the destination server public key.
	encryptedPayload, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, destinationPubKey.publicKey, payload, nil)
	if err != nil {
		log.Printf("Cannot properly encrypt the payload for %v, possibly oversized.\n", dest)
		log.Printf("Error: %v\n", err)
		return nil
	}

	// Sign the payload with our private key.
	payloadHash := sha256.Sum256(encryptedPayload)
	payloadSignature, err := rsa.SignPSS(rand.Reader, g.privKey.privateKey, crypto.SHA256, payloadHash[:], nil)
	if err != nil {
		log.Printf("Cannot properly sign the payload for %v with our private key.\n", dest)
		return nil
	}

	return &S2SPayload{
		SourceIdentifier:      g.pubKey.Identifier(),
		DestinationIdentifier: destinationPubKey.Identifier(),
		ProxyPayload:          encryptedPayload,
		PayloadSignature:      payloadSignature,
	}
}

// DecryptAndVerify a payload and its signature from source. Returns nil and error
// if source public key mismatches the signature.
func (g S2SPayloadGenerator) DecryptAndVerify(packedPayload *S2SPayload) ([]byte, error) {

	// Find the source server public key.
	source := packedPayload.SourceIdentifier
	sourcePubKey := g.keyStore.Retrieve(source)
	if sourcePubKey == nil {
		errorMsg := fmt.Sprintf("cannot find public key for source %s to verify the payload signature", source)
		return nil, errors.New(errorMsg)
	}

	// Verify the signature of the encrypted payload.
	payloadHash := sha256.Sum256(packedPayload.ProxyPayload)
	sigerr := rsa.VerifyPSS(sourcePubKey.publicKey, crypto.SHA256, payloadHash[:], packedPayload.PayloadSignature, nil)
	if sigerr != nil {
		errorMsg := fmt.Sprintf("signature mismatch for source %s", source)
		return nil, errors.New(errorMsg)
	}

	// Decrypt the payload.
	payload, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, g.privKey.privateKey, packedPayload.ProxyPayload, nil)
	if err != nil {
		errorMsg := fmt.Sprintf("cannot decrypt payload from source %s", source)
		return nil, errors.New(errorMsg)
	}

	return payload, nil

}
