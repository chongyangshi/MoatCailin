package crypt

import (
	"bytes"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/gob"
	"errors"
	"fmt"
	"log"
	"net"
)

/*
	Unobfuscated asymmetric cryptography for between entry and
	exit servers.
*/

const symmetricKeySize = 32 // AES-256
const maxNouncePerKey = 102400

// Decrypt GCM with symmetric key and nounce, returns payload and
// nil error if successful.
func decryptGCM(ciphertext []byte, key []byte, nonce []byte) (payload []byte, decryptErr error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	payload, err = gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	return payload, nil
}

var proxiedProtocols = map[int]string{
	0: "error",
	1: "tcp",
	2: "udp",
}

// S2SPayload holds the original Layer 4 information, along with
// the remote IP address and an ID to identify the supported protocol.
type S2SPayload struct {
	RemoteAddr    net.IPAddr
	ProtocolID    int
	Layer4Payload []byte
}

// Marshal encodes a server-to-server payload into serialised bytes.
func (s S2SPayload) Marshal() ([]byte, error) {
	b := bytes.Buffer{}
	e := gob.NewEncoder(&b)
	err := e.Encode(s)
	if err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

// Unmarshal decodes the serialised bytes into a server-to-server payload.
func (s *S2SPayload) Unmarshal(source []byte) error {
	b := bytes.Buffer{}
	b.Write(source)
	d := gob.NewDecoder(&b)
	err := d.Decode(s)
	if err != nil {
		return err
	}
	return nil
}

// S2SData carries the encrypted payload along with a signature
// from the source server, intended for protocol-transparent
// transmission, in addition to additional cipher information.
type S2SData struct {
	SourceIdentifier      string
	DestinationIdentifier string
	EncryptedKey          []byte
	ProxyPayload          []byte
	PayloadNonce          []byte
	PayloadSignature      []byte
}

// Marshal encodes the data unit into transmittable bytes.
func (s S2SData) Marshal() ([]byte, error) {
	b := bytes.Buffer{}
	e := gob.NewEncoder(&b)
	err := e.Encode(s)
	if err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

// Unmarshal decodes the seralised bytes into a server-to-server data unit.
func (s *S2SData) Unmarshal(source []byte) error {
	b := bytes.Buffer{}
	b.Write(source)
	d := gob.NewDecoder(&b)
	err := d.Decode(s)
	if err != nil {
		return err
	}
	return nil
}

// S2SDataGenerator creates S2SDatas by encrypting payloads
// with the correct target public key and signing.
type S2SDataGenerator struct {
	keyStore       PubKeyStore
	privKey        *RSAPrivateKey
	pubKey         *RSAPublicKey
	keyNounceCount int
	currentKey     []byte
	currentCipher  cipher.AEAD
}

// Rekey the cipher if the key has been used for a predefined
// limit of nounces (significantly below 2^32, of course.)
func (g *S2SDataGenerator) getCipher() error {

	g.keyNounceCount++

	if g.currentCipher == nil || g.keyNounceCount > maxNouncePerKey {
		// Generate a new random key.
		g.currentKey = make([]byte, symmetricKeySize)
		_, keyerr := rand.Read(g.currentKey)
		if keyerr != nil {
			log.Printf("Key Generation Error: %v\n", keyerr)
			return keyerr
		}

		// Reinitialise the cipher.
		block, blockerr := aes.NewCipher(g.currentKey)
		if blockerr != nil {
			log.Printf("GCM Block Error: %v\n", blockerr)
			return blockerr
		}
		gcm, gcmerr := cipher.NewGCM(block)
		if gcmerr != nil {
			log.Printf("GCM Cipher Error: %v\n", gcmerr)
			return gcmerr
		}

		g.currentCipher = gcm
		g.keyNounceCount = 0

		return nil
	}

	return nil
}

// EncryptAndSign a payload for a defined destination server identifier,
// with a specific protocol and remote IP address. returns nil if invalid
// destination or signing error. Encryption in OAEP mode, and signed with PSS.
func (g *S2SDataGenerator) EncryptAndSign(payload []byte, dest string, ip net.IPAddr, protoID int) *S2SData {

	// Check protocol.
	if _, ok := proxiedProtocols[protoID]; !ok {
		log.Printf("Invalid protocol specified (%d).\n", protoID)
		return nil
	}

	// Find the destination server public key.
	destinationPubKey := g.keyStore.Retrieve(dest)
	if destinationPubKey == nil {
		log.Printf("Cannot find public key for %v to encrypt the payload.\n", dest)
		return nil
	}

	// Get cipher and generate nounce, rekey if necessary.
	err := g.getCipher()
	if err != nil {
		log.Printf("Cannot properly rekey the AEAD cipher.\n")
		log.Printf("Error: %v\n", err)
		return nil
	}

	nonce := make([]byte, g.currentCipher.NonceSize())
	_, nounceerr := rand.Read(nonce)
	if nounceerr != nil {
		log.Printf("Cannot properly generate the AEAD nounce.\n")
		log.Printf("Error: %v\n", nounceerr)
		return nil
	}

	// Encrypt the key for the destination server public key.
	encryptedKey, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, destinationPubKey.publicKey, g.currentKey, nil)
	if err != nil {
		log.Printf("Cannot properly encrypt the payload for %v, possibly oversized.\n", dest)
		log.Printf("Error: %v\n", err)
		return nil
	}

	// Now we can encrypt the payload.
	innerPayload, err := S2SPayload{
		RemoteAddr:    ip,
		ProtocolID:    protoID,
		Layer4Payload: payload,
	}.Marshal()
	if err != nil {
		log.Printf("Cannot properly wrap the payload for %v due to error %v.\n", dest, err)
		return nil
	}
	encryptedPayload := g.currentCipher.Seal(innerPayload[:0], nonce, innerPayload, nil)

	// Sign the payload with our private key.
	payloadHash := sha256.Sum256(encryptedPayload)
	payloadSignature, err := rsa.SignPSS(rand.Reader, g.privKey.privateKey, crypto.SHA256, payloadHash[:], nil)
	if err != nil {
		log.Printf("Cannot properly sign the payload for %v with our private key.\n", dest)
		return nil
	}

	return &S2SData{
		SourceIdentifier:      g.pubKey.Identifier(),
		DestinationIdentifier: destinationPubKey.Identifier(),
		EncryptedKey:          encryptedKey,
		ProxyPayload:          encryptedPayload,
		PayloadNonce:          nonce,
		PayloadSignature:      payloadSignature,
	}
}

// DecryptAndVerify a payload and its signature from source. Returns nils and error
// if source public key mismatches the signature. Returns decrypted payload, remote IP
// and protocol id otherwise.
func (g *S2SDataGenerator) DecryptAndVerify(packedPayload *S2SData) ([]byte, *net.IPAddr, int, error) {

	// Find the source server public key.
	source := packedPayload.SourceIdentifier
	sourcePubKey := g.keyStore.Retrieve(source)
	if sourcePubKey == nil {
		errorMsg := fmt.Sprintf("cannot find public key for source %s to verify the payload signature", source)
		return nil, nil, 0, errors.New(errorMsg)
	}

	// Verify the signature of the encrypted payload.
	payloadHash := sha256.Sum256(packedPayload.ProxyPayload)
	sigerr := rsa.VerifyPSS(sourcePubKey.publicKey, crypto.SHA256, payloadHash[:], packedPayload.PayloadSignature, nil)
	if sigerr != nil {
		errorMsg := fmt.Sprintf("signature mismatch for source %s", source)
		log.Printf("Signature Matching Error: %v\n", sigerr)
		return nil, nil, 0, errors.New(errorMsg)
	}

	// Decrypt the GCM symmetric key.
	key, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, g.privKey.privateKey, packedPayload.EncryptedKey, nil)
	if err != nil {
		errorMsg := fmt.Sprintf("cannot decrypt symmetric key from source %s", source)
		log.Printf("Decryption Error: %v\n", err)
		return nil, nil, 0, errors.New(errorMsg)
	}

	// Decrypt the payload proper now.
	payload, err := decryptGCM(packedPayload.ProxyPayload, key, packedPayload.PayloadNonce)
	if err != nil {
		errorMsg := fmt.Sprintf("cannot decrypt payload from source %s", source)
		log.Printf("Decryption Error: %v\n", err)
		return nil, nil, 0, errors.New(errorMsg)
	}

	// Unwrap the inner payload.
	innerPayload := S2SPayload{}
	err = innerPayload.Unmarshal(payload)
	if err != nil {
		errorMsg := fmt.Sprintf("Unwrapping of S2S payload from source %s failed: %v", source, err)
		return nil, nil, 0, errors.New(errorMsg)
	}

	return innerPayload.Layer4Payload, &innerPayload.RemoteAddr, innerPayload.ProtocolID, nil
}
