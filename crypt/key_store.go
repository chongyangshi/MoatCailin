package crypt

import "sync"

/*
	Manages public key storage and signing for pre-defined source
	and destination servers.
*/

// PubKeyStore defines the common interface for retrieveing
// and storing public keys.
type PubKeyStore interface {
	New()
	Store(RSAPublicKey)
	Retrieve(string) *RSAPublicKey
}

// PublicKeybase is a concrete public key store.
type PublicKeybase struct {
	keyStore sync.Map
}

// Store records the public key supplied regardless of prior existance.
func (p *PublicKeybase) Store(pub *RSAPublicKey) {
	p.keyStore.Store(pub.Identifier(), *pub)
}

// Retrieve returns the public key specified by its SHA256 identifier,
// or returns nil if does not exist.
func (p *PublicKeybase) Retrieve(keyIdentifier string) *RSAPublicKey {

	key, exists := p.keyStore.Load(keyIdentifier)

	if !exists {
		return nil
	}

	retrievedKey := key.(RSAPublicKey)
	return &retrievedKey
}
