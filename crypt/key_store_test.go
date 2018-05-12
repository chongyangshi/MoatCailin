package crypt

import (
	"bytes"
	"testing"
)

func TestValidStoreRetrieve(t *testing.T) {
	_, pub1 := GenRSAKeyPair()
	_, pub2 := GenRSAKeyPair()

	keybase := PublicKeybase{}
	keybase.Store(pub1)
	keybase.Store(pub2)

	pub1Retrieved := keybase.Retrieve(pub1.Identifier())
	pub2Retrieved := keybase.Retrieve(pub2.Identifier())

	if bytes.Compare(pub1Retrieved.publicKeyBytes, pub1.publicKeyBytes) != 0 ||
		bytes.Compare(pub2Retrieved.publicKeyBytes, pub2.publicKeyBytes) != 0 {
		t.Errorf("Keybase cannot correctly retrieve stored public keys.")
	}

}

func TestInvalidRetrieve(t *testing.T) {
	keybase := PublicKeybase{}

	invalidRetrieved := keybase.Retrieve("INVALID")

	if invalidRetrieved != nil {
		t.Errorf("Expected invalid keybase retrival succeeded.")
	}

}
