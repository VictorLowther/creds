// Package creds implements the basics of a secure credential storage and
// sending.  It uses golang.org/x/crypto/nacl/box for encrypting the payload,
// and sha256 to sign the overall Credential.
package creds

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"golang.org/x/crypto/nacl/box"
)

// Credential is an encrypted set of data that can be used to gain
// access to something.  Think username/password pairs, private keys,
// AWS secret tokens, etc.
type Credential struct {
	// Provider is who or what generated the Credential
	Provider string
	// Consumer is what Credential is being made available to.
	Consumer string
	// Endpoint is the thing that the Credential provides access to.
	Endpoint string
	// ProviderKey is the curve25519 public key corresponding to the
	// ephemeral secret key that New created to encrypt the payload.
	// It must be 32 bytes long.
	ProviderKey []byte
	// ConsumerKey is the curve25519 public key that was used to generate
	// encrypt the payload.
	ConsumerKey []byte
	// Nonce is 24 random bytes.
	Nonce []byte
	// Payload is the encrypted access token.
	Payload []byte
	// Signature is the SHA256 signature for the Credential.
	// It must be 32 bytes long.
	Signature []byte
}

// zap is a utility function for zeroing pieces of information that
// should not persist in memory.
func zap(k []byte) {
	for i := range k {
		k[i] = 0
	}
}

func (c *Credential) sig() []byte {
	ce := c.Provider + c.Consumer + c.Endpoint
	length := len(c.Provider) + len(c.Consumer) + len(c.Endpoint) +
		len(c.ProviderKey) + len(c.ConsumerKey) + len(c.Nonce) +
		len(c.Payload)

	bits := make([]byte, length)
	l := 0
	copy(bits[l:], ce)
	l += len(ce)
	copy(bits[l:], c.ProviderKey)
	l += len(c.ProviderKey)
	copy(bits[l:], c.ConsumerKey)
	l += len(c.ConsumerKey)
	copy(bits[l:], c.Nonce)
	l += len(c.Nonce)
	copy(bits[l:], c.Payload)
	signature := sha256.Sum256(bits)
	return signature[:]
}

// Sign generates a SHA256 for the Credential.
// The cleartext portions are:
//    Consumer
//    Endpoint
//    ProviderKey
//    Nonce
//    Payload
// These fields are concatenated together and hashed using SHA256
func (c *Credential) Sign() {
	c.Signature = c.sig()
}

// Verify performs hash validation on the cleartext parts of the Credential.
func (c *Credential) Verify() bool {
	return subtle.ConstantTimeCompare(c.Signature, c.sig()) == 1
}

// Encrypt creates a new Credential, which will be encoded using
// an ephemeral private key, a known public key, and a random nonce.
// The known public key must be a Curve25519 public key.
func New(provider, consumer, endpoint string,
	consumerPublic *[32]byte, payload []byte) (*Credential, error) {
	nonce := [24]byte{}
	nb := nonce[:]
	cp := [32]byte{}
	copy(cp[:], consumerPublic[:])
	cnt, err := rand.Read(nb)
	if err != nil {
		return nil, err
	}
	if cnt != 24 {
		return nil, errors.New("Did not read 24 random bytes for nonce")
	}
	ephemPublic, ephemPrivate, err := box.GenerateKey(rand.Reader)
	defer zap(ephemPrivate[:])
	if err != nil {
		return nil, err
	}
	encPayload := box.Seal(nil, payload, &nonce, consumerPublic, ephemPrivate)
	res := &Credential{
		Provider:    provider,
		Consumer:    consumer,
		Endpoint:    endpoint,
		ProviderKey: ephemPublic[:],
		ConsumerKey: cp[:],
		Nonce:       nonce[:],
		Payload:     encPayload,
	}
	res.Sign()
	return res, nil
}

// Decrypt decrypts a Credential using the appropriate Curve25519 private key.
// If the Credential fails authentication or any other problem happens
// an error will be returned.
func (c *Credential) Decrypt(privateKey *[32]byte) (payload []byte, err error) {
	nonce := [24]byte{}
	providerKey := [32]byte{}
	if len(c.Nonce) != 24 {
		return nil, errors.New("Nonce must be 24 bytes long!")
	}
	if len(c.ProviderKey) != 32 {
		return nil, errors.New("ProviderKey must be 32 bytes long!")
	}
	if len(c.ConsumerKey) != 32 {
		return nil, errors.New("ConsumerKey must be 32 bytes long!")
	}
	if len(c.Signature) != 32 {
		return nil, errors.New("Signature must be 32 bytes long!")
	}
	copy(nonce[:], c.Nonce)
	copy(providerKey[:], c.ProviderKey)
	if !c.Verify() {
		return nil, errors.New("Signature Mismatch")
	}
	payload, ok := box.Open(nil, c.Payload, &nonce, &providerKey, privateKey)
	if !ok {
		return nil, errors.New("Invalid Payload")
	}
	return payload, nil
}
