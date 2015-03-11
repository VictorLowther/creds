package creds

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"golang.org/x/crypto/nacl/box"
	"testing"
)

var consumerPrivate, consumerPublic *[32]byte

func init() {
	var err error
	consumerPublic, consumerPrivate, err = box.GenerateKey(rand.Reader)
	if err != nil {
		panic("Cannot create consumer keys!")
	}
}

func BenchmarkCreds(b *testing.B) {
	consumer := "Squeamish"
	endpoint := "None"
	payload := []byte("The secret phrase is Squeamish Ossifrage")
	for i := 0; i < b.N; i++ {
		cred, _ := New("", consumer, endpoint, consumerPublic, payload)
		dec, _ := cred.Decrypt(consumerPrivate)
		bytes.Equal(payload, dec)
	}
}

func TestCreds(t *testing.T) {
	consumer := "Squeamish"
	endpoint := "None"
	payload := []byte("The secret phrase is Squeamish Ossifrage")
	cred, err := New("", consumer, endpoint, consumerPublic, payload)
	if err != nil {
		t.Fatalf("Error creating Credential: %v", err)
	}
	res, err := json.Marshal(cred)
	if err != nil {
		t.Fatalf("Failed to marshal Credential: %v", err)
	}
	gotCred := &Credential{}
	err = json.Unmarshal(res, gotCred)
	if err != nil {
		t.Fatalf("Failed to unmarshal Credential: %v", err)
	}
	dec, err := gotCred.Decrypt(consumerPrivate)
	if err != nil {
		t.Fatalf("Error decrypting Credential: %v", err)
	}
	if !bytes.Equal(dec, payload) {
		t.Fatalf("Expected '%s', got '%s'", payload, dec)
	}
}
