// SPDX-License-Identifier: AGPL-3.0-only
package protocol

import (
	"crypto/ed25519"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"strconv"
)

type Receipt struct {
	V              int    `json:"v"`
	DeploymentID   string `json:"deployment_id"`
	ReceiptID      string `json:"receipt_id"`
	ReviewID       string `json:"review_id"`
	DescriptorHash string `json:"descriptor_hash"`
	IssuerKeyID    string `json:"issuer_key_id"`
	ResponseHash   string `json:"response_hash"`
	AcceptedAt     string `json:"accepted_at"`
	ReceiptKeyID   string `json:"receipt_key_id"`
	Signature      string `json:"signature"`
}

// ReceiptContext contains independently obtained expectations, not receipt claims.
type ReceiptContext struct {
	DeploymentID   string `json:"deployment_id"`
	ReviewID       string `json:"review_id"`
	DescriptorHash string `json:"descriptor_hash"`
	IssuerKeyID    string `json:"issuer_key_id"`
	ResponseHash   string `json:"response_hash"`
}

func ResponseHash(deploymentID, reviewID, descriptorHash, issuerKeyID, enc, ciphertext []byte) ([]byte, error) {
	fields := [][]byte{deploymentID, reviewID, descriptorHash, issuerKeyID, enc, ciphertext}
	for i, n := range []int{32, 16, 32, 32, 32} {
		if len(fields[i]) != n {
			return nil, errors.New("invalid response field length")
		}
	}
	if len(ciphertext) < 16 || len(ciphertext) > 262144 {
		return nil, errors.New("invalid ciphertext length")
	}
	return Hash(E("accepted-response-v2", fields...)), nil
}

// ReceiptTranscript validates unsigned fields; signature is not part of the transcript.
func ReceiptTranscript(r Receipt) ([]byte, error) {
	if r.V != 2 {
		return nil, errors.New("invalid receipt version")
	}
	fields := make([][]byte, 0, 9)
	for i, s := range []string{r.DeploymentID, r.ReceiptID, r.ReviewID, r.DescriptorHash, r.IssuerKeyID, r.ResponseHash} {
		n := 32
		if i == 1 || i == 2 {
			n = 16
		}
		b, err := Decode(s, n)
		if err != nil {
			return nil, err
		}
		fields = append(fields, b)
	}
	n, err := strconv.ParseUint(r.AcceptedAt, 10, 64)
	if err != nil || strconv.FormatUint(n, 10) != r.AcceptedAt {
		return nil, errors.New("invalid receipt timestamp")
	}
	key, err := Decode(r.ReceiptKeyID, 32)
	if err != nil {
		return nil, err
	}
	fields = append(fields, U64(n), key)
	return E("receipt-v2", fields...), nil
}

func SignReceipt(r Receipt, key ed25519.PrivateKey) (Receipt, error) {
	if len(key) != ed25519.PrivateKeySize {
		return Receipt{}, errors.New("invalid receipt private key")
	}
	canonical := ed25519.NewKeyFromSeed(key[:ed25519.SeedSize])
	if subtle.ConstantTimeCompare(key, canonical) != 1 {
		return Receipt{}, errors.New("inconsistent receipt private key")
	}
	if r.ReceiptKeyID != B64(Hash(key[32:])) {
		return Receipt{}, errors.New("receipt key ID mismatch")
	}
	b, err := ReceiptTranscript(r)
	if err != nil {
		return Receipt{}, err
	}
	r.Signature = B64(ed25519.Sign(key, b))
	return r, nil
}

func ParseReceipt(b []byte) (Receipt, error) {
	var r Receipt
	if err := exactReceiptKeys(b, []string{"v", "deployment_id", "receipt_id", "review_id", "descriptor_hash", "issuer_key_id", "response_hash", "accepted_at", "receipt_key_id", "signature"}); err != nil {
		return r, err
	}
	if err := StrictJSON(b, &r); err != nil {
		return r, err
	}
	if _, err := ReceiptTranscript(r); err != nil {
		return r, err
	}
	_, err := Decode(r.Signature, ed25519.SignatureSize)
	return r, err
}

func VerifyReceipt(r Receipt, key ed25519.PublicKey, expected ReceiptContext) error {
	b, err := ReceiptTranscript(r)
	if err != nil {
		return err
	}
	if len(key) != ed25519.PublicKeySize || r.ReceiptKeyID != B64(Hash(key)) {
		return errors.New("receipt key mismatch")
	}
	for i, s := range []string{expected.DeploymentID, expected.ReviewID, expected.DescriptorHash, expected.IssuerKeyID, expected.ResponseHash} {
		n := 32
		if i == 1 {
			n = 16
		}
		if _, err := Decode(s, n); err != nil {
			return err
		}
		if s != []string{r.DeploymentID, r.ReviewID, r.DescriptorHash, r.IssuerKeyID, r.ResponseHash}[i] {
			return errors.New("receipt context mismatch")
		}
	}
	sig, err := Decode(r.Signature, ed25519.SignatureSize)
	if err != nil {
		return err
	}
	if !ed25519.Verify(key, b, sig) {
		return errors.New("invalid receipt signature")
	}
	return nil
}

type ReceiptTrustKey struct {
	ReceiptKeyID     string `json:"receipt_key_id"`
	ReceiptPublicKey string `json:"receipt_public_key"`
}
type ReceiptTrust struct {
	V            int               `json:"v"`
	DeploymentID string            `json:"deployment_id"`
	ReceiptKeyID string            `json:"receipt_key_id"`
	ReceiptKeys  []ReceiptTrustKey `json:"receipt_keys"`
}

func ParseReceiptTrust(b []byte) (ReceiptTrust, error) {
	var t ReceiptTrust
	if err := exactReceiptKeys(b, []string{"v", "deployment_id", "receipt_key_id", "receipt_keys"}); err != nil {
		return t, err
	}
	var raw struct {
		Keys []json.RawMessage `json:"receipt_keys"`
	}
	if err := json.Unmarshal(b, &raw); err != nil {
		return t, err
	}
	for _, entry := range raw.Keys {
		if err := exactReceiptKeys(entry, []string{"receipt_key_id", "receipt_public_key"}); err != nil {
			return t, err
		}
	}
	if err := StrictJSON(b, &t); err != nil {
		return t, err
	}
	return t, t.Validate()
}

func exactReceiptKeys(b []byte, keys []string) error {
	var object map[string]json.RawMessage
	if err := json.Unmarshal(b, &object); err != nil {
		return err
	}
	if len(object) != len(keys) {
		return errors.New("invalid receipt object fields")
	}
	for _, key := range keys {
		value, ok := object[key]
		if !ok || string(value) == "null" {
			return errors.New("missing receipt object field")
		}
	}
	return nil
}
func (t ReceiptTrust) Validate() error {
	if t.V != 1 {
		return errors.New("invalid receipt trust version")
	}
	if _, err := Decode(t.DeploymentID, 32); err != nil {
		return err
	}
	if _, err := Decode(t.ReceiptKeyID, 32); err != nil {
		return err
	}
	seen := map[string]bool{}
	for _, entry := range t.ReceiptKeys {
		key, err := Decode(entry.ReceiptPublicKey, 32)
		if err != nil {
			return err
		}
		if entry.ReceiptKeyID != B64(Hash(key)) || seen[entry.ReceiptKeyID] {
			return errors.New("invalid or duplicate receipt trust key")
		}
		seen[entry.ReceiptKeyID] = true
	}
	if !seen[t.ReceiptKeyID] {
		return errors.New("missing current receipt trust key")
	}
	return nil
}
func (t ReceiptTrust) PublicKey(id string) (ed25519.PublicKey, error) {
	if err := t.Validate(); err != nil {
		return nil, err
	}
	for _, entry := range t.ReceiptKeys {
		if entry.ReceiptKeyID == id {
			b, err := Decode(entry.ReceiptPublicKey, 32)
			return ed25519.PublicKey(b), err
		}
	}
	return nil, errors.New("untrusted receipt key")
}
func (t ReceiptTrust) CurrentPublicKey() (ed25519.PublicKey, error) {
	return t.PublicKey(t.ReceiptKeyID)
}
