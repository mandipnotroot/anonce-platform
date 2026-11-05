// SPDX-License-Identifier: AGPL-3.0-only
package protocol

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

type receiptVector struct {
	V                  int            `json:"v"`
	Seed               string         `json:"seed_hex"`
	Public             string         `json:"public_key_hex"`
	KeyID              string         `json:"receipt_key_id_hex"`
	ResponseTranscript string         `json:"response_transcript_hex"`
	ResponseHash       string         `json:"response_hash_hex"`
	Transcript         string         `json:"receipt_transcript_hex"`
	Signature          string         `json:"signature_hex"`
	Context            ReceiptContext `json:"context"`
	Envelope           struct {
		Enc        string `json:"enc"`
		Ciphertext string `json:"ciphertext"`
	} `json:"envelope"`
	Receipt Receipt      `json:"receipt"`
	Trust   ReceiptTrust `json:"trust"`
}

func loadReceiptVector(t *testing.T) receiptVector {
	t.Helper()
	b, err := os.ReadFile("../../testdata/receipt-v2.json")
	if err != nil {
		t.Fatal(err)
	}
	var v receiptVector
	if err = StrictJSON(b, &v); err != nil {
		t.Fatal(err)
	}
	return v
}
func TestReceiptVector(t *testing.T) {
	v := loadReceiptVector(t)
	decode := func(s string) []byte {
		b, err := Decode(s, -1)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	fields := [][]byte{decode(v.Context.DeploymentID), decode(v.Context.ReviewID), decode(v.Context.DescriptorHash), decode(v.Context.IssuerKeyID), decode(v.Envelope.Enc), decode(v.Envelope.Ciphertext)}
	if hex.EncodeToString(E("accepted-response-v2", fields...)) != v.ResponseTranscript {
		t.Fatal("response transcript")
	}
	h, err := ResponseHash(fields[0], fields[1], fields[2], fields[3], fields[4], fields[5])
	if err != nil || hex.EncodeToString(h) != v.ResponseHash || B64(h) != v.Context.ResponseHash {
		t.Fatal("response hash", err)
	}
	b, err := ReceiptTranscript(v.Receipt)
	if err != nil || hex.EncodeToString(b) != v.Transcript {
		t.Fatal("receipt transcript", err)
	}
	seed, _ := hex.DecodeString(v.Seed)
	key := ed25519.NewKeyFromSeed(seed)
	if hex.EncodeToString(key[32:]) != v.Public || hex.EncodeToString(Hash(key[32:])) != v.KeyID {
		t.Fatal("public key")
	}
	r, err := SignReceipt(v.Receipt, key)
	if err != nil || r != v.Receipt || hex.EncodeToString(decode(r.Signature)) != v.Signature {
		t.Fatal("signature", err)
	}
	if err := VerifyReceipt(r, key.Public().(ed25519.PublicKey), v.Context); err != nil {
		t.Fatal(err)
	}
	encoded, _ := json.Marshal(r)
	if _, err := ParseReceipt(encoded); err != nil {
		t.Fatal(err)
	}
	encoded, _ = json.Marshal(v.Trust)
	trust, err := ParseReceiptTrust(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = trust.CurrentPublicKey(); err != nil {
		t.Fatal(err)
	}
	for index := range fields {
		bad := append([][]byte(nil), fields...)
		bad[index] = nil
		if _, err := ResponseHash(bad[0], bad[1], bad[2], bad[3], bad[4], bad[5]); err == nil {
			t.Fatal("accepted invalid response field", index)
		}
	}
	for _, size := range []int{16, 262144} {
		if _, err := ResponseHash(fields[0], fields[1], fields[2], fields[3], fields[4], make([]byte, size)); err != nil {
			t.Fatal(err)
		}
	}
	for _, size := range []int{15, 262145} {
		if _, err := ResponseHash(fields[0], fields[1], fields[2], fields[3], fields[4], make([]byte, size)); err == nil {
			t.Fatal("ciphertext bound")
		}
	}
}

func TestReceiptRejections(t *testing.T) {
	v := loadReceiptVector(t)
	pub, _ := hex.DecodeString(v.Public)
	mutations := []func(*Receipt){
		func(r *Receipt) { r.V = 1 }, func(r *Receipt) { r.DeploymentID = B64(make([]byte, 32)) },
		func(r *Receipt) { r.ReceiptID = B64(make([]byte, 16)) }, func(r *Receipt) { r.ReviewID = B64(make([]byte, 16)) },
		func(r *Receipt) { r.DescriptorHash = B64(make([]byte, 32)) }, func(r *Receipt) { r.IssuerKeyID = B64(make([]byte, 32)) },
		func(r *Receipt) { r.ResponseHash = B64(make([]byte, 32)) }, func(r *Receipt) { r.AcceptedAt = "0" },
		func(r *Receipt) { r.ReceiptKeyID = B64(make([]byte, 32)) }, func(r *Receipt) { r.Signature = B64(make([]byte, 64)) },
	}
	for i, mutate := range mutations {
		r := v.Receipt
		mutate(&r)
		if VerifyReceipt(r, pub, v.Context) == nil {
			t.Fatal("accepted mutation", i)
		}
	}
	for _, stamp := range []string{"", "01", "+1", "-1", "1.0", "18446744073709551616"} {
		r := v.Receipt
		r.AcceptedAt = stamp
		if _, err := ReceiptTranscript(r); err == nil {
			t.Fatal(stamp)
		}
	}
	for _, id := range []string{"", v.Receipt.ReceiptID + "=", B64(make([]byte, 15)), B64(make([]byte, 17))} {
		r := v.Receipt
		r.ReceiptID = id
		if _, err := ReceiptTranscript(r); err == nil {
			t.Fatal("receipt ID", id)
		}
	}
	if VerifyReceipt(v.Receipt, pub, ReceiptContext{}) == nil {
		t.Fatal("missing expected context")
	}
	if VerifyReceipt(v.Receipt, nil, v.Context) == nil {
		t.Fatal("missing key")
	}
	if _, err := SignReceipt(v.Receipt, nil); err == nil {
		t.Fatal("missing private key")
	}
	for _, trust := range []bool{false, true} {
		var encoded []byte
		if trust {
			encoded, _ = json.Marshal(v.Trust)
		} else {
			encoded, _ = json.Marshal(v.Receipt)
		}
		var object map[string]json.RawMessage
		_ = json.Unmarshal(encoded, &object)
		for field := range object {
			copyObject := map[string]json.RawMessage{}
			for k, val := range object {
				copyObject[k] = val
			}
			delete(copyObject, field)
			bad, _ := json.Marshal(copyObject)
			if trust {
				if _, err := ParseReceiptTrust(bad); err == nil {
					t.Fatal("missing trust field", field)
				}
			} else if _, err := ParseReceipt(bad); err == nil {
				t.Fatal("missing receipt field", field)
			}
		}
		for _, bad := range []string{strings.Replace(string(encoded), `"v":`, `"V":`, 1), strings.Replace(string(encoded), `"v":`, `"extra":0,"v":`, 1), strings.Replace(string(encoded), `"v":`, `"v":2,"v":`, 1), string(encoded) + " {}"} {
			if trust {
				if _, err := ParseReceiptTrust([]byte(bad)); err == nil {
					t.Fatal("trust schema", bad)
				}
			} else if _, err := ParseReceipt([]byte(bad)); err == nil {
				t.Fatal("receipt schema", bad)
			}
		}
	}
	t1 := v.Trust
	t1.ReceiptKeys = append(append([]ReceiptTrustKey(nil), t1.ReceiptKeys...), t1.ReceiptKeys[0])
	if t1.Validate() == nil {
		t.Fatal("duplicate trust key")
	}
	t1 = v.Trust
	t1.ReceiptKeyID = B64(make([]byte, 32))
	if t1.Validate() == nil {
		t.Fatal("missing current key")
	}
	t1 = v.Trust
	t1.ReceiptKeys = []ReceiptTrustKey{{ReceiptKeyID: t1.ReceiptKeyID, ReceiptPublicKey: B64(make([]byte, 32))}}
	if t1.Validate() == nil {
		t.Fatal("key ID mismatch")
	}
	if _, err := v.Trust.PublicKey(B64(make([]byte, 32))); err == nil {
		t.Fatal("unknown trusted key")
	}
}
