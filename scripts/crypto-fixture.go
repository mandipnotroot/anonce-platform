// SPDX-License-Identifier: AGPL-3.0-only
// Test-only JSONL peer. Generates ephemeral dummy keys; never use with live data.
package main

import (
	"bufio"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/cloudflare/circl/blindsign/blindrsa"
	"github.com/cloudflare/circl/hpke"
	"github.com/mandipnotroot/anonce-platform/internal/protocol"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

type request struct {
	Op         string   `json:"op"`
	Label      string   `json:"label"`
	Fields     []string `json:"fields"`
	Message    string   `json:"message"`
	Signature  string   `json:"signature"`
	Key        string   `json:"key"`
	Salt       string   `json:"salt"`
	Info       string   `json:"info"`
	AAD        string   `json:"aad"`
	Nonce      string   `json:"nonce"`
	Plaintext  string   `json:"plaintext"`
	Ciphertext string   `json:"ciphertext"`
	Enc        string   `json:"enc"`
}

func must[T any](v T, err error) T {
	if err != nil {
		panic(err)
	}
	return v
}
func dec(s string) []byte { return must(protocol.Decode(s, -1)) }

func main() {
	// No production key import/export interface: the RSA key only lives here.
	key := must(rsa.GenerateKey(rand.Reader, 3072))
	signer := blindrsa.NewSigner(key)
	verifier := must(blindrsa.NewVerifier(blindrsa.SHA384PSSRandomized, &key.PublicKey))
	kem := hpke.KEM_X25519_HKDF_SHA256.Scheme()
	pub, priv, err := kem.GenerateKeyPair()
	if err != nil {
		panic(err)
	}
	suite := hpke.NewSuite(hpke.KEM_X25519_HKDF_SHA256, hpke.KDF_HKDF_SHA256, hpke.AEAD_ChaCha20Poly1305)
	scanner := bufio.NewScanner(os.Stdin)
	scanner.Buffer(make([]byte, 4096), 2*1024*1024)
	encoder := json.NewEncoder(os.Stdout)
	for scanner.Scan() {
		result := func() (out map[string]any) {
			defer func() {
				if recover() != nil {
					out = map[string]any{"error": "fixture operation failed"}
				}
			}()
			var r request
			if err := protocol.StrictJSON(scanner.Bytes(), &r); err != nil {
				panic(err)
			}
			switch r.Op {
			case "init":
				return map[string]any{"rsa_spki": protocol.B64(must(x509.MarshalPKIXPublicKey(&key.PublicKey))), "hpke_public_key": protocol.B64(must(pub.MarshalBinary())), "hpke_private_key": protocol.B64(must(priv.MarshalBinary()))}
			case "sign":
				return map[string]any{"blind_signature": protocol.B64(must(signer.BlindSign(dec(r.Message))))}
			case "verify":
				return map[string]any{"valid": verifier.Verify(dec(r.Message), dec(r.Signature)) == nil}
			case "context":
				fields := make([][]byte, len(r.Fields))
				for i, f := range r.Fields {
					fields[i] = dec(f)
				}
				return map[string]any{"bytes": protocol.B64(protocol.E(r.Label, fields...))}
			case "review-content-context":
				if len(r.Fields) != 3 {
					panic("invalid review content context")
				}
				deployment := must(protocol.Decode(r.Fields[0], 32))
				org := must(protocol.Decode(r.Fields[1], 16))
				review := must(protocol.Decode(r.Fields[2], 16))
				return map[string]any{"bytes": protocol.B64(protocol.E("review-content", deployment, org, review, protocol.U64(1)))}
			case "hkdf":
				out := make([]byte, 32)
				_, err := io.ReadFull(hkdf.New(sha256.New, dec(r.Key), dec(r.Salt), dec(r.Info)), out)
				if err != nil {
					panic(err)
				}
				return map[string]any{"bytes": protocol.B64(out)}
			case "chacha-seal":
				cipher := must(chacha20poly1305.New(dec(r.Key)))
				return map[string]any{"ciphertext": protocol.B64(cipher.Seal(nil, dec(r.Nonce), dec(r.Plaintext), dec(r.AAD)))}
			case "chacha-open":
				cipher := must(chacha20poly1305.New(dec(r.Key)))
				return map[string]any{"plaintext": protocol.B64(must(cipher.Open(nil, dec(r.Nonce), dec(r.Ciphertext), dec(r.AAD))))}
			case "hpke-seal":
				sender := must(suite.NewSender(pub, dec(r.Info)))
				enc, sealer, err := sender.Setup(rand.Reader)
				if err != nil {
					panic(err)
				}
				return map[string]any{"enc": protocol.B64(enc), "ciphertext": protocol.B64(must(sealer.Seal(dec(r.Plaintext), dec(r.AAD))))}
			case "hpke-open":
				receiver := must(suite.NewReceiver(priv, dec(r.Info)))
				opener := must(receiver.Setup(dec(r.Enc)))
				return map[string]any{"plaintext": protocol.B64(must(opener.Open(dec(r.Ciphertext), dec(r.AAD))))}
			default:
				panic("unknown operation")
			}
		}()
		if err := encoder.Encode(result); err != nil {
			panic(err)
		}
	}
	if err := scanner.Err(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
