// SPDX-License-Identifier: AGPL-3.0-only
package protocol

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
)

var Encoding = base64.RawURLEncoding.Strict()

func B64(b []byte) string { return Encoding.EncodeToString(b) }
func Decode(s string, n int) ([]byte, error) {
	b, e := Encoding.DecodeString(s)
	if e != nil || B64(b) != s || (n >= 0 && len(b) != n) {
		return nil, errors.New("invalid canonical base64url")
	}
	return b, nil
}
func Random(n int) []byte {
	b := make([]byte, n)
	if _, e := rand.Read(b); e != nil {
		panic(e)
	}
	return b
}
func ID() string           { return B64(Random(16)) }
func U64(n uint64) []byte  { return binary.BigEndian.AppendUint64(nil, n) }
func Hash(b []byte) []byte { h := sha256.Sum256(b); return h[:] }
func E(label string, fields ...[]byte) []byte {
	b := append([]byte("ANONCE"), 1)
	b = binary.BigEndian.AppendUint16(b, uint16(len(label)))
	b = append(b, label...)
	b = binary.BigEndian.AppendUint16(b, uint16(len(fields)))
	for _, f := range fields {
		b = binary.BigEndian.AppendUint32(b, uint32(len(f)))
		b = append(b, f...)
	}
	return b
}

// StrictJSON rejects duplicate keys at every depth as well as unknown fields and trailing values.
func StrictJSON(b []byte, v any) error {
	d := json.NewDecoder(bytes.NewReader(b))
	if err := walk(d); err != nil {
		return err
	}
	if _, err := d.Token(); err != io.EOF {
		return errors.New("trailing JSON")
	}
	d = json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if err := d.Decode(v); err != nil {
		return err
	}
	return nil
}
func walk(d *json.Decoder) error {
	t, e := d.Token()
	if e != nil {
		return e
	}
	delim, ok := t.(json.Delim)
	if !ok {
		return nil
	}
	switch delim {
	case '{':
		seen := map[string]bool{}
		for d.More() {
			k, e := d.Token()
			if e != nil {
				return e
			}
			s, ok := k.(string)
			if !ok || seen[s] {
				return errors.New("duplicate JSON key")
			}
			seen[s] = true
			if e = walk(d); e != nil {
				return e
			}
		}
	case '[':
		for d.More() {
			if e = walk(d); e != nil {
				return e
			}
		}
	default:
		return errors.New("invalid JSON")
	}
	_, e = d.Token()
	return e
}
