// SPDX-License-Identifier: AGPL-3.0-only
package protocol

import "testing"

func TestStrict(t *testing.T) {
	type V struct {
		A map[string]int `json:"a"`
	}
	for _, s := range []string{`{"a":{"x":1,"x":2}}`, `{"z":1}`, `{"a":{}} {}`} {
		var v V
		if StrictJSON([]byte(s), &v) == nil {
			t.Fatalf("accepted %s", s)
		}
	}
	var v V
	if e := StrictJSON([]byte(`{"a":{"x":1}}`), &v); e != nil {
		t.Fatal(e)
	}
}
func TestCanonical(t *testing.T) {
	for _, s := range []string{"AB", "AA=", "AA\n"} {
		if _, e := Decode(s, -1); e == nil {
			t.Fatal(s)
		}
	}
	if _, e := Decode("AA", 1); e != nil {
		t.Fatal(e)
	}
}
func TestEnvelope(t *testing.T) {
	want := "QU5PTkNFAQABeAABAAAAAQE"
	if got := B64(E("x", []byte{1})); got != want {
		t.Fatalf("%s", got)
	}
}
