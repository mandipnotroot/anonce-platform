// SPDX-License-Identifier: AGPL-3.0-only
package protocol

import "testing"

func TestLimitsFromEnv(t *testing.T) {
	l, err := LimitsFromEnv(func(string) (string, bool) { return "", false })
	if err != nil || l != Defaults() {
		t.Fatalf("defaults: %v %v", l, err)
	}
	for _, name := range []string{"ANONCE_MAX_QUESTIONS", "ANONCE_MAX_REVIEW_BYTES", "ANONCE_MAX_DESCRIPTION_BYTES", "ANONCE_MAX_RESPONSE_BYTES"} {
		for _, raw := range []string{"", "abc", "0", "-1", "999999999999999999999999", "1048577"} {
			_, err := LimitsFromEnv(func(key string) (string, bool) { return raw, key == name })
			if err == nil {
				t.Errorf("%s=%q accepted", name, raw)
			}
		}
	}
	settings := map[string]string{"ANONCE_MAX_QUESTIONS": "1", "ANONCE_MAX_REVIEW_BYTES": "1024", "ANONCE_MAX_DESCRIPTION_BYTES": "1", "ANONCE_MAX_RESPONSE_BYTES": "1024"}
	l, err = LimitsFromEnv(func(k string) (string, bool) { v, ok := settings[k]; return v, ok })
	if err != nil || l != (Limits{1, 1024, 1, 1024}) {
		t.Fatalf("minimum: %v %v", l, err)
	}
	settings["ANONCE_MAX_DESCRIPTION_BYTES"] = "1025"
	if _, err := LimitsFromEnv(func(k string) (string, bool) { v, ok := settings[k]; return v, ok }); err == nil {
		t.Fatal("description exceeds review")
	}
}
