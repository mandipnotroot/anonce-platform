// SPDX-License-Identifier: AGPL-3.0-only
package server

import "strings"

// normalizeEmail validates syntax only, not mailbox or domain ownership.
func normalizeEmail(value string) (string, error) {
	value = strings.TrimSpace(value)
	if len(value) > 254 {
		return "", bad("invalid_email")
	}
	for _, c := range value {
		if c <= 32 || c >= 127 {
			return "", bad("invalid_email")
		}
	}
	value = strings.ToLower(value)
	local, domain, ok := strings.Cut(value, "@")
	if !ok || len(local) == 0 || len(local) > 64 || strings.HasPrefix(local, ".") || strings.HasSuffix(local, ".") || strings.Contains(local, "..") || !strings.Contains(domain, ".") {
		return "", bad("invalid_email")
	}
	for _, c := range local {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || strings.ContainsRune(".!#$%&'*+-/=?^_`{|}~", c)) {
			return "", bad("invalid_email")
		}
	}
	for label := range strings.SplitSeq(domain, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", bad("invalid_email")
		}
		for _, c := range label {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
				return "", bad("invalid_email")
			}
		}
	}
	return value, nil
}
