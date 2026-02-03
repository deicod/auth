package handlers

import (
	"strings"
	"testing"
	"unicode/utf8"
)

func TestSanitizeUserAgent_UTF8(t *testing.T) {
	// Construct a string with 511 'a's followed by a 3-byte character '世'
	// 511 bytes + 3 bytes = 514 bytes.
	// Truncating to 512 using simple slicing will keep 511 'a's and the first byte of '世'.
	// This results in an invalid UTF-8 string.

	prefix := strings.Repeat("a", 511)
	input := prefix + "世" // '世' is 3 bytes (E4 B8 96)

	sanitized := sanitizeUserAgent(input)

	if !utf8.ValidString(sanitized) {
		t.Errorf("sanitizeUserAgent returned invalid UTF-8 string for input length %d", len(input))
	}

	if len(sanitized) > 512 {
		t.Errorf("sanitizeUserAgent result longer than 512 bytes: %d", len(sanitized))
	}

	// We expect the result to be truncated to 511 bytes (removing the partial character)
	// IF the fix is implemented correctly.
	// But for now, we just assert validity.
}
