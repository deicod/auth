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

func TestSanitizeUserAgent_InvalidUTF8(t *testing.T) {
	// Construct a string with invalid UTF-8 bytes
	input := "User-Agent-With-Invalid-\xff-Bytes"

	sanitized := sanitizeUserAgent(input)

	if !utf8.ValidString(sanitized) {
		t.Errorf("sanitizeUserAgent returned invalid UTF-8 string: %q", sanitized)
	}

	if strings.Contains(sanitized, "\xff") {
		t.Errorf("sanitizeUserAgent failed to remove invalid bytes: %q", sanitized)
	}

	expected := "User-Agent-With-Invalid--Bytes" // invalid byte removed
	if sanitized != expected {
		t.Errorf("Expected sanitized string %q, got %q", expected, sanitized)
	}
}

func TestSanitizeUserAgent_NullBytes(t *testing.T) {
	// Construct a string with NULL bytes
	input := "User-Agent-With-\x00-Null-Bytes"

	sanitized := sanitizeUserAgent(input)

	if strings.Contains(sanitized, "\x00") {
		t.Errorf("sanitizeUserAgent failed to remove NULL bytes: %q", sanitized)
	}

	expected := "User-Agent-With--Null-Bytes" // NULL byte removed
	if sanitized != expected {
		t.Errorf("Expected sanitized string %q, got %q", expected, sanitized)
	}
}
