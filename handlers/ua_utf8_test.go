package handlers

import (
	"strings"
	"testing"
	"unicode/utf8"
)

func TestSanitizeUserAgent_UTF8(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		wantLen  int
		wantUTF8 bool
	}{
		{
			name:     "short string",
			input:    "Mozilla/5.0",
			wantLen:  11,
			wantUTF8: true,
		},
		{
			name:     "truncated multi-byte char",
			input:    strings.Repeat("a", 511) + "ñ", // 513 bytes total. ñ is 2 bytes. Truncates to 511 bytes.
			wantLen:  511, // Should drop the partial byte
			wantUTF8: true,
		},
		{
			name:     "truncated emoji",
			input:    strings.Repeat("a", 510) + "🧪", // 514 bytes. 🧪 is 4 bytes (\xf0\x9f\xa7\xaa).
			// 510 'a's + first 2 bytes of emoji = 512 bytes.
			// \xf0\x9f are invalid on their own. Should be removed.
			wantLen:  510,
			wantUTF8: true,
		},
		{
			name:     "exact boundary",
			input:    strings.Repeat("a", 510) + "ñ", // 512 bytes exactly.
			wantLen:  512,
			wantUTF8: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := sanitizeUserAgent(tt.input)
			if len(got) != tt.wantLen {
				t.Errorf("got len %d, want %d", len(got), tt.wantLen)
			}
			if utf8.ValidString(got) != tt.wantUTF8 {
				t.Errorf("utf8.ValidString() = %v, want %v", utf8.ValidString(got), tt.wantUTF8)
			}
			if len(got) > 512 {
				t.Errorf("result longer than 512 bytes: %d", len(got))
			}
		})
	}
}
