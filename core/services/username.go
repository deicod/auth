package services

import (
	"fmt"
	"strings"

	"github.com/deicod/auth/core"
)

// normalizeUsername is shared by registration and username updates. Casing is
// preserved for display; stores enforce case-insensitive availability.
func normalizeUsername(username string) (string, error) {
	username = strings.TrimSpace(username)
	if !isValidUsername(username) {
		return "", fmt.Errorf("%w: invalid username (must be 3-30 chars, alphanumeric, underscore, or hyphen)", core.ErrInvalidInput)
	}
	return username, nil
}

// isValidUsername accepts 3-30 ASCII letters, digits, underscores or hyphens.
func isValidUsername(username string) bool {
	if len(username) < 3 || len(username) > 30 {
		return false
	}
	for i := 0; i < len(username); i++ {
		c := username[i]
		if (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') && (c < '0' || c > '9') && c != '_' && c != '-' {
			return false
		}
	}
	return true
}
