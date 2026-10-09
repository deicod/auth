package repos

import "go.mongodb.org/mongo-driver/v2/mongo/options"

// UsernameCollation defines case-insensitive equality for accepted ASCII
// usernames. Punctuation remains significant; digit strings are not numeric.
// Return a fresh value so callers cannot change the repository's comparison.
func UsernameCollation() *options.Collation {
	return &options.Collation{Locale: "en", Strength: 2, Alternate: "non-ignorable"}
}
